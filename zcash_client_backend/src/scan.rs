use crossbeam_channel as channel;
use std::collections::HashMap;
use std::fmt;
use std::mem;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use memuse::DynamicUsage;
use zcash_note_encryption::{batch, BatchDomain, Domain, ShieldedOutput};
use zcash_primitives::{block::BlockHash, transaction::TxId};

/// A decrypted transaction output.
pub(crate) struct DecryptedOutput<IvkTag, D: Domain, M> {
    /// The tag corresponding to the incoming viewing key used to decrypt the note.
    pub(crate) ivk_tag: IvkTag,
    /// The recipient of the note.
    pub(crate) recipient: D::Recipient,
    /// The note!
    pub(crate) note: D::Note,
    /// The memo field, or `()` if this is a decrypted compact output.
    pub(crate) memo: M,
}

impl<IvkTag, D: Domain, M> fmt::Debug for DecryptedOutput<IvkTag, D, M>
where
    IvkTag: fmt::Debug,
    D::IncomingViewingKey: fmt::Debug,
    D::Recipient: fmt::Debug,
    D::Note: fmt::Debug,
    M: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedOutput")
            .field("ivk_tag", &self.ivk_tag)
            .field("recipient", &self.recipient)
            .field("note", &self.note)
            .field("memo", &self.memo)
            .finish()
    }
}

/// A decryptor of transaction outputs.
pub(crate) trait Decryptor<D: BatchDomain, Output> {
    type Memo;

    // Once we reach MSRV 1.75.0, this can return `impl Iterator`.
    fn batch_decrypt<IvkTag: Clone>(
        tags: &[IvkTag],
        ivks: &[D::IncomingViewingKey],
        outputs: &[(D, Output)],
    ) -> Vec<Option<DecryptedOutput<IvkTag, D, Self::Memo>>>;
}

/// A decryptor of outputs as encoded in transactions.
pub(crate) struct FullDecryptor;

impl<D: BatchDomain, Output: ShieldedOutput<D>> Decryptor<D, Output> for FullDecryptor {
    type Memo = D::Memo;

    fn batch_decrypt<IvkTag: Clone>(
        tags: &[IvkTag],
        ivks: &[D::IncomingViewingKey],
        outputs: &[(D, Output)],
    ) -> Vec<Option<DecryptedOutput<IvkTag, D, Self::Memo>>> {
        batch::try_note_decryption(ivks, outputs)
            .into_iter()
            .map(|res| {
                res.map(|((note, recipient, memo), ivk_idx)| DecryptedOutput {
                    ivk_tag: tags[ivk_idx].clone(),
                    recipient,
                    note,
                    memo,
                })
            })
            .collect()
    }
}

/// A decryptor of outputs as encoded in compact blocks.
pub(crate) struct CompactDecryptor;

impl<D: BatchDomain, Output: ShieldedOutput<D>> Decryptor<D, Output> for CompactDecryptor {
    type Memo = ();

    fn batch_decrypt<IvkTag: Clone>(
        tags: &[IvkTag],
        ivks: &[D::IncomingViewingKey],
        outputs: &[(D, Output)],
    ) -> Vec<Option<DecryptedOutput<IvkTag, D, Self::Memo>>> {
        batch::try_compact_note_decryption(ivks, outputs)
            .into_iter()
            .map(|res| {
                res.map(|((note, recipient), ivk_idx)| DecryptedOutput {
                    ivk_tag: tags[ivk_idx].clone(),
                    recipient,
                    note,
                    memo: (),
                })
            })
            .collect()
    }
}

/// A value correlated with an output index.
struct OutputIndex<V> {
    /// The index of the output within the corresponding shielded bundle.
    output_index: usize,
    /// The value for the output index.
    value: V,
}

type OutputItem<IvkTag, D, M> = OutputIndex<DecryptedOutput<IvkTag, D, M>>;

/// The sender for the result of batch scanning a specific transaction output.
struct OutputReplier<IvkTag, D: Domain, M>(OutputIndex<channel::Sender<OutputItem<IvkTag, D, M>>>);

impl<IvkTag, D: Domain, M> DynamicUsage for OutputReplier<IvkTag, D, M> {
    #[inline(always)]
    fn dynamic_usage(&self) -> usize {
        // We count the memory usage of items in the channel on the receiver side.
        0
    }

    #[inline(always)]
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

/// The receiver for the result of batch scanning a specific transaction.
struct BatchReceiver<IvkTag, D: Domain, M>(channel::Receiver<OutputItem<IvkTag, D, M>>);

impl<IvkTag, D: Domain, M> DynamicUsage for BatchReceiver<IvkTag, D, M> {
    fn dynamic_usage(&self) -> usize {
        // We count the memory usage of items in the channel on the receiver side.
        let num_items = self.0.len();

        // We know we use unbounded channels, so the items in the channel are stored as a
        // linked list. `crossbeam_channel` allocates memory for the linked list in blocks
        // of 31 items.
        const ITEMS_PER_BLOCK: usize = 31;
        let num_blocks = (num_items + ITEMS_PER_BLOCK - 1) / ITEMS_PER_BLOCK;

        // The structure of a block is:
        // - A pointer to the next block.
        // - For each slot in the block:
        //   - Space for an item.
        //   - The state of the slot, stored as an AtomicUsize.
        const PTR_SIZE: usize = std::mem::size_of::<usize>();
        let item_size = std::mem::size_of::<OutputItem<IvkTag, D, M>>();
        const ATOMIC_USIZE_SIZE: usize = std::mem::size_of::<AtomicUsize>();
        let block_size = PTR_SIZE + ITEMS_PER_BLOCK * (item_size + ATOMIC_USIZE_SIZE);

        num_blocks * block_size
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let usage = self.dynamic_usage();
        (usage, Some(usage))
    }
}

/// A tracker for the batch scanning tasks that are currently running.
///
/// This enables a [`BatchRunner`] to be optionally configured to track heap memory usage.
pub(crate) trait Tasks<Item> {
    type Task: Task;
    fn new() -> Self;
    fn add_task(&self, item: Item) -> Self::Task;
    fn run_task(&self, item: Item) {
        let task = self.add_task(item);
        rayon::spawn_fifo(|| task.run());
    }
}

/// A batch scanning task.
pub(crate) trait Task: Send + 'static {
    fn run(self);
}

impl<Item: Task> Tasks<Item> for () {
    type Task = Item;
    fn new() -> Self {}
    fn add_task(&self, item: Item) -> Self::Task {
        // Return the item itself as the task; we aren't tracking anything about it, so
        // there is no need to wrap it in a newtype.
        item
    }
}

/// A task tracker that measures heap usage.
///
/// This struct implements `DynamicUsage` without any item bounds, but that works because
/// it only implements `Tasks` for items that implement `DynamicUsage`.
pub(crate) struct WithUsage {
    // The current heap usage for all running tasks.
    running_usage: Arc<AtomicUsize>,
}

impl DynamicUsage for WithUsage {
    fn dynamic_usage(&self) -> usize {
        self.running_usage.load(Ordering::Relaxed)
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        // Tasks are relatively short-lived, so we accept the inaccuracy of treating the
        // tasks's approximate usage as its bounds.
        let usage = self.dynamic_usage();
        (usage, Some(usage))
    }
}

impl<Item: Task + DynamicUsage> Tasks<Item> for WithUsage {
    type Task = WithUsageTask<Item>;

    fn new() -> Self {
        Self {
            running_usage: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn add_task(&self, item: Item) -> Self::Task {
        // Create the task that will move onto the heap with the batch item.
        let mut task = WithUsageTask {
            item,
            own_usage: 0,
            running_usage: self.running_usage.clone(),
        };

        // `rayon::spawn_fifo` creates a `HeapJob` holding a closure. The size of a
        // closure is (to good approximation) the size of the captured environment, which
        // in this case is two moved variables:
        // - An `Arc<Registry>`, which is a pointer to data that is amortized over the
        //   entire `rayon` thread pool, so we only count the pointer size here.
        // - The spawned closure, which in our case moves `task` into it.
        task.own_usage =
            mem::size_of::<Arc<()>>() + mem::size_of_val(&task) + task.item.dynamic_usage();

        // Approximate now as when the heap cost of this running batch begins. In practice
        // this is fine, because `Self::add_task` is called from `Self::run_task` which
        // immediately moves the task to the heap.
        self.running_usage
            .fetch_add(task.own_usage, Ordering::SeqCst);

        task
    }
}

/// A task that will clean up its own heap usage from the overall running usage once it is
/// complete.
pub(crate) struct WithUsageTask<Item> {
    /// The item being run.
    item: Item,
    /// Size of this task on the heap. We assume that the size of the task does not change
    /// once it has been created, to avoid needing to maintain bidirectional channels
    /// between [`WithUsage`] and its tasks.
    own_usage: usize,
    /// Pointer to the parent [`WithUsage`]'s heap usage tracker for running tasks.
    running_usage: Arc<AtomicUsize>,
}

impl<Item: Task> Task for WithUsageTask<Item> {
    fn run(self) {
        // Run the item.
        self.item.run();

        // Signal that the heap memory for this task has been freed.
        self.running_usage
            .fetch_sub(self.own_usage, Ordering::SeqCst);
    }
}

/// A batch of outputs to trial decrypt.
pub(crate) struct Batch<IvkTag, D: BatchDomain, Output, Dec: Decryptor<D, Output>> {
    tags: Vec<IvkTag>,
    ivks: Vec<D::IncomingViewingKey>,
    /// We currently store outputs and repliers as parallel vectors, because
    /// [`batch::try_note_decryption`] accepts a slice of domain/output pairs
    /// rather than a value that implements `IntoIterator`, and therefore we
    /// can't just use `map` to select the parts we need in order to perform
    /// batch decryption. Ideally the domain, output, and output replier would
    /// all be part of the same struct, which would also track the output index
    /// (that is captured in the outer `OutputIndex` of each `OutputReplier`).
    outputs: Vec<(D, Output)>,
    repliers: Vec<OutputReplier<IvkTag, D, Dec::Memo>>,
}

impl<IvkTag, D, Output, Dec> DynamicUsage for Batch<IvkTag, D, Output, Dec>
where
    IvkTag: DynamicUsage,
    D: BatchDomain + DynamicUsage,
    D::IncomingViewingKey: DynamicUsage,
    Output: DynamicUsage,
    Dec: Decryptor<D, Output>,
{
    fn dynamic_usage(&self) -> usize {
        self.tags.dynamic_usage()
            + self.ivks.dynamic_usage()
            + self.outputs.dynamic_usage()
            + self.repliers.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let (tags_lower, tags_upper) = self.tags.dynamic_usage_bounds();
        let (ivks_lower, ivks_upper) = self.ivks.dynamic_usage_bounds();
        let (outputs_lower, outputs_upper) = self.outputs.dynamic_usage_bounds();
        let (repliers_lower, repliers_upper) = self.repliers.dynamic_usage_bounds();

        (
            tags_lower + ivks_lower + outputs_lower + repliers_lower,
            tags_upper
                .zip(ivks_upper)
                .zip(outputs_upper)
                .zip(repliers_upper)
                .map(|(((a, b), c), d)| a + b + c + d),
        )
    }
}

impl<IvkTag, D, Output, Dec> Batch<IvkTag, D, Output, Dec>
where
    IvkTag: Clone,
    D: BatchDomain,
    Dec: Decryptor<D, Output>,
{
    /// Constructs a new batch.
    fn new(tags: Vec<IvkTag>, ivks: Vec<D::IncomingViewingKey>) -> Self {
        assert_eq!(tags.len(), ivks.len());
        Self {
            tags,
            ivks,
            outputs: vec![],
            repliers: vec![],
        }
    }

    /// Returns `true` if the batch is currently empty.
    fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }
}

impl<IvkTag, D, Output, Dec> Task for Batch<IvkTag, D, Output, Dec>
where
    IvkTag: Clone + Send + 'static,
    D: BatchDomain + Send + 'static,
    D::IncomingViewingKey: Send,
    D::Memo: Send,
    D::Note: Send,
    D::Recipient: Send,
    Output: Send + 'static,
    Dec: Decryptor<D, Output> + 'static,
    Dec::Memo: Send,
{
    /// Runs the batch of trial decryptions, and reports the results.
    fn run(self) {
        // Deconstruct self so we can consume the pieces individually.
        let Self {
            tags,
            ivks,
            outputs,
            repliers,
        } = self;

        assert_eq!(outputs.len(), repliers.len());

        let decryption_results = Dec::batch_decrypt(&tags, &ivks, &outputs);
        for (decryption_result, OutputReplier(replier)) in
            decryption_results.into_iter().zip(repliers.into_iter())
        {
            // If `decryption_result` is `None` then we will just drop `replier`,
            // indicating to the parent `BatchRunner` that this output was not for us.
            if let Some(value) = decryption_result {
                let result = OutputIndex {
                    output_index: replier.output_index,
                    value,
                };

                if replier.value.send(result).is_err() {
                    tracing::debug!("BatchRunner was dropped before batch finished");
                    break;
                }
            }
        }
    }
}

impl<IvkTag, D, Output, Dec> Batch<IvkTag, D, Output, Dec>
where
    D: BatchDomain,
    Output: Clone,
    Dec: Decryptor<D, Output>,
{
    /// Adds the given outputs to this batch.
    ///
    /// `replier` will be called with the result of every output.
    fn add_outputs(
        &mut self,
        domain: impl Fn(&Output) -> D,
        outputs: &[Output],
        replier: channel::Sender<OutputItem<IvkTag, D, Dec::Memo>>,
    ) {
        self.outputs.extend(
            outputs
                .iter()
                .cloned()
                .map(|output| (domain(&output), output)),
        );
        self.repliers.extend((0..outputs.len()).map(|output_index| {
            OutputReplier(OutputIndex {
                output_index,
                value: replier.clone(),
            })
        }));
    }
}

/// A `HashMap` key for looking up the result of a batch scanning a specific transaction.
#[derive(PartialEq, Eq, Hash)]
struct ResultKey(BlockHash, TxId);

impl DynamicUsage for ResultKey {
    #[inline(always)]
    fn dynamic_usage(&self) -> usize {
        0
    }

    #[inline(always)]
    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

/// Logic to run batches of trial decryptions on the global threadpool.
pub(crate) struct BatchRunner<IvkTag, D, Output, Dec, T>
where
    D: BatchDomain,
    Dec: Decryptor<D, Output>,
    T: Tasks<Batch<IvkTag, D, Output, Dec>>,
{
    batch_size_threshold: usize,
    // The batch currently being accumulated.
    acc: Batch<IvkTag, D, Output, Dec>,
    // The running batches.
    running_tasks: T,
    // Receivers for the results of the running batches.
    pending_results: HashMap<ResultKey, BatchReceiver<IvkTag, D, Dec::Memo>>,
}

impl<IvkTag, D, Output, Dec, T> DynamicUsage for BatchRunner<IvkTag, D, Output, Dec, T>
where
    IvkTag: DynamicUsage,
    D: BatchDomain + DynamicUsage,
    D::IncomingViewingKey: DynamicUsage,
    Output: DynamicUsage,
    Dec: Decryptor<D, Output>,
    T: Tasks<Batch<IvkTag, D, Output, Dec>> + DynamicUsage,
{
    fn dynamic_usage(&self) -> usize {
        self.acc.dynamic_usage()
            + self.running_tasks.dynamic_usage()
            + self.pending_results.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let running_usage = self.running_tasks.dynamic_usage();

        let bounds = (
            self.acc.dynamic_usage_bounds(),
            self.pending_results.dynamic_usage_bounds(),
        );
        (
            bounds.0 .0 + running_usage + bounds.1 .0,
            bounds
                .0
                 .1
                .zip(bounds.1 .1)
                .map(|(a, b)| a + running_usage + b),
        )
    }
}

impl<IvkTag, D, Output, Dec, T> BatchRunner<IvkTag, D, Output, Dec, T>
where
    IvkTag: Clone,
    D: BatchDomain,
    Dec: Decryptor<D, Output>,
    T: Tasks<Batch<IvkTag, D, Output, Dec>>,
{
    /// Constructs a new batch runner for the given incoming viewing keys.
    pub(crate) fn new(
        batch_size_threshold: usize,
        ivks: impl Iterator<Item = (IvkTag, D::IncomingViewingKey)>,
    ) -> Self {
        let (tags, ivks) = ivks.unzip();
        Self {
            batch_size_threshold,
            acc: Batch::new(tags, ivks),
            running_tasks: T::new(),
            pending_results: HashMap::default(),
        }
    }
}

impl<IvkTag, D, Output, Dec, T> BatchRunner<IvkTag, D, Output, Dec, T>
where
    IvkTag: Clone + Send + 'static,
    D: BatchDomain + Send + 'static,
    D::IncomingViewingKey: Clone + Send,
    D::Memo: Send,
    D::Note: Send,
    D::Recipient: Send,
    Output: Clone + Send + 'static,
    Dec: Decryptor<D, Output>,
    T: Tasks<Batch<IvkTag, D, Output, Dec>>,
{
    /// Batches the given outputs for trial decryption.
    ///
    /// `block_tag` is the hash of the block that triggered this txid being added to the
    /// batch, or the all-zeros hash to indicate that no block triggered it (i.e. it was a
    /// mempool change).
    ///
    /// If after adding the given outputs, the accumulated batch size is at least the size
    /// threshold that was set via `Self::new`, `Self::flush` is called. Subsequent calls
    /// to `Self::add_outputs` will be accumulated into a new batch.
    pub(crate) fn add_outputs(
        &mut self,
        block_tag: BlockHash,
        txid: TxId,
        domain: impl Fn(&Output) -> D,
        outputs: &[Output],
    ) {
        let (tx, rx) = channel::unbounded();
        self.acc.add_outputs(domain, outputs, tx);
        self.pending_results
            .insert(ResultKey(block_tag, txid), BatchReceiver(rx));

        if self.acc.outputs.len() >= self.batch_size_threshold {
            self.flush();
        }
    }

    /// Runs the currently accumulated batch on the global threadpool.
    ///
    /// Subsequent calls to `Self::add_outputs` will be accumulated into a new batch.
    pub(crate) fn flush(&mut self) {
        if !self.acc.is_empty() {
            let mut batch = Batch::new(self.acc.tags.clone(), self.acc.ivks.clone());
            mem::swap(&mut batch, &mut self.acc);
            self.running_tasks.run_task(batch);
        }
    }

    /// Collects the pending decryption results for the given transaction.
    ///
    /// `block_tag` is the hash of the block that triggered this txid being added to the
    /// batch, or the all-zeros hash to indicate that no block triggered it (i.e. it was a
    /// mempool change).
    pub(crate) fn collect_results(
        &mut self,
        block_tag: BlockHash,
        txid: TxId,
    ) -> HashMap<(TxId, usize), DecryptedOutput<IvkTag, D, Dec::Memo>> {
        self.pending_results
            .remove(&ResultKey(block_tag, txid))
            // We won't have a pending result if the transaction didn't have outputs of
            // this runner's kind.
            .map(|BatchReceiver(rx)| {
                // This iterator will end once the channel becomes empty and disconnected.
                // We created one sender per output, and each sender is dropped after the
                // batch it is in completes (and in the case of successful decryptions,
                // after the decrypted note has been sent to the channel). Completion of
                // the iterator therefore corresponds to complete knowledge of the outputs
                // of this transaction that could be decrypted.
                rx.into_iter()
                    .map(
                        |OutputIndex {
                             output_index,
                             value,
                         }| { ((txid, output_index), value) },
                    )
                    .collect()
            })
            .unwrap_or_default()
    }
}
