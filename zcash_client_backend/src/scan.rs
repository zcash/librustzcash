use crossbeam_channel as channel;
use std::collections::HashMap;
use std::fmt;
use std::mem;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use memuse::DynamicUsage;
use zcash_note_encryption::{batch, BatchDomain, Domain, ShieldedOutput, COMPACT_NOTE_SIZE};
use zcash_primitives::{block::BlockHash, transaction::TxId};

/// A decrypted note.
pub(crate) struct DecryptedNote<A, D: Domain> {
    /// The tag corresponding to the incoming viewing key used to decrypt the note.
    pub(crate) ivk_tag: A,
    /// The recipient of the note.
    pub(crate) recipient: D::Recipient,
    /// The note!
    pub(crate) note: D::Note,
}

impl<A, D: Domain> fmt::Debug for DecryptedNote<A, D>
where
    A: fmt::Debug,
    D::IncomingViewingKey: fmt::Debug,
    D::Recipient: fmt::Debug,
    D::Note: fmt::Debug,
    D::Memo: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedNote")
            .field("ivk_tag", &self.ivk_tag)
            .field("recipient", &self.recipient)
            .field("note", &self.note)
            .finish()
    }
}

/// A value correlated with an output index.
struct OutputIndex<V> {
    /// The index of the output within the corresponding shielded bundle.
    output_index: usize,
    /// The value for the output index.
    value: V,
}

type OutputItem<A, D> = OutputIndex<Option<DecryptedNote<A, D>>>;

/// The sender for the result of batch scanning a specific transaction output.
struct OutputReplier<A, D: Domain>(OutputIndex<channel::Sender<OutputItem<A, D>>>);

impl<A, D: Domain> DynamicUsage for OutputReplier<A, D> {
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
struct BatchReceiver<A, D: Domain>(channel::Receiver<OutputItem<A, D>>);

impl<A, D: Domain> DynamicUsage for BatchReceiver<A, D> {
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
        let item_size = std::mem::size_of::<OutputItem<A, D>>();
        const ATOMIC_USIZE_SIZE: usize = std::mem::size_of::<AtomicUsize>();
        let block_size = PTR_SIZE + ITEMS_PER_BLOCK * (item_size + ATOMIC_USIZE_SIZE);

        num_blocks * block_size
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let usage = self.dynamic_usage();
        (usage, Some(usage))
    }
}

/// A batch of outputs to trial decrypt.
struct Batch<A, D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>> {
    tags: Vec<A>,
    ivks: Vec<D::IncomingViewingKey>,
    /// We currently store outputs and repliers as parallel vectors, because
    /// [`batch::try_note_decryption`] accepts a slice of domain/output pairs
    /// rather than a value that implements `IntoIterator`, and therefore we
    /// can't just use `map` to select the parts we need in order to perform
    /// batch decryption. Ideally the domain, output, and output replier would
    /// all be part of the same struct, which would also track the output index
    /// (that is captured in the outer `OutputIndex` of each `OutputReplier`).
    outputs: Vec<(D, Output)>,
    repliers: Vec<OutputReplier<A, D>>,
    // Pointer to the parent `BatchRunner`'s heap usage tracker for running batches.
    running_usage: Arc<AtomicUsize>,
}

fn base_vec_usage<T>(c: &Vec<T>) -> usize {
    c.capacity() * mem::size_of::<T>()
}

impl<A, D, Output> DynamicUsage for Batch<A, D, Output>
where
    D: BatchDomain,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
{
    fn dynamic_usage(&self) -> usize {
        // We don't have a `DynamicUsage` bound on `D::IncomingViewingKey`, `D`, or
        // `Output`, and we can't use newtypes because the batch decryption API takes
        // slices. But we know that we don't allocate memory inside either of these, so we
        // just compute the size directly.
        base_vec_usage(&self.ivks) + base_vec_usage(&self.outputs) + self.repliers.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let base_usage = base_vec_usage(&self.ivks) + base_vec_usage(&self.outputs);
        let bounds = self.repliers.dynamic_usage_bounds();
        (
            base_usage + bounds.0,
            bounds.1.map(|upper| base_usage + upper),
        )
    }
}

impl<A, D, Output> Batch<A, D, Output>
where
    A: Clone,
    D: BatchDomain,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
{
    /// Constructs a new batch.
    fn new(
        tags: Vec<A>,
        ivks: Vec<D::IncomingViewingKey>,
        running_usage: Arc<AtomicUsize>,
    ) -> Self {
        assert_eq!(tags.len(), ivks.len());
        Self {
            tags,
            ivks,
            outputs: vec![],
            repliers: vec![],
            running_usage,
        }
    }

    /// Returns `true` if the batch is currently empty.
    fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Runs the batch of trial decryptions, and reports the results.
    fn run(self) {
        // Approximate now as when the heap cost of this running batch begins. We use the
        // size of `self` as a lower bound on the actual heap memory allocated by the
        // rayon threadpool to store this `Batch`.
        let own_usage = std::mem::size_of_val(&self) + self.dynamic_usage();
        self.running_usage.fetch_add(own_usage, Ordering::SeqCst);

        assert_eq!(self.outputs.len(), self.repliers.len());

        let decryption_results = batch::try_compact_note_decryption(&self.ivks, &self.outputs);
        for (decryption_result, OutputReplier(replier)) in
            decryption_results.into_iter().zip(self.repliers.iter())
        {
            let result = OutputIndex {
                output_index: replier.output_index,
                value: decryption_result.map(|((note, recipient), ivk_idx)| DecryptedNote {
                    ivk_tag: self.tags[ivk_idx].clone(),
                    recipient,
                    note,
                }),
            };

            if replier.value.send(result).is_err() {
                tracing::debug!("BatchRunner was dropped before batch finished");
                break;
            }
        }

        // Signal that the heap memory for this batch is about to be freed.
        self.running_usage.fetch_sub(own_usage, Ordering::SeqCst);
    }
}

impl<A, D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE> + Clone> Batch<A, D, Output> {
    /// Adds the given outputs to this batch.
    ///
    /// `replier` will be called with the result of every output.
    fn add_outputs(
        &mut self,
        domain: impl Fn() -> D,
        outputs: &[Output],
        replier: channel::Sender<OutputItem<A, D>>,
    ) {
        self.outputs
            .extend(outputs.iter().cloned().map(|output| (domain(), output)));
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
pub(crate) struct BatchRunner<A, D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>> {
    batch_size_threshold: usize,
    // The batch currently being accumulated.
    acc: Batch<A, D, Output>,
    // The dynamic memory usage of the running batches.
    running_usage: Arc<AtomicUsize>,
    // Receivers for the results of the running batches.
    pending_results: HashMap<ResultKey, BatchReceiver<A, D>>,
}

impl<A, D, Output> DynamicUsage for BatchRunner<A, D, Output>
where
    D: BatchDomain,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
{
    fn dynamic_usage(&self) -> usize {
        self.acc.dynamic_usage()
            + self.running_usage.load(Ordering::Relaxed)
            + self.pending_results.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        let running_usage = self.running_usage.load(Ordering::Relaxed);

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

impl<A, D, Output> BatchRunner<A, D, Output>
where
    A: Clone,
    D: BatchDomain,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
{
    /// Constructs a new batch runner for the given incoming viewing keys.
    pub(crate) fn new(
        batch_size_threshold: usize,
        ivks: impl Iterator<Item = (A, D::IncomingViewingKey)>,
    ) -> Self {
        let (tags, ivks) = ivks.unzip();
        let running_usage = Arc::new(AtomicUsize::new(0));
        Self {
            batch_size_threshold,
            acc: Batch::new(tags, ivks, running_usage.clone()),
            running_usage,
            pending_results: HashMap::default(),
        }
    }
}

impl<A, D, Output> BatchRunner<A, D, Output>
where
    A: Clone + Send + 'static,
    D: BatchDomain + Send + 'static,
    D::IncomingViewingKey: Clone + Send,
    D::Memo: Send,
    D::Note: Send,
    D::Recipient: Send,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE> + Clone + Send + 'static,
{
    /// Batches the given outputs for trial decryption.
    ///
    /// `block_tag` is the hash of the block that triggered this txid being added to the
    /// batch, or the all-zeros hash to indicate that no block triggered it (i.e. it was a
    /// mempool change).
    ///
    /// If after adding the given outputs, the accumulated batch size is at least
    /// `BATCH_SIZE_THRESHOLD`, `Self::flush` is called. Subsequent calls to
    /// `Self::add_outputs` will be accumulated into a new batch.
    pub(crate) fn add_outputs(
        &mut self,
        block_tag: BlockHash,
        txid: TxId,
        domain: impl Fn() -> D,
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
            let mut batch = Batch::new(
                self.acc.tags.clone(),
                self.acc.ivks.clone(),
                self.running_usage.clone(),
            );
            mem::swap(&mut batch, &mut self.acc);
            rayon::spawn_fifo(|| batch.run());
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
    ) -> HashMap<(TxId, usize), DecryptedNote<A, D>> {
        self.pending_results
            .remove(&ResultKey(block_tag, txid))
            // We won't have a pending result if the transaction didn't have outputs of
            // this runner's kind.
            .map(|BatchReceiver(rx)| {
                rx.into_iter()
                    .filter_map(
                        |OutputIndex {
                             output_index,
                             value,
                         }| {
                            value.map(|decrypted_note| ((txid, output_index), decrypted_note))
                        },
                    )
                    .collect()
            })
            .unwrap_or_default()
    }
}
