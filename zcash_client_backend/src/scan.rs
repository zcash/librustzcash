use crossbeam_channel as channel;
use std::collections::HashMap;
use std::fmt;
use std::mem;

use zcash_note_encryption::{batch, BatchDomain, Domain, ShieldedOutput, COMPACT_NOTE_SIZE};
use zcash_primitives::{block::BlockHash, transaction::TxId};

/// A decrypted note.
pub(crate) struct DecryptedNote<D: Domain> {
    /// The incoming viewing key used to decrypt the note.
    pub(crate) ivk: D::IncomingViewingKey,
    /// The recipient of the note.
    pub(crate) recipient: D::Recipient,
    /// The note!
    pub(crate) note: D::Note,
}

impl<D: Domain> fmt::Debug for DecryptedNote<D>
where
    D::IncomingViewingKey: fmt::Debug,
    D::Recipient: fmt::Debug,
    D::Note: fmt::Debug,
    D::Memo: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedNote")
            .field("ivk", &self.ivk)
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

type OutputReplier<D> = OutputIndex<channel::Sender<OutputIndex<Option<DecryptedNote<D>>>>>;

/// A batch of outputs to trial decrypt.
struct Batch<D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>> {
    ivks: Vec<D::IncomingViewingKey>,
    /// We currently store outputs and repliers as parallel vectors, because
    /// [`batch::try_note_decryption`] accepts a slice of domain/output pairs
    /// rather than a value that implements `IntoIterator`, and therefore we
    /// can't just use `map` to select the parts we need in order to perform
    /// batch decryption. Ideally the domain, output, and output replier would
    /// all be part of the same struct, which would also track the output index
    /// (that is captured in the outer `OutputIndex` of each `OutputReplier`).
    outputs: Vec<(D, Output)>,
    repliers: Vec<OutputReplier<D>>,
}

impl<D, Output> Batch<D, Output>
where
    D: BatchDomain,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
    D::IncomingViewingKey: Clone,
{
    /// Constructs a new batch.
    fn new(ivks: Vec<D::IncomingViewingKey>) -> Self {
        Self {
            ivks,
            outputs: vec![],
            repliers: vec![],
        }
    }

    /// Returns `true` if the batch is currently empty.
    fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// Runs the batch of trial decryptions, and reports the results.
    fn run(self) {
        assert_eq!(self.outputs.len(), self.repliers.len());

        let decryption_results = batch::try_compact_note_decryption(&self.ivks, &self.outputs);
        for (decryption_result, replier) in decryption_results.into_iter().zip(self.repliers.iter())
        {
            let result = OutputIndex {
                output_index: replier.output_index,
                value: decryption_result.map(|((note, recipient), ivk_idx)| DecryptedNote {
                    ivk: self.ivks[ivk_idx].clone(),
                    recipient,
                    note,
                }),
            };

            if replier.value.send(result).is_err() {
                tracing::debug!("BatchRunner was dropped before batch finished");
                return;
            }
        }
    }
}

impl<D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE> + Clone> Batch<D, Output> {
    /// Adds the given outputs to this batch.
    ///
    /// `replier` will be called with the result of every output.
    fn add_outputs(
        &mut self,
        domain: impl Fn() -> D,
        outputs: &[Output],
        replier: channel::Sender<OutputIndex<Option<DecryptedNote<D>>>>,
    ) {
        self.outputs
            .extend(outputs.iter().cloned().map(|output| (domain(), output)));
        self.repliers
            .extend((0..outputs.len()).map(|output_index| OutputIndex {
                output_index,
                value: replier.clone(),
            }));
    }
}

type ResultKey = (BlockHash, TxId);

/// Logic to run batches of trial decryptions on the global threadpool.
pub(crate) struct BatchRunner<D: BatchDomain, Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>> {
    batch_size_threshold: usize,
    acc: Batch<D, Output>,
    pending_results: HashMap<ResultKey, channel::Receiver<OutputIndex<Option<DecryptedNote<D>>>>>,
}

impl<D, Output> BatchRunner<D, Output>
where
    D: BatchDomain,
    Output: ShieldedOutput<D, COMPACT_NOTE_SIZE>,
    D::IncomingViewingKey: Clone,
{
    /// Constructs a new batch runner for the given incoming viewing keys.
    pub(crate) fn new(batch_size_threshold: usize, ivks: Vec<D::IncomingViewingKey>) -> Self {
        Self {
            batch_size_threshold,
            acc: Batch::new(ivks),
            pending_results: HashMap::default(),
        }
    }
}

impl<D, Output> BatchRunner<D, Output>
where
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
        self.pending_results.insert((block_tag, txid), rx);

        if self.acc.outputs.len() >= self.batch_size_threshold {
            self.flush();
        }
    }

    /// Runs the currently accumulated batch on the global threadpool.
    ///
    /// Subsequent calls to `Self::add_outputs` will be accumulated into a new batch.
    pub(crate) fn flush(&mut self) {
        if !self.acc.is_empty() {
            let mut batch = Batch::new(self.acc.ivks.clone());
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
    ) -> HashMap<(TxId, usize), DecryptedNote<D>> {
        self.pending_results
            .remove(&(block_tag, txid))
            // We won't have a pending result if the transaction didn't have outputs of
            // this runner's kind.
            .map(|rx| {
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
