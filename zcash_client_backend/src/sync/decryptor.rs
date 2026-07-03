//! Full block batch decryption engine.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::{
    sync::{mpsc, oneshot},
    time,
};
use zcash_primitives::{
    block::{Block, BlockHeader},
    transaction::Transaction,
};
use zcash_protocol::consensus::{self, BlockHeight};

use crate::scanning::{
    ScanningKeys,
    full::{BatchResult, BatchRunners, DEFAULT_BATCH_SIZE_THRESHOLD},
};

/// The default depth of the queue between the [`Handle`]s and the [`Engine`].
const DEFAULT_QUEUE_SIZE: usize = 1000;

/// The default time the engine waits for a new queue item before flushing any pending
/// batches.
const DEFAULT_BATCH_START_DELAY: Duration = Duration::from_millis(500);

/// Constructs a new batch decryption engine.
pub fn new() -> Builder {
    Builder {
        queue_size: DEFAULT_QUEUE_SIZE,
        sapling_batch_size_threshold: DEFAULT_BATCH_SIZE_THRESHOLD,
        #[cfg(feature = "orchard")]
        orchard_batch_size_threshold: DEFAULT_BATCH_SIZE_THRESHOLD,
        batch_start_delay: DEFAULT_BATCH_START_DELAY,
    }
}

/// Builder for an [`Engine`].
pub struct Builder {
    queue_size: usize,
    sapling_batch_size_threshold: usize,
    #[cfg(feature = "orchard")]
    orchard_batch_size_threshold: usize,
    batch_start_delay: Duration,
}

impl Builder {
    /// Sets the size of the queue between [`Handle`]s and the [`Engine`].
    ///
    /// When the queue is full, calls to [`Handle::queue_block`] and [`Handle::queue_tx`]
    /// will wait until the queue has space, while calls to [`Handle::try_queue_block`]
    /// and [`Handle::try_queue_tx`] will return an error.
    ///
    /// Default is 1000.
    pub fn queue_size(mut self, queue_size: usize) -> Self {
        self.queue_size = queue_size;
        self
    }

    /// Sets the number of outputs at which the batch runner will immediately flush a
    /// batch, for both the Sapling and Orchard runners.
    ///
    /// To configure the pools independently, use [`Self::sapling_batch_size_threshold`]
    /// and [`Self::orchard_batch_size_threshold`].
    ///
    /// Default is 200.
    pub fn batch_size_threshold(self, batch_size_threshold: usize) -> Self {
        let this = self.sapling_batch_size_threshold(batch_size_threshold);
        #[cfg(feature = "orchard")]
        let this = this.orchard_batch_size_threshold(batch_size_threshold);
        this
    }

    /// Sets the number of outputs at which the Sapling batch runner will immediately
    /// flush a batch.
    ///
    /// Default is 200.
    pub fn sapling_batch_size_threshold(mut self, batch_size_threshold: usize) -> Self {
        self.sapling_batch_size_threshold = batch_size_threshold;
        self
    }

    /// Sets the number of outputs at which the Orchard batch runner will immediately
    /// flush a batch.
    ///
    /// Default is 200.
    #[cfg(feature = "orchard")]
    pub fn orchard_batch_size_threshold(mut self, batch_size_threshold: usize) -> Self {
        self.orchard_batch_size_threshold = batch_size_threshold;
        self
    }

    /// Sets how long the engine will wait for a queue item before automatically flushing
    /// any pending batches.
    ///
    /// Default is 500ms.
    pub fn batch_start_delay(mut self, batch_start_delay: Duration) -> Self {
        self.batch_start_delay = batch_start_delay;
        self
    }

    /// Builds the engine with the configured settings.
    pub fn build<AccountId, IvkTag>(
        self,
    ) -> (Handle<AccountId, IvkTag>, Engine<AccountId, IvkTag>) {
        let (handle, queue) = mpsc::channel(self.queue_size);

        (
            Handle { handle },
            Engine {
                queue,
                sapling_batch_size_threshold: self.sapling_batch_size_threshold,
                #[cfg(feature = "orchard")]
                orchard_batch_size_threshold: self.orchard_batch_size_threshold,
                batch_start_delay: self.batch_start_delay,
            },
        )
    }
}

/// The reason a non-blocking [`Handle::try_queue_block`] or [`Handle::try_queue_tx`]
/// request was rejected.
///
/// The rejected payload (the `Block` or `Transaction`) is returned in both cases, so that
/// the caller may retry.
#[derive(Debug)]
pub enum TryQueueError<T> {
    /// The batch decryptor has shut down.
    Shutdown(Box<T>),
    /// The batch decryptor queue is full.
    Full(Box<T>),
}

impl<T> TryQueueError<T> {
    /// Returns the rejected payload, discarding the reason for rejection.
    pub fn into_inner(self) -> T {
        match self {
            TryQueueError::Shutdown(payload) | TryQueueError::Full(payload) => *payload,
        }
    }
}

impl<T> fmt::Display for TryQueueError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TryQueueError::Shutdown(_) => f.write_str("the batch decryptor has shut down"),
            TryQueueError::Full(_) => f.write_str("the batch decryptor queue is full"),
        }
    }
}

impl<T: fmt::Debug> std::error::Error for TryQueueError<T> {}

/// A handle to a batch decryption [`Engine`].
#[derive(Clone)]
pub struct Handle<AccountId, IvkTag> {
    handle: mpsc::Sender<DecryptRequest<AccountId, IvkTag>>,
}

impl<AccountId, IvkTag> Handle<AccountId, IvkTag> {
    /// Requests decryption of a block, waiting until there is space in the queue.
    ///
    /// Returns `None` if the batch decryptor has shut down.
    pub async fn queue_block(
        &self,
        block: Block,
    ) -> Option<oneshot::Receiver<BlockDecryptResult<AccountId, IvkTag>>> {
        let (on_complete, rx) = oneshot::channel();
        match self
            .handle
            .send(DecryptRequest::Block { block, on_complete })
            .await
        {
            Ok(()) => Some(rx),
            Err(_) => None,
        }
    }

    /// Requests decryption of a block, without waiting for queue space.
    ///
    /// On failure the rejected `block` is returned, so that the caller may retry: see
    /// [`TryQueueError`].
    pub fn try_queue_block(
        &self,
        block: Block,
    ) -> Result<oneshot::Receiver<BlockDecryptResult<AccountId, IvkTag>>, TryQueueError<Block>>
    {
        let (on_complete, rx) = oneshot::channel();
        match self
            .handle
            .try_send(DecryptRequest::Block { block, on_complete })
        {
            Ok(()) => Ok(rx),
            Err(mpsc::error::TrySendError::Full(DecryptRequest::Block { block, .. })) => {
                Err(TryQueueError::Full(Box::new(block)))
            }
            Err(mpsc::error::TrySendError::Closed(DecryptRequest::Block { block, .. })) => {
                Err(TryQueueError::Shutdown(Box::new(block)))
            }
            _ => unreachable!(),
        }
    }

    /// Requests decryption of a transaction, waiting until there is space in the queue.
    ///
    /// Returns `None` if the batch decryptor has shut down.
    pub async fn queue_tx(
        &self,
        tx: Transaction,
        mempool_height: BlockHeight,
    ) -> Option<oneshot::Receiver<BatchResult<IvkTag>>> {
        let (on_complete, rx) = oneshot::channel();
        match self
            .handle
            .send(DecryptRequest::Tx {
                tx,
                mempool_height,
                on_complete,
            })
            .await
        {
            Ok(()) => Some(rx),
            Err(_) => None,
        }
    }

    /// Requests decryption of a transaction, without waiting for queue space.
    ///
    /// On failure the rejected `tx` is returned, so that the caller may retry: see
    /// [`TryQueueError`].
    pub fn try_queue_tx(
        &self,
        tx: Transaction,
        mempool_height: BlockHeight,
    ) -> Result<oneshot::Receiver<BatchResult<IvkTag>>, TryQueueError<Transaction>> {
        let (on_complete, rx) = oneshot::channel();
        match self.handle.try_send(DecryptRequest::Tx {
            tx,
            mempool_height,
            on_complete,
        }) {
            Ok(()) => Ok(rx),
            Err(mpsc::error::TrySendError::Full(DecryptRequest::Tx { tx, .. })) => {
                Err(TryQueueError::Full(Box::new(tx)))
            }
            Err(mpsc::error::TrySendError::Closed(DecryptRequest::Tx { tx, .. })) => {
                Err(TryQueueError::Shutdown(Box::new(tx)))
            }
            _ => unreachable!(),
        }
    }

    /// Requests that the engine reload its scanning keys, so that accounts or keys added
    /// since the engine started (or since the last reload) are applied to subsequently
    /// queued blocks and transactions.
    ///
    /// The reload is ordered within the queue: every block or transaction queued before
    /// this call is decrypted with the previous keys, and everything queued afterwards
    /// with the reloaded keys.
    ///
    /// Returns a receiver that completes once the reload has been applied, or `None` if
    /// the batch decryptor has shut down.
    ///
    /// Note that the returned receiver resolving to an error (because its sender was
    /// dropped) does not distinguish "the engine shut down" from "the reload closure
    /// passed to [`Engine::run`] returned an error, terminating the engine"; in both cases
    /// no further requests will be served.
    pub async fn reload_keys(&self) -> Option<oneshot::Receiver<()>> {
        let (on_complete, rx) = oneshot::channel();
        match self
            .handle
            .send(DecryptRequest::ReloadKeys { on_complete })
            .await
        {
            Ok(()) => Some(rx),
            Err(_) => None,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum DecryptRequest<AccountId, IvkTag> {
    Block {
        block: Block,
        on_complete: oneshot::Sender<BlockDecryptResult<AccountId, IvkTag>>,
    },
    Tx {
        tx: Transaction,
        mempool_height: BlockHeight,
        on_complete: oneshot::Sender<BatchResult<IvkTag>>,
    },
    ReloadKeys {
        on_complete: oneshot::Sender<()>,
    },
}

type BlockDecryptResult<AccountId, IvkTag> = (
    Arc<ScanningKeys<AccountId, IvkTag>>,
    BlockHeader,
    Vec<BatchResult<IvkTag>>,
);

/// A batch decryption engine.
pub struct Engine<AccountId, IvkTag> {
    queue: mpsc::Receiver<DecryptRequest<AccountId, IvkTag>>,
    sapling_batch_size_threshold: usize,
    #[cfg(feature = "orchard")]
    orchard_batch_size_threshold: usize,
    batch_start_delay: Duration,
}

impl<AccountId, IvkTag> Engine<AccountId, IvkTag>
where
    AccountId: 'static,
    IvkTag: Copy + Send + Sync + 'static,
{
    /// Runs the batch decryption engine.
    ///
    /// This method should be spawned as a task. It will loop indefinitely until either
    /// all [`Handle`]s have been dropped, or `reload_keys` returns an error.
    ///
    /// `reload_keys` is called once at startup, and then again each time a key reload is
    /// requested via [`Handle::reload_keys`], so that accounts or keys added after the
    /// engine started are picked up. Each block decryption result reports the
    /// [`ScanningKeys`] that were applied to it (see [`Handle::queue_block`]), so that a
    /// caller can detect which keys a given block was scanned with.
    ///
    /// For each queued block or transaction the engine spawns a lightweight asynchronous
    /// task that awaits the batch-runner results; decryption itself runs in parallel on
    /// the global threadpool. No blocking-pool threads are used.
    pub async fn run<P, E>(
        mut self,
        params: P,
        mut reload_keys: impl FnMut() -> Result<ScanningKeys<AccountId, IvkTag>, E>,
    ) -> Result<(), E>
    where
        P: consensus::Parameters + Send + 'static,
    {
        let mut scanning_keys = Arc::new(reload_keys()?);
        let mut runners = BatchRunners::<_, (), ()>::for_keys(
            self.sapling_batch_size_threshold,
            #[cfg(feature = "orchard")]
            self.orchard_batch_size_threshold,
            // Ironwood outputs are Orchard-shaped, so they use the same batching threshold.
            #[cfg(feature = "orchard")]
            self.orchard_batch_size_threshold,
            &scanning_keys,
        );

        // Whether a batch has been accumulated since the last flush. The idle-flush
        // timer is only armed while this is set, so that a quiescent engine does not
        // wake up to perform no-op flushes.
        //
        // The deadline is anchored to the first request after a flush and is not reset by
        // later requests, so a steady stream of sub-threshold requests cannot postpone the
        // flush of an aging batch indefinitely.
        let mut idle_flush_pending = false;
        let idle_flush = time::sleep(self.batch_start_delay);
        tokio::pin!(idle_flush);

        loop {
            tokio::select! {
                request = self.queue.recv() => match request {
                    // Block decryption.
                    Some(DecryptRequest::Block { block, on_complete }) => {
                        let mined_height = block.claimed_height();
                        let (header, vtx) = block.into_parts();
                        let batches = vtx
                            .into_iter()
                            .map(|tx| runners.process_transaction(&params, mined_height, tx))
                            .collect::<Vec<_>>();

                        // Record the scanning keys applied to this block.
                        let scanning_keys = scanning_keys.clone();

                        // Await the batch results on a lightweight task, so the engine
                        // loop stays free to accept further requests. The decryption
                        // work itself is already running on the global threadpool.
                        crate::spawn!("Block decryption", async move {
                            let mut vtx = Vec::with_capacity(batches.len());
                            for batch in batches {
                                vtx.push(batch.wait_async().await);
                            }
                            // An error means the calling task is shutting down.
                            let _ = on_complete.send((scanning_keys, header, vtx));
                        });
                        // Arm the idle-flush deadline on the first request after a flush;
                        // subsequent requests do not reset it, so an aging batch is
                        // flushed even under a steady stream of sub-threshold requests.
                        if !idle_flush_pending {
                            idle_flush
                                .as_mut()
                                .reset(time::Instant::now() + self.batch_start_delay);
                            idle_flush_pending = true;
                        }
                    }

                    // Mempool decryption.
                    Some(DecryptRequest::Tx {
                        tx,
                        mempool_height,
                        on_complete,
                    }) => {
                        let batch = runners.process_transaction(&params, mempool_height, tx);
                        crate::spawn!("Mempool decryption", async move {
                            // An error means the calling task is shutting down.
                            let _ = on_complete.send(batch.wait_async().await);
                        });
                        // Arm the idle-flush deadline on the first request after a flush;
                        // subsequent requests do not reset it, so an aging batch is
                        // flushed even under a steady stream of sub-threshold requests.
                        if !idle_flush_pending {
                            idle_flush
                                .as_mut()
                                .reset(time::Instant::now() + self.batch_start_delay);
                            idle_flush_pending = true;
                        }
                    }

                    // Key reload. Flush any pending batches under the current keys
                    // before rebuilding the runners with the reloaded set, so that
                    // blocks queued before this request are unaffected.
                    Some(DecryptRequest::ReloadKeys { on_complete }) => {
                        runners.flush();
                        scanning_keys = Arc::new(reload_keys()?);
                        runners = BatchRunners::for_keys(
                            self.sapling_batch_size_threshold,
                            #[cfg(feature = "orchard")]
                            self.orchard_batch_size_threshold,
                            // Ironwood outputs are Orchard-shaped, so they use the same batching
                            // threshold.
                            #[cfg(feature = "orchard")]
                            self.orchard_batch_size_threshold,
                            &scanning_keys,
                        );

                        // An error means the calling task is shutting down.
                        let _ = on_complete.send(());
                        idle_flush_pending = false;
                    }

                    // Calling tasks are shutting down, so we are done.
                    None => return Ok(()),
                },

                // The oldest accumulated batch has been waiting `batch_start_delay`;
                // flush so any sub-threshold batch is run rather than left waiting.
                _ = &mut idle_flush, if idle_flush_pending => {
                    runners.flush();
                    idle_flush_pending = false;
                }
            }
        }
    }
}
