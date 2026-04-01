//! Full block batch decryption engine.

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
    full::{BatchResult, BatchRunners},
};

/// Constructs a new batch decryption engine.
pub fn new() -> Builder {
    Builder {
        queue_size: 1000,
        sapling_batch_size_threshold: 200,
        #[cfg(feature = "orchard")]
        orchard_batch_size_threshold: 200,
        batch_start_delay: Duration::from_millis(500),
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
    /// batch.
    ///
    /// Default is 200.
    pub fn batch_size_threshold(mut self, batch_size_threshold: usize) -> Self {
        self.sapling_batch_size_threshold = batch_size_threshold;
        #[cfg(feature = "orchard")]
        {
            self.orchard_batch_size_threshold = batch_size_threshold;
        }
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

    /// Requests decryption of a block.
    ///
    /// - Returns `None` if the batch decryptor has shut down.
    /// - Returns `Some(Err(block))` if the batch decryptor queue is full.
    pub fn try_queue_block(
        &self,
        block: Block,
    ) -> Option<Result<oneshot::Receiver<BlockDecryptResult<AccountId, IvkTag>>, Block>> {
        let (on_complete, rx) = oneshot::channel();
        match self
            .handle
            .try_send(DecryptRequest::Block { block, on_complete })
        {
            Ok(()) => Some(Ok(rx)),
            Err(mpsc::error::TrySendError::Full(DecryptRequest::Block { block, .. })) => {
                Some(Err(block))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => None,
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

    /// Requests decryption of a transaction.
    ///
    /// - Returns `None` if the batch decryptor has shut down.
    /// - Returns `Some(Err(tx))` if the batch decryptor queue is full.
    pub fn try_queue_tx(
        &self,
        tx: Transaction,
        mempool_height: BlockHeight,
    ) -> Option<Result<oneshot::Receiver<BatchResult<IvkTag>>, Transaction>> {
        let (on_complete, rx) = oneshot::channel();
        match self.handle.try_send(DecryptRequest::Tx {
            tx,
            mempool_height,
            on_complete,
        }) {
            Ok(()) => Some(Ok(rx)),
            Err(mpsc::error::TrySendError::Full(DecryptRequest::Tx { tx, .. })) => Some(Err(tx)),
            Err(mpsc::error::TrySendError::Closed(_)) => None,
            _ => unreachable!(),
        }
    }
}

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
    pub async fn run<P, E>(
        mut self,
        params: P,
        mut reload_keys: impl FnMut() -> Result<ScanningKeys<AccountId, IvkTag>, E>,
    ) -> Result<(), E>
    where
        P: consensus::Parameters + Send + 'static,
    {
        let scanning_keys = Arc::new(reload_keys()?);
        let mut runners = BatchRunners::<_, (), ()>::for_keys(
            self.sapling_batch_size_threshold,
            #[cfg(feature = "orchard")]
            self.orchard_batch_size_threshold,
            &scanning_keys,
        );

        loop {
            match time::timeout(self.batch_start_delay, self.queue.recv()).await {
                // Block decryption.
                Ok(Some(DecryptRequest::Block { block, on_complete })) => {
                    let mined_height = block.claimed_height();
                    let (header, vtx) = block.into_parts();
                    let batches = vtx
                        .into_iter()
                        .map(|tx| runners.process_transaction(&params, mined_height, tx))
                        .collect::<Vec<_>>();

                    // Take a copy of the scanning keys applied to this block.
                    let scanning_keys = scanning_keys.clone();

                    crate::spawn_blocking!("Block decryption waiter", || {
                        let vtx = batches
                            .into_iter()
                            .map(|batch| batch.wait())
                            .collect::<Vec<_>>();

                        // An error means the calling task is shutting down.
                        let _ = on_complete.send((scanning_keys, header, vtx));
                    });
                }

                // Mempool decryption.
                Ok(Some(DecryptRequest::Tx {
                    tx,
                    mempool_height,
                    on_complete,
                })) => {
                    let batch = runners.process_transaction(&params, mempool_height, tx);
                    crate::spawn_blocking!("Mempool decryption waiter", || {
                        // An error means the calling task is shutting down.
                        let _ = on_complete.send(batch.wait());
                    });
                }

                // Calling tasks are shutting down, so we are done.
                Ok(None) => return Ok(()),

                // Timed out waiting for another decryption request; ensure all prior
                // requests are running.
                Err(_) => runners.flush(),
            }
        }
    }
}
