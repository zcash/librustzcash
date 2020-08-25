//! Functions for scanning the chain and extracting relevant information.

use zcash_primitives::{
    consensus::{self, NetworkUpgrade},
    transaction::Transaction,
};

use crate::{
    data_api::{error::Error, DBOps, DBUpdate},
    decrypt_transaction,
};

/// Scans a [`Transaction`] for any information that can be decrypted by the accounts in
/// the wallet, and saves it to the wallet.
pub fn decrypt_and_store_transaction<'db, E0, N, E, P, D>(
    params: &P,
    data: &'db D,
    tx: &Transaction,
) -> Result<(), E>
where
    E: From<Error<E0, N>>,
    P: consensus::Parameters,
    &'db D: DBOps<Error = E>,
{
    // Fetch the ExtendedFullViewingKeys we are tracking
    let extfvks = data.get_extended_full_viewing_keys(params)?;

    // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
    // for mempool transactions.
    let height = data
        .get_tx_height(tx.txid())?
        .or(data
            .block_height_extrema()?
            .map(|(_, max_height)| max_height + 1))
        .or(params.activation_height(NetworkUpgrade::Sapling))
        .ok_or(Error::SaplingNotActive.into())?;

    let outputs = decrypt_transaction(params, height, tx, &extfvks);
    if outputs.is_empty() {
        Ok(())
    } else {
        let mut db_update = data.get_update_ops()?;

        // Update the database atomically, to ensure the result is internally consistent.
        data.transactionally(&mut db_update, |up| {
            let tx_ref = up.put_tx_data(tx)?;

            for output in outputs {
                if output.outgoing {
                    up.put_sent_note(params, &output, tx_ref)?;
                } else {
                    up.put_received_note(&output, None, tx_ref)?;
                }
            }

            Ok(())
        })
    }
}
