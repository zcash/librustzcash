//! Records the funding attribution that a late-linked transparent spend never produced.
//!
//! Storing a transaction whose funding account is known records, for each of its transparent
//! outputs, the account that paid for it and the recipient it paid. A transaction that reached
//! the wallet before the output it spends was recognized carries no such record: the spend was
//! held against the outpoint, and the row linking it to the transaction was written only when
//! the output was discovered, at which point nothing revisited the transaction. Its outputs were
//! reported forever as receipts from an unknown sender, so a transfer between two accounts of one
//! wallet appeared as an external payment.
//!
//! Every stored transaction the wallet records as spending one of its transparent outputs is
//! re-attributed here, from the transaction data the wallet holds. An output for which a
//! recipient is already recorded is left alone, so a wallet whose attribution is complete is
//! unchanged.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_protocol::consensus;

use super::transparent_tx_address_observations;
use crate::wallet::init::WalletMigrationError;

#[cfg(feature = "transparent-inputs")]
use crate::wallet::transparent::observations;

/// Records the account that funded each transparent output of a stored transaction whose spend
/// of a wallet output was linked after that transaction was stored.
pub const MIGRATION_ID: Uuid = Uuid::from_u128(0x5b29cad6_5691_4eec_a26a_deca8e77fd27);

/// `transparent_tx_address_observations` links spends to stored transactions across a wallet's
/// whole history, so the repair must follow it in order to cover everything it links.
pub(super) const DEPENDENCIES: &[Uuid] = &[transparent_tx_address_observations::MIGRATION_ID];

pub(super) struct Migration<P> {
    pub(super) _params: P,
}

impl<P> schemerz::Migration<Uuid> for Migration<P> {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Attributes the outputs of stored transactions whose transparent spends were linked late."
    }
}

impl<P: consensus::Parameters> RusqliteMigration for Migration<P> {
    type Error = WalletMigrationError;

    fn up(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        #[cfg(feature = "transparent-inputs")]
        observations::repair_funding_attribution(_transaction, &self._params)?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }

    /// The repair heals a wallet holding the shape this migration exists for: a stored
    /// transaction whose spend of a wallet output is linked, and whose own outputs carry no
    /// record of the account that funded them.
    ///
    /// The fixture is built through the wallet's own writers and then stripped of its
    /// attribution, because the writers no longer produce the broken state: a wallet reaches it
    /// only by having been upgraded before the attribution replay existed.
    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn repairs_a_linked_spend_with_no_attribution() {
        use schemerz_rusqlite::RusqliteMigration as _;
        use transparent::address::TransparentAddress;
        use zcash_client_backend::data_api::{
            Account as _, AccountPurpose, WalletWrite,
            testing::{TestBuilder, TestState},
        };
        use zcash_primitives::block::BlockHash;

        use crate::{
            testing::db::TestDbFactory,
            wallet::transparent::observations::tests::{
                external_address, store_spend_before_its_prevout, tx_output_accounts,
                unattributed_receipts,
            },
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();
        let network = *st.network();
        let host = st.test_account().unwrap();
        let host_uuid = host.account().id().expose_uuid();
        let birthday = host.birthday().clone();
        let host_address = external_address(&host.usk().to_unified_full_viewing_key(), 0);

        let (spend_tx, guest_ufvk) = store_spend_before_its_prevout(
            &mut st,
            host_address,
            TransparentAddress::PublicKeyHash([0x4B; 20]),
        );
        let spend_txid = spend_tx.txid();

        let guest_uuid = st
            .wallet_mut()
            .import_account_ufvk(
                "guest",
                &guest_ufvk,
                &birthday,
                AccountPurpose::ViewOnly,
                None,
            )
            .unwrap()
            .id()
            .expose_uuid();

        // Strip the attribution, leaving the linkage: the state of a wallet upgraded before the
        // replay existed.
        {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            conn.execute(
                "DELETE FROM sent_notes
                 WHERE transaction_id = (SELECT id_tx FROM transactions WHERE txid = :txid)",
                rusqlite::named_params! { ":txid": spend_txid.as_ref() },
            )
            .unwrap();
            conn.commit().unwrap();
        }
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            vec![(0, None, Some(guest_uuid)), (1, None, Some(host_uuid))],
            "the fixture starts with no attribution",
        );
        assert!(
            unattributed_receipts(&st.wallet().db().conn)
                .iter()
                .any(|(txid, _)| txid == spend_txid.as_ref()),
        );

        let migration = super::Migration { _params: network };
        let repair = |st: &TestState<_, crate::testing::db::TestDb, _>| {
            let conn = st.wallet().db().conn.unchecked_transaction().unwrap();
            migration.up(&conn).unwrap();
            conn.commit().unwrap();
        };

        repair(&st);

        let repaired = vec![
            (0, Some(guest_uuid), Some(guest_uuid)),
            (1, Some(guest_uuid), Some(host_uuid)),
            (2, Some(guest_uuid), None),
        ];
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            repaired,
        );
        assert!(
            unattributed_receipts(&st.wallet().db().conn)
                .iter()
                .all(|(txid, _)| txid != spend_txid.as_ref()),
        );

        // Running the repair again records nothing further.
        repair(&st);
        assert_eq!(
            tx_output_accounts(&st.wallet().db().conn, spend_txid),
            repaired,
        );
    }
}
