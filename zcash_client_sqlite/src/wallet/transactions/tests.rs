use std::convert::Infallible;

use rusqlite::{Connection, named_params};
use zcash_client_backend::{
    data_api::{
        Account as _, TransactionDataRequest, TransactionStatus, WalletRead, WalletWrite,
        testing::{
            TestBuilder, TestState,
            pool::{ShieldedPoolTester, dsl::TestDsl},
            sapling::SaplingPoolTester,
        },
        wallet::ConfirmationsPolicy,
    },
    wallet::OvkPolicy,
};
use zcash_primitives::block::BlockHash;
use zcash_protocol::{ShieldedPool, TxId, local_consensus::LocalNetwork, value::Zatoshis};

use crate::{
    NullifierQuery, TxRef, WalletDb,
    error::SqliteClientError,
    testing::{
        BlockCache,
        db::{TestDb, TestDbFactory, test_clock, test_rng},
    },
    wallet::common,
};

use super::POOLS;

#[cfg(feature = "orchard")]
use {
    zcash_client_backend::{
        data_api::testing::{AddressType, IronwoodFvk, orchard::OrchardPoolTester},
        fees::StandardFeeRule,
    },
    zcash_protocol::consensus::{NetworkUpgrade, Parameters},
};

#[cfg(feature = "transparent-inputs")]
use {
    transparent::{
        address::{Script, TransparentAddress},
        bundle::OutPoint,
    },
    zcash_client_backend::data_api::{
        CoinbaseFilter, InputSource,
        wallet::input_selection::{LockFilter, LockedInputPolicy},
    },
    zcash_keys::encoding::AddressCodec,
};

/// Each fixture note is large enough to remain economic under the standard fee rule.
const VALUE: Zatoshis = Zatoshis::const_from_u64(100_000);

fn fixture() -> TestState<(), TestDb, LocalNetwork> {
    let mut st = TestBuilder::new()
        .with_data_store_factory(TestDbFactory::file_backed())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let tip = st.sapling_activation_height();
    st.wallet_mut().update_chain_tip(tip).unwrap();
    st
}

fn tx(conn: &Connection, tag: u8) -> (TxRef, TxId) {
    let txid = TxId::from_bytes([tag; 32]);
    let id = conn
        .query_row(
            "INSERT INTO transactions (txid, expiry_height, min_observed_height)
             VALUES (?, 0, 0) RETURNING id_tx",
            [txid.as_ref()],
            |row| row.get(0).map(TxRef),
        )
        .unwrap();
    (id, txid)
}

/// Creates a relationship fixture, not a cryptographically spendable note.
fn output(st: &TestState<(), TestDb, LocalNetwork>, parent: TxRef, pool: usize) -> i64 {
    let conn = st.wallet().conn();
    let account: i64 = conn
        .query_row("SELECT id FROM accounts LIMIT 1", [], |row| row.get(0))
        .unwrap();
    let (table, _, _) = POOLS[pool];
    let sql = match pool {
        0 => format!(
            "INSERT INTO {table} (transaction_id, output_index, account_id,
                diversifier, value, rcm, is_change)
             VALUES (:tx, 0, :account, zeroblob(11), :value, zeroblob(32), 1)
             RETURNING id"
        ),
        1 | 2 => format!(
            "INSERT INTO {table} (transaction_id, action_index, account_id,
                diversifier, value, rho, rseed, is_change, note_version)
             VALUES (:tx, 0, :account, zeroblob(11), :value, zeroblob(32), zeroblob(32), 1, 2)
             RETURNING id"
        ),
        #[cfg(feature = "transparent-inputs")]
        3 => {
            let (address_id, address): (i64, String) = conn
                .query_row(
                    "SELECT id, cached_transparent_receiver_address FROM addresses
                     WHERE cached_transparent_receiver_address IS NOT NULL LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let receiver = TransparentAddress::decode(st.network(), &address).unwrap();
            return conn.query_row(
                "INSERT INTO transparent_received_outputs
                    (transaction_id, output_index, account_id, address, address_id, script, value_zat)
                 VALUES (?, 0, ?, ?, ?, ?, ?) RETURNING id",
                rusqlite::params![
                    parent.0, account, address, address_id,
                    Script::from(receiver.script()).0.0, u64::from(VALUE)
                ],
                |row| row.get(0),
            ).unwrap();
        }
        _ => unreachable!(),
    };
    conn.query_row(
        &sql,
        named_params![
            ":tx": parent.0,
            ":account": account,
            ":value": u64::from(VALUE),
        ],
        |row| row.get(0),
    )
    .unwrap()
}

fn spend(conn: &Connection, pool: usize, output: i64, child: TxRef) {
    let (_, spends, output_id) = POOLS[pool];
    conn.execute(
        &format!("INSERT INTO {spends} ({output_id}, transaction_id) VALUES (?, ?)"),
        [output, child.0],
    )
    .unwrap();
}

fn mapped_spend(conn: &Connection, child: TxRef, parent: TxId) {
    conn.execute(
        "INSERT INTO transparent_spend_map
            (spending_transaction_id, prevout_txid, prevout_output_index)
         VALUES (?, ?, 0)",
        rusqlite::params![child.0, parent.as_ref()],
    )
    .unwrap();
}

fn abandoned(conn: &Connection, txid: TxId) -> bool {
    conn.query_row(
        "SELECT abandoned FROM transactions WHERE txid = ?",
        [txid.as_ref()],
        |row| row.get(0),
    )
    .unwrap()
}

fn retrieval_queue_len(conn: &Connection) -> usize {
    conn.query_row("SELECT COUNT(*) FROM tx_retrieval_queue", [], |row| {
        row.get(0)
    })
    .unwrap()
}

#[test]
fn abandonment_cascades_across_pools_and_survives_reopen() {
    let mut st = fixture();
    let (root, root_txid) = tx(st.wallet().conn(), 1);
    st.wallet()
        .conn()
        .execute(
            "INSERT INTO tx_retrieval_queue (txid, query_type) VALUES (?, ?)",
            rusqlite::params![root_txid.as_ref(), super::super::TxQueryType::Status.code()],
        )
        .unwrap();
    let mut parent = root;
    let mut txids = vec![root_txid];
    for pool in 0..POOLS.len() {
        if pool == 3 && !cfg!(feature = "transparent-inputs") {
            continue;
        }
        let (child, child_txid) = tx(st.wallet().conn(), u8::try_from(pool + 2).unwrap());
        let note = output(&st, parent, pool);
        spend(st.wallet().conn(), pool, note, child);
        txids.push(child_txid);
        parent = child;
    }
    st.wallet_mut().abandon_transaction(root_txid).unwrap();
    st.wallet_mut().abandon_transaction(root_txid).unwrap();
    let reopened = WalletDb::for_path(
        st.wallet().data_file_path(),
        *st.network(),
        test_clock(),
        test_rng(),
    )
    .unwrap();
    for txid in txids {
        assert!(abandoned(&reopened.conn, txid));
    }
    assert!(
        reopened
            .transaction_data_requests()
            .unwrap()
            .contains(&TransactionDataRequest::GetStatus(root_txid))
    );
    for view in ["v_transactions", "v_transactions_with_pending_migrations"] {
        let count: usize = reopened
            .conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {view} WHERE abandoned = 1"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(count > 0);
    }
}

#[test]
fn abandonment_rejects_unknown_and_mined_descendants_without_writes() {
    let mut st = fixture();
    let unknown = TxId::from_bytes([0xff; 32]);
    assert!(matches!(
        st.wallet_mut().abandon_transaction(unknown),
        Err(SqliteClientError::TransactionUnknown(id)) if id == unknown
    ));
    let (parent, parent_txid) = tx(st.wallet().conn(), 1);
    let (child, child_txid) = tx(st.wallet().conn(), 2);
    let note = output(&st, parent, 0);
    spend(st.wallet().conn(), 0, note, child);
    st.wallet()
        .conn()
        .execute(
            "UPDATE transactions SET mined_height = 1 WHERE id_tx = ?",
            [child.0],
        )
        .unwrap();
    for txid in [parent_txid, child_txid] {
        assert!(matches!(
            st.wallet_mut().abandon_transaction(txid),
            Err(SqliteClientError::TransactionMined(id)) if id == child_txid
        ));
    }
    assert!(!abandoned(st.wallet().conn(), parent_txid));
    assert!(!abandoned(st.wallet().conn(), child_txid));
    assert_eq!(retrieval_queue_len(st.wallet().conn()), 0);
}

#[test]
fn abandonment_rolls_back_after_a_partial_write_and_can_be_retried() {
    let mut st = fixture();
    let (parent, parent_txid) = tx(st.wallet().conn(), 1);
    let (child, child_txid) = tx(st.wallet().conn(), 2);
    let note = output(&st, parent, 0);
    spend(st.wallet().conn(), 0, note, child);
    st.wallet()
        .conn()
        .execute_batch(&format!(
            "CREATE TRIGGER fail_abandon BEFORE UPDATE OF abandoned ON transactions
         WHEN NEW.id_tx = {}
         BEGIN SELECT RAISE(ABORT, 'injected abandonment failure'); END;",
            child.0,
        ))
        .unwrap();
    assert!(st.wallet_mut().abandon_transaction(parent_txid).is_err());
    for txid in [parent_txid, child_txid] {
        assert!(!abandoned(st.wallet().conn(), txid));
    }
    assert_eq!(retrieval_queue_len(st.wallet().conn()), 0);
    st.wallet()
        .conn()
        .execute_batch("DROP TRIGGER fail_abandon")
        .unwrap();
    st.wallet_mut().abandon_transaction(parent_txid).unwrap();
    assert!(abandoned(st.wallet().conn(), parent_txid));
    assert!(abandoned(st.wallet().conn(), child_txid));
}

#[test]
fn mempool_observation_reactivates_ancestors_but_not_descendants() {
    let mut st = fixture();
    let (parent, parent_txid) = tx(st.wallet().conn(), 1);
    let (child, child_txid) = tx(st.wallet().conn(), 2);
    let (grandchild, grandchild_txid) = tx(st.wallet().conn(), 3);
    let a = output(&st, parent, 0);
    let b = output(&st, child, 1);
    spend(st.wallet().conn(), 0, a, child);
    spend(st.wallet().conn(), 1, b, grandchild);
    st.wallet_mut().abandon_transaction(parent_txid).unwrap();
    for status in [
        TransactionStatus::TxidNotRecognized,
        TransactionStatus::NotInMainChain,
    ] {
        st.wallet_mut()
            .set_transaction_status(child_txid, status)
            .unwrap();
        assert!(abandoned(st.wallet().conn(), child_txid));
    }
    st.wallet_mut()
        .set_transaction_status(child_txid, TransactionStatus::InMempool)
        .unwrap();
    assert!(!abandoned(st.wallet().conn(), parent_txid));
    assert!(!abandoned(st.wallet().conn(), child_txid));
    assert!(abandoned(st.wallet().conn(), grandchild_txid));
}

#[test]
fn abandonment_follows_transparent_dependencies_without_recognized_prevouts() {
    let mut st = fixture();
    let (_, funding_txid) = tx(st.wallet().conn(), 1);
    let (parent, parent_txid) = tx(st.wallet().conn(), 2);
    let (child, child_txid) = tx(st.wallet().conn(), 3);
    let (replacement, replacement_txid) = tx(st.wallet().conn(), 4);
    mapped_spend(st.wallet().conn(), parent, funding_txid);
    mapped_spend(st.wallet().conn(), child, parent_txid);
    st.wallet_mut().abandon_transaction(parent_txid).unwrap();
    assert!(abandoned(st.wallet().conn(), child_txid));
    mapped_spend(st.wallet().conn(), replacement, funding_txid);
    st.wallet_mut()
        .set_transaction_status(child_txid, TransactionStatus::InMempool)
        .unwrap();
    assert!(!abandoned(st.wallet().conn(), parent_txid));
    assert!(!abandoned(st.wallet().conn(), child_txid));
    assert!(abandoned(st.wallet().conn(), replacement_txid));
}

#[test]
#[cfg(feature = "transparent-inputs")]
fn observation_reconciles_conflicts_between_mapped_and_recognized_prevouts() {
    for original_is_mapped in [false, true] {
        let mut st = fixture();
        let (funding, funding_txid) = tx(st.wallet().conn(), 1);
        let (original, original_txid) = tx(st.wallet().conn(), 2);
        let (replacement, replacement_txid) = tx(st.wallet().conn(), 3);
        let note = output(&st, funding, 3);
        let (mapped, recognized) = if original_is_mapped {
            (original, replacement)
        } else {
            (replacement, original)
        };
        mapped_spend(st.wallet().conn(), mapped, funding_txid);
        spend(st.wallet().conn(), 3, note, recognized);
        st.wallet_mut().abandon_transaction(original_txid).unwrap();
        st.wallet_mut()
            .set_transaction_status(original_txid, TransactionStatus::InMempool)
            .unwrap();
        assert!(!abandoned(st.wallet().conn(), original_txid));
        assert!(abandoned(st.wallet().conn(), replacement_txid));
    }
}

#[test]
#[cfg(feature = "transparent-inputs")]
fn late_linked_dependency_inherits_abandonment_but_mining_reactivates_it() {
    let mut st = fixture();
    let (_, parent_txid) = tx(st.wallet().conn(), 1);
    st.wallet_mut().abandon_transaction(parent_txid).unwrap();
    let (child, child_txid) = tx(st.wallet().conn(), 2);
    let sql_tx = st.wallet_mut().conn_mut().transaction().unwrap();
    super::super::transparent::mark_transparent_utxo_spent(
        &sql_tx,
        child,
        &OutPoint::new(parent_txid.into(), 0),
    )
    .unwrap();
    sql_tx.commit().unwrap();
    assert!(abandoned(st.wallet().conn(), child_txid));
    let tip = st.sapling_activation_height();
    st.wallet_mut()
        .set_transaction_status(child_txid, TransactionStatus::Mined(tip))
        .unwrap();
    assert!(!abandoned(st.wallet().conn(), parent_txid));
    assert!(!abandoned(st.wallet().conn(), child_txid));
}

#[test]
fn mined_original_abandons_replacement_and_its_descendants() {
    let mut st = fixture();
    let (funding, _) = tx(st.wallet().conn(), 1);
    let (original, original_txid) = tx(st.wallet().conn(), 2);
    let (replacement, replacement_txid) = tx(st.wallet().conn(), 3);
    let (child, child_txid) = tx(st.wallet().conn(), 4);
    let input = output(&st, funding, 0);
    spend(st.wallet().conn(), 0, input, original);
    st.wallet_mut().abandon_transaction(original_txid).unwrap();
    spend(st.wallet().conn(), 0, input, replacement);
    let change = output(&st, replacement, 1);
    spend(st.wallet().conn(), 1, change, child);
    let tip = st.sapling_activation_height();
    st.wallet_mut()
        .set_transaction_status(original_txid, TransactionStatus::Mined(tip))
        .unwrap();
    assert!(!abandoned(st.wallet().conn(), original_txid));
    assert!(abandoned(st.wallet().conn(), replacement_txid));
    assert!(abandoned(st.wallet().conn(), child_txid));
    // A stale mempool response cannot override the mined original.
    st.wallet_mut()
        .set_transaction_status(replacement_txid, TransactionStatus::InMempool)
        .unwrap();
    assert!(abandoned(st.wallet().conn(), replacement_txid));
}

#[test]
fn abandoned_nonexpiring_spends_release_inputs_in_every_pool() {
    let mut st = fixture();
    for pool in 0..3 {
        let (funding, _) = tx(st.wallet().conn(), u8::try_from(pool * 2 + 1).unwrap());
        let (spender, txid) = tx(st.wallet().conn(), u8::try_from(pool * 2 + 2).unwrap());
        let note = output(&st, funding, pool);
        spend(st.wallet().conn(), pool, note, spender);
        let prefix = ["sapling", "orchard", "ironwood"][pool];
        let spent = |st: &TestState<(), TestDb, LocalNetwork>| {
            let sql = common::spent_notes_clause(st.network(), prefix);
            st.wallet().conn().query_row(
                &format!("SELECT EXISTS(SELECT 1 FROM ({sql}) WHERE {prefix}_received_note_id = :note)"),
                named_params![":note": note, ":target_height": u32::from(st.sapling_activation_height()) + 1],
                |row| row.get::<_, bool>(0),
            ).unwrap()
        };
        assert!(spent(&st));
        st.wallet_mut().abandon_transaction(txid).unwrap();
        assert!(!spent(&st));
        assert!(abandoned(st.wallet().conn(), txid));
    }
}

#[test]
fn abandonment_preserves_other_active_spends_and_explicit_locks() {
    let mut st = fixture();
    let (funding, _) = tx(st.wallet().conn(), 1);
    let (first, first_txid) = tx(st.wallet().conn(), 2);
    let (second, second_txid) = tx(st.wallet().conn(), 3);
    let note = output(&st, funding, 0);
    spend(st.wallet().conn(), 0, note, first);
    spend(st.wallet().conn(), 0, note, second);
    let lock_height = st.sapling_activation_height() + 100;
    st.wallet()
        .conn()
        .execute(
            "UPDATE sapling_received_notes SET lock_expiry_height = ? WHERE id = ?",
            rusqlite::params![u32::from(lock_height), note],
        )
        .unwrap();
    st.wallet_mut().abandon_transaction(first_txid).unwrap();
    assert!(!abandoned(st.wallet().conn(), second_txid));
    let spent = common::spent_notes_clause(st.network(), "sapling");
    let still_spent: bool = st.wallet().conn().query_row(
        &format!("SELECT EXISTS(SELECT 1 FROM ({spent}) WHERE sapling_received_note_id = :note)"),
        named_params![":note": note, ":target_height": u32::from(st.sapling_activation_height()) + 1],
        |row| row.get(0),
    ).unwrap();
    assert!(still_spent);
    let actual_lock: u32 = st
        .wallet()
        .conn()
        .query_row(
            "SELECT lock_expiry_height FROM sapling_received_notes WHERE id = ?",
            [note],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(actual_lock, u32::from(lock_height));
}

#[test]
fn abandonment_keeps_nonexpiring_spends_discoverable_by_nullifier() {
    let mut st = fixture();
    for (pool, protocol) in [
        (0, ShieldedPool::Sapling),
        #[cfg(feature = "orchard")]
        (1, ShieldedPool::Orchard),
        #[cfg(feature = "orchard")]
        (2, ShieldedPool::Ironwood),
    ] {
        let (funding, _) = tx(st.wallet().conn(), u8::try_from(pool * 2 + 1).unwrap());
        let (spender, txid) = tx(st.wallet().conn(), u8::try_from(pool * 2 + 2).unwrap());
        let note = output(&st, funding, pool);
        let (notes, _, _) = POOLS[pool];
        st.wallet()
            .conn()
            .execute(
                &format!("UPDATE {notes} SET nf = zeroblob(32) WHERE id = ?"),
                [note],
            )
            .unwrap();
        st.wallet()
            .conn()
            .execute(
                "UPDATE transactions SET mined_height = 1 WHERE id_tx = ?",
                [funding.0],
            )
            .unwrap();
        spend(st.wallet().conn(), pool, note, spender);
        let nullifiers = |st: &TestState<(), TestDb, LocalNetwork>| {
            common::get_nullifiers(
                st.wallet().conn(),
                protocol,
                NullifierQuery::Unspent,
                |nf| Ok(nf.to_vec()),
            )
            .unwrap()
        };
        assert!(nullifiers(&st).is_empty());
        st.wallet_mut().abandon_transaction(txid).unwrap();
        assert_eq!(nullifiers(&st).len(), 1);
    }
}

#[test]
fn mempool_reactivation_rolls_back_both_sides_on_error() {
    let mut st = fixture();
    let (funding, _) = tx(st.wallet().conn(), 1);
    let (original, original_txid) = tx(st.wallet().conn(), 2);
    let (replacement, replacement_txid) = tx(st.wallet().conn(), 3);
    let input = output(&st, funding, 0);
    spend(st.wallet().conn(), 0, input, original);
    st.wallet_mut().abandon_transaction(original_txid).unwrap();
    spend(st.wallet().conn(), 0, input, replacement);
    let queue_len = retrieval_queue_len(st.wallet().conn());
    st.wallet()
        .conn()
        .execute_batch(&format!(
            "CREATE TRIGGER fail_reactivate BEFORE UPDATE OF abandoned ON transactions
         WHEN NEW.id_tx = {} AND NEW.abandoned = 0
         BEGIN SELECT RAISE(ABORT, 'injected reactivation failure'); END;",
            original.0,
        ))
        .unwrap();
    assert!(
        st.wallet_mut()
            .set_transaction_status(original_txid, TransactionStatus::InMempool)
            .is_err()
    );
    assert!(abandoned(st.wallet().conn(), original_txid));
    assert!(!abandoned(st.wallet().conn(), replacement_txid));
    assert_eq!(retrieval_queue_len(st.wallet().conn()), queue_len);
    st.wallet()
        .conn()
        .execute_batch("DROP TRIGGER fail_reactivate")
        .unwrap();
    st.wallet_mut()
        .set_transaction_status(original_txid, TransactionStatus::InMempool)
        .unwrap();
    assert!(!abandoned(st.wallet().conn(), original_txid));
    assert!(abandoned(st.wallet().conn(), replacement_txid));
}

fn restores_shielded_inputs<T: ShieldedPoolTester>() {
    let mut st =
        TestDsl::with_sapling_birthday_account(TestDbFactory::default(), BlockCache::new())
            .build::<T>();
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    st.add_a_single_note_checking_balance(VALUE);
    let to = T::sk_default_address(&T::sk(&[0xf5; 32]));
    let proposal = st.propose_transfer_to(&to, Zatoshis::const_from_u64(20_000));
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];
    let pending_balance = st.get_total_balance(account_id);
    assert!(pending_balance < VALUE);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO
    );
    let raw = st.wallet().get_transaction(txid).unwrap().unwrap();
    st.wallet_mut().abandon_transaction(txid).unwrap();
    assert!(
        !st.wallet()
            .transaction_data_requests()
            .unwrap()
            .contains(&TransactionDataRequest::GetStatus(txid))
    );
    assert_eq!(st.get_total_balance(account_id), VALUE);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        VALUE
    );
    // Cached raw data must not reactivate abandonment.
    let network = *st.network();
    zcash_client_backend::data_api::wallet::decrypt_and_store_transaction(
        &network,
        st.wallet_mut(),
        &raw,
        None,
    )
    .unwrap();
    assert_eq!(st.get_total_balance(account_id), VALUE);
    // A replacement can immediately reuse the released note.
    let replacement_proposal = st.propose_transfer_to(&to, Zatoshis::const_from_u64(25_000));
    let replacement = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &replacement_proposal,
        )
        .unwrap()[0];
    assert_ne!(replacement, txid);
    let (height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(height, 1);
    assert!(!abandoned(st.wallet().conn(), txid));
    assert!(abandoned(st.wallet().conn(), replacement));
    assert_eq!(st.get_total_balance(account_id), pending_balance);
    st.truncate_to_height(height - 1);
    assert!(!abandoned(st.wallet().conn(), txid));
    assert_eq!(st.get_total_balance(account_id), pending_balance);
}

#[test]
fn abandonment_restores_sapling_inputs_and_later_scanning_reactivates() {
    restores_shielded_inputs::<SaplingPoolTester>();
}

#[test]
#[cfg(feature = "orchard")]
fn abandonment_restores_orchard_inputs_and_later_scanning_reactivates() {
    restores_shielded_inputs::<zcash_client_backend::data_api::testing::orchard::OrchardPoolTester>(
    );
}

#[test]
#[cfg(feature = "orchard")]
fn abandonment_restores_ironwood_inputs_and_mempool_observation_reserves_them() {
    let activation = TestBuilder::<(), ()>::DEFAULT_NETWORK
        .activation_height(NetworkUpgrade::Sapling)
        .unwrap();
    let network = LocalNetwork {
        nu6: Some(activation),
        nu6_1: Some(activation),
        nu6_2: Some(activation),
        nu6_3: Some(activation),
        ..TestBuilder::<(), ()>::DEFAULT_NETWORK
    };
    let mut st = TestBuilder::new()
        .with_network(network)
        .with_data_store_factory(TestDbFactory::default())
        .with_block_cache(BlockCache::new())
        .with_account_from_sapling_activation(BlockHash([0; 32]))
        .build();
    let account = st.test_account().cloned().unwrap();
    let account_id = account.id();
    let recipient = IronwoodFvk(OrchardPoolTester::test_account_fvk(&st));
    let (height, _, _) = st.generate_next_block(&recipient, AddressType::DefaultExternal, VALUE);
    st.scan_cached_blocks(height, 1);
    for _ in 0..5 {
        let (height, _) = st.generate_empty_block();
        st.scan_cached_blocks(height, 1);
    }
    let to = OrchardPoolTester::sk_default_address(&OrchardPoolTester::sk(&[0xf5; 32]));
    let proposal = st
        .propose_standard_transfer::<Infallible>(
            account_id,
            StandardFeeRule::Zip317,
            ConfirmationsPolicy::MIN,
            &to,
            Zatoshis::const_from_u64(20_000),
            None,
            None,
            ShieldedPool::Ironwood,
        )
        .unwrap();
    let txid = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap()[0];
    assert!(
        st.wallet()
            .get_transaction(txid)
            .unwrap()
            .unwrap()
            .ironwood_bundle()
            .is_some()
    );
    let pending_balance = st.get_total_balance(account_id);
    st.wallet_mut().abandon_transaction(txid).unwrap();
    assert_eq!(st.get_total_balance(account_id), VALUE);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        VALUE
    );
    st.propose_standard_transfer::<Infallible>(
        account_id,
        StandardFeeRule::Zip317,
        ConfirmationsPolicy::MIN,
        &to,
        Zatoshis::const_from_u64(20_000),
        None,
        None,
        ShieldedPool::Ironwood,
    )
    .unwrap();
    st.wallet_mut()
        .set_transaction_status(txid, TransactionStatus::InMempool)
        .unwrap();
    assert_eq!(st.get_total_balance(account_id), pending_balance);
    assert_eq!(
        st.get_spendable_balance(account_id, ConfirmationsPolicy::MIN),
        Zatoshis::ZERO
    );
    let (height, _) = st.generate_next_block_including(txid);
    st.scan_cached_blocks(height, 1);
    assert!(!abandoned(st.wallet().conn(), txid));
    assert_eq!(st.get_total_balance(account_id), pending_balance);
}

#[test]
#[cfg(feature = "transparent-inputs")]
fn abandonment_restores_transparent_inputs_and_excludes_zero_conf_change() {
    let mut st = fixture();
    let (funding, funding_txid) = tx(st.wallet().conn(), 1);
    let (spender, spender_txid) = tx(st.wallet().conn(), 2);
    let input = output(&st, funding, 3);
    output(&st, spender, 3);
    spend(st.wallet().conn(), 3, input, spender);
    let account_id = st.test_account().unwrap().id();
    let address: String = st
        .wallet()
        .conn()
        .query_row(
            "SELECT address FROM transparent_received_outputs WHERE id = ?",
            [input],
            |row| row.get(0),
        )
        .unwrap();
    let address = TransparentAddress::decode(st.network(), &address).unwrap();
    let target = (st.sapling_activation_height() + 1).into();
    let select = |st: &TestState<(), TestDb, LocalNetwork>| {
        st.wallet()
            .get_spendable_transparent_outputs(
                &address,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .unwrap()
    };
    let before = select(&st);
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].outpoint(), &OutPoint::new(spender_txid.into(), 0));
    st.wallet_mut().abandon_transaction(spender_txid).unwrap();
    let after = select(&st);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].outpoint(), &OutPoint::new(funding_txid.into(), 0));
    assert!(
        st.wallet()
            .get_unspent_transparent_output(&OutPoint::new(spender_txid.into(), 0), target,)
            .unwrap()
            .is_none()
    );
    let balances = st
        .wallet()
        .get_transparent_balances(account_id, target, ConfirmationsPolicy::MIN)
        .unwrap();
    assert_eq!(balances[&address].1.total(), VALUE);
}

#[test]
#[cfg(feature = "transparent-inputs")]
fn abandonment_of_tex_child_preserves_mined_parent_and_releases_ephemeral_input() {
    let mut st =
        TestDsl::with_sapling_birthday_account(TestDbFactory::default(), BlockCache::new())
            .build::<SaplingPoolTester>();
    let account = st.test_account().cloned().unwrap();
    st.add_a_single_note_checking_balance(VALUE);
    let to = zcash_keys::address::Address::Tex([7; 20]);
    let proposal = st.propose_transfer_to(&to, Zatoshis::const_from_u64(20_000));
    let txids = st
        .create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        )
        .unwrap();
    assert_eq!(txids.len(), 2);
    let parent = txids[0];
    let child = txids[1];
    let (height, _) = st.generate_next_block_including(parent);
    st.scan_cached_blocks(height, 1);
    let ephemeral = st
        .wallet()
        .get_ephemeral_transparent_receivers(account.id(), u32::MAX, false)
        .unwrap()
        .into_keys()
        .next()
        .unwrap();
    let target = (height + 1).into();
    assert!(
        st.wallet()
            .get_spendable_transparent_outputs(
                &ephemeral,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .unwrap()
            .is_empty()
    );
    st.wallet_mut().abandon_transaction(child).unwrap();
    assert!(!abandoned(st.wallet().conn(), parent));
    let released = st
        .wallet()
        .get_spendable_transparent_outputs(
            &ephemeral,
            target,
            ConfirmationsPolicy::MIN,
            CoinbaseFilter::AllTransparentOutputs,
            LockFilter::Policy(&LockedInputPolicy::Exclude),
        )
        .unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].outpoint().hash().as_slice(), parent.as_ref());
    st.wallet_mut()
        .set_transaction_status(child, TransactionStatus::InMempool)
        .unwrap();
    assert!(
        st.wallet()
            .get_spendable_transparent_outputs(
                &ephemeral,
                target,
                ConfirmationsPolicy::MIN,
                CoinbaseFilter::AllTransparentOutputs,
                LockFilter::Policy(&LockedInputPolicy::Exclude),
            )
            .unwrap()
            .is_empty()
    );
}
