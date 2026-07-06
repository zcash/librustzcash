//! Import of wallets from ZeWIF (Zcash Wallet Interchange Format) documents.
//!
//! This module populates a [`WalletDb`] from a [`::zewif::Zewif`] document, importing
//! each account it can represent and diverting all spending key material to a
//! caller-provided [`SecretSink`]. Secret material is never stored in the wallet
//! database itself; the sink is expected to persist it in an application keystore
//! (for example, zallet's age-encrypted keystore).
//!
//! # Pipeline
//!
//! [`import_wallet`] performs the following steps, in order:
//!
//! 1. Verifies that every wallet in the document was recorded for the network the
//!    database's [`Parameters`] describe.
//! 2. Delivers every entry of the document's secret store to the [`SecretSink`],
//!    recording which seeds and spending keys are available so that account
//!    spendability can be determined.
//! 3. Imports each account: seed-derived accounts whose seed material is present are
//!    imported via HD derivation (preserving the recorded ZIP 32 account index);
//!    all others are imported from their viewing keys, as spending accounts when
//!    corresponding spending material was delivered to the sink and as view-only
//!    accounts otherwise. Account birthdays are constructed from the tree-state
//!    frontiers carried by the document where present.
//! 4. Registers standalone transparent keys: each transparent spending key in the
//!    secret store whose pay-to-public-key-hash address appears under an imported
//!    account is registered with that account (its secret half having already been
//!    delivered to the sink), and P2SH redeem scripts recorded on imported
//!    accounts' addresses are registered where the wallet can represent them.
//! 5. Marks the transparent addresses recorded in the document as exposed, so
//!    that address-based recovery includes them.
//! 6. Stores the document's transactions: each transaction carrying raw data is
//!    parsed and trial-decrypted against the imported accounts' viewing keys, and
//!    stored if it involves the wallet. Transactions that cannot be shown to
//!    involve the wallet are not stored (the post-import rescan recovers them if
//!    they do), and are counted in the report.
//!
//! The database must already have been initialized with
//! [`crate::wallet::init::WalletMigrator`] before calling [`import_wallet`].
//!
//! # Limitations
//!
//! * Sprout accounts and Sprout spending keys are not representable in the wallet
//!   database. Sprout spending keys are still delivered to the [`SecretSink`];
//!   Sprout accounts are skipped and recorded in the [`ZewifImportReport`].
//! * Address book entries have no backing store in this crate and are not
//!   imported; the caller retains the document and may preserve them elsewhere.
//! * Received-note spendability requires commitment tree positions, which only
//!   block scanning can establish. Importing an account seeds the scan queue from
//!   its birthday; the wallet's balance becomes visible and spendable as the
//!   post-import rescan progresses.
//! * Documents recorded against a regtest network are not currently supported,
//!   as the equivalence of regtest activation schedules cannot be verified here.
//! * Encrypted secret stores must be decrypted by the caller (using the `zewif`
//!   crate's decryption support) before import.

use std::collections::HashMap;
use std::fmt;

use bech32::primitives::decode::CheckedHrpstring;
use bip0039::{English, Mnemonic};
use rand::RngCore;
use secrecy::SecretVec;
use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation, chain::ChainState,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::block::BlockHash;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::consensus::{
    self, BlockHeight, NetworkConstants as _, NetworkType, NetworkUpgrade, Parameters,
};
use zip32::fingerprint::SeedFingerprint;

use ::transparent::address::TransparentAddress;
use zcash_keys::encoding::AddressCodec;

use crate::{AccountUuid, WalletDb, error::SqliteClientError, util::Clock};

/// The Bech32m human-readable part of the canonical ZIP 32 seed fingerprint
/// encoding used by ZeWIF documents.
const SEED_FP_HRP: &str = "zip32seedfp";

/// A destination for the spending key material carried by a ZeWIF document.
///
/// The wallet database stores only viewing keys and public metadata; all secret
/// material encountered during import is delivered to an implementation of this
/// trait, which is expected to persist it outside the wallet database (for
/// example, in an age-encrypted keystore such as zallet's). Implementations
/// should be idempotent with respect to re-delivery of the same entry.
pub trait SecretSink {
    /// The error type produced when the sink fails to persist an entry.
    type Error: std::error::Error;

    /// Persists seed material (a BIP 39 mnemonic or a legacy raw seed), keyed by
    /// its ZIP 32 seed fingerprint.
    fn store_seed(&mut self, entry: &::zewif::SeedEntry) -> Result<(), Self::Error>;

    /// Persists a transparent spending key (WIF-encoded), keyed by its public key.
    fn store_transparent_key(
        &mut self,
        entry: &::zewif::TransparentKeyEntry,
    ) -> Result<(), Self::Error>;

    /// Persists a Sapling extended spending key, keyed by the canonical encoding
    /// of its extended full viewing key.
    fn store_sapling_key(&mut self, entry: &::zewif::SaplingKeyEntry) -> Result<(), Self::Error>;

    /// Persists a Sprout spending key, keyed by its Sprout address. Sprout funds
    /// are not representable in the wallet database, so this is the only
    /// destination for Sprout key material.
    fn store_sprout_key(&mut self, entry: &::zewif::SproutKeyEntry) -> Result<(), Self::Error>;

    /// Persists an extracted unified spending key, keyed by the canonical
    /// encoding of its unified full viewing key.
    fn store_unified_key(&mut self, entry: &::zewif::UnifiedKeyEntry) -> Result<(), Self::Error>;
}

/// A [`SecretSink`] that discards all secret material.
///
/// Use this only for view-only imports where the document's secret material is
/// intentionally not being retained.
#[derive(Debug, Default, Clone, Copy)]
pub struct DiscardSecrets;

impl SecretSink for DiscardSecrets {
    type Error = core::convert::Infallible;

    fn store_seed(&mut self, _entry: &::zewif::SeedEntry) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_transparent_key(
        &mut self,
        _entry: &::zewif::TransparentKeyEntry,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_sapling_key(&mut self, _entry: &::zewif::SaplingKeyEntry) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_sprout_key(&mut self, _entry: &::zewif::SproutKeyEntry) -> Result<(), Self::Error> {
        Ok(())
    }

    fn store_unified_key(&mut self, _entry: &::zewif::UnifiedKeyEntry) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// The shielded pool to which an invalid tree frontier belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontierPool {
    /// The Sapling note commitment tree.
    Sapling,
    /// The Orchard note commitment tree.
    Orchard,
    /// The Ironwood note commitment tree.
    Ironwood,
}

impl fmt::Display for FrontierPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrontierPool::Sapling => write!(f, "Sapling"),
            FrontierPool::Orchard => write!(f, "Orchard"),
            FrontierPool::Ironwood => write!(f, "Ironwood"),
        }
    }
}

/// Errors that can occur while importing a ZeWIF document.
#[derive(Debug)]
pub enum ZewifImportError<S> {
    /// A wallet in the document was recorded for a different network than the one
    /// described by the database's [`Parameters`].
    NetworkMismatch {
        /// The network recorded in the document.
        document: ::zewif::Network,
        /// The network type of the database parameters.
        expected: NetworkType,
    },
    /// The document was recorded against a regtest network, which this importer
    /// does not currently support.
    UnsupportedRegtest,
    /// The document's secret store is encrypted; the caller must decrypt it (via
    /// the `zewif` crate's decryption support) before import.
    EncryptedSecrets,
    /// A unified full viewing key in the document could not be parsed.
    UfvkDecoding {
        /// The name of the account whose viewing key failed to parse.
        account_name: String,
        /// The parse failure diagnostic.
        message: String,
    },
    /// A Sapling extended full viewing key in the document could not be parsed.
    SaplingFvkDecoding {
        /// The name of the account whose viewing key failed to parse.
        account_name: String,
    },
    /// A seed fingerprint in the document is not a valid `zip32seedfp` Bech32m
    /// encoding.
    SeedFingerprintDecoding {
        /// The malformed fingerprint encoding.
        encoding: String,
    },
    /// Seed material in the document does not match the fingerprint under which
    /// it was recorded.
    SeedFingerprintMismatch {
        /// The fingerprint recorded in the document.
        claimed: String,
    },
    /// A BIP 39 mnemonic in the document could not be interpreted.
    InvalidMnemonic {
        /// The fingerprint of the seed entry containing the mnemonic.
        fingerprint: String,
        /// The underlying mnemonic decoding error.
        source: bip0039::Error,
    },
    /// Seed material has a length outside the range ZIP 32 permits (32 to 252
    /// bytes).
    InvalidSeedLength {
        /// The fingerprint of the offending seed entry.
        fingerprint: String,
    },
    /// A recorded ZIP 32 account index is outside the valid hardened range.
    InvalidAccountIndex {
        /// The name of the account with the invalid index.
        account_name: String,
        /// The recorded index.
        index: u32,
    },
    /// A recorded zcashd legacy address index is outside the valid range.
    InvalidLegacyAddressIndex {
        /// The name of the account with the invalid index.
        account_name: String,
        /// The recorded index.
        index: u32,
    },
    /// A hash in a note commitment tree frontier is not a valid node for its
    /// pool.
    InvalidMerkleNode {
        /// The name of the account whose birthday contains the invalid node.
        account_name: String,
        /// The pool whose frontier contains the invalid node.
        pool: FrontierPool,
    },
    /// A note commitment tree frontier in an account birthday is structurally
    /// invalid.
    InvalidFrontier {
        /// The name of the account whose birthday contains the invalid frontier.
        account_name: String,
        /// The pool whose frontier is invalid.
        pool: FrontierPool,
        /// The underlying structural error.
        source: incrementalmerkletree::frontier::FrontierError,
    },
    /// A transparent public key in the document's secret store is not a valid
    /// secp256k1 point.
    InvalidTransparentPubKey {
        /// The underlying secp256k1 error.
        source: secp256k1::Error,
    },
    /// A transparent spending key in the document's secret store is not a valid
    /// WIF encoding for the document's network.
    InvalidTransparentKeyEncoding {
        /// The pay-to-public-key-hash address of the entry's public key.
        address: String,
    },
    /// A transparent spending key in the document's secret store does not
    /// correspond to the public key under which it was recorded.
    TransparentKeyMismatch {
        /// The pay-to-public-key-hash address of the entry's public key.
        address: String,
    },
    /// The raw bytes of a transaction in the document could not be parsed as a
    /// Zcash transaction.
    TransactionParse {
        /// The id of the unparseable transaction, as recorded in the document.
        txid: zcash_protocol::TxId,
        /// The underlying parse error.
        source: std::io::Error,
    },
    /// The raw bytes of a transaction in the document parse to a transaction
    /// with a different id than the one under which they were recorded.
    TxidMismatch {
        /// The id under which the transaction was recorded.
        recorded: zcash_protocol::TxId,
        /// The id of the transaction the recorded bytes parse to.
        parsed: zcash_protocol::TxId,
    },
    /// An error occurred writing to the wallet database.
    Wallet(SqliteClientError),
    /// The [`SecretSink`] failed to persist an entry.
    Sink(S),
}

impl<S: fmt::Display> fmt::Display for ZewifImportError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZewifImportError::NetworkMismatch { document, expected } => write!(
                f,
                "Document was recorded for network {document:?}, but the wallet database is for {expected:?}."
            ),
            ZewifImportError::UnsupportedRegtest => write!(
                f,
                "Documents recorded against regtest networks are not currently supported."
            ),
            ZewifImportError::EncryptedSecrets => write!(
                f,
                "The document's secret store is encrypted; decrypt it before import."
            ),
            ZewifImportError::UfvkDecoding {
                account_name,
                message,
            } => write!(
                f,
                "Unable to parse the unified full viewing key of account \"{account_name}\": {message}"
            ),
            ZewifImportError::SaplingFvkDecoding { account_name } => write!(
                f,
                "Unable to parse the Sapling extended full viewing key of account \"{account_name}\"."
            ),
            ZewifImportError::SeedFingerprintDecoding { encoding } => write!(
                f,
                "\"{encoding}\" is not a valid zip32seedfp Bech32m seed fingerprint encoding."
            ),
            ZewifImportError::SeedFingerprintMismatch { claimed } => write!(
                f,
                "Seed material does not match the fingerprint {claimed} under which it was recorded."
            ),
            ZewifImportError::InvalidMnemonic {
                fingerprint,
                source,
            } => write!(
                f,
                "The mnemonic recorded under seed fingerprint {fingerprint} is invalid: {source}"
            ),
            ZewifImportError::InvalidSeedLength { fingerprint } => write!(
                f,
                "The seed recorded under fingerprint {fingerprint} has a length outside the range ZIP 32 permits."
            ),
            ZewifImportError::InvalidAccountIndex {
                account_name,
                index,
            } => write!(
                f,
                "Account \"{account_name}\" records ZIP 32 account index {index}, which is outside the valid range."
            ),
            ZewifImportError::InvalidLegacyAddressIndex {
                account_name,
                index,
            } => write!(
                f,
                "Account \"{account_name}\" records legacy address index {index}, which is outside the valid range."
            ),
            ZewifImportError::InvalidMerkleNode { account_name, pool } => write!(
                f,
                "The {pool} tree frontier in the birthday of account \"{account_name}\" contains an invalid node hash."
            ),
            ZewifImportError::InvalidFrontier {
                account_name,
                pool,
                source,
            } => write!(
                f,
                "The {pool} tree frontier in the birthday of account \"{account_name}\" is invalid: {source:?}"
            ),
            ZewifImportError::InvalidTransparentPubKey { source } => write!(
                f,
                "A transparent public key in the secret store is not a valid secp256k1 point: {source}"
            ),
            ZewifImportError::InvalidTransparentKeyEncoding { address } => write!(
                f,
                "The transparent spending key recorded for {address} is not a valid WIF encoding for the document's network."
            ),
            ZewifImportError::TransparentKeyMismatch { address } => write!(
                f,
                "The transparent spending key recorded for {address} does not correspond to its recorded public key."
            ),
            ZewifImportError::TransactionParse { txid, source } => write!(
                f,
                "Unable to parse the raw data of transaction {txid}: {source}"
            ),
            ZewifImportError::TxidMismatch { recorded, parsed } => write!(
                f,
                "The raw data recorded for transaction {recorded} parses to a transaction with id {parsed}."
            ),
            ZewifImportError::Wallet(e) => write!(f, "Wallet database error: {e}"),
            ZewifImportError::Sink(e) => write!(f, "Secret sink error: {e}"),
        }
    }
}

impl<S: std::error::Error + 'static> std::error::Error for ZewifImportError<S> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ZewifImportError::InvalidMnemonic { source, .. } => Some(source),
            ZewifImportError::InvalidTransparentPubKey { source } => Some(source),
            ZewifImportError::TransactionParse { source, .. } => Some(source),
            ZewifImportError::Wallet(e) => Some(e),
            ZewifImportError::Sink(e) => Some(e),
            _ => None,
        }
    }
}

impl<S> From<SqliteClientError> for ZewifImportError<S> {
    fn from(e: SqliteClientError) -> Self {
        ZewifImportError::Wallet(e)
    }
}

/// The reason an account in a ZeWIF document was not imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountSkipReason {
    /// The account's viewing capability is a Sprout viewing key; the Sprout pool
    /// is not representable in the wallet database.
    SproutViewingKey,
    /// The account is a bare set of transparent addresses with no unified key
    /// structure, and no seed material was available from which its contents
    /// could be re-derived.
    TransparentAddressSetWithoutSeed,
}

/// How the birthday of an imported account was determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BirthdayBasis {
    /// The document carried the tree state prior to the account's birthday
    /// height; the birthday is fully precise.
    ChainState,
    /// The document carried only a birthday height; scanning will begin there,
    /// but the note commitment trees must be rebuilt by scanning.
    BirthdayHeight,
    /// The document carried no birthday information; scanning will begin at
    /// Sapling activation to guarantee no account history is missed.
    SaplingActivation,
}

/// An account that was successfully imported.
#[derive(Debug, Clone)]
pub struct ImportedAccount {
    /// The name of the account in the document.
    pub name: String,
    /// The identifier of the newly created wallet database account.
    pub account_uuid: AccountUuid,
    /// How the account's birthday was determined.
    pub birthday_basis: BirthdayBasis,
}

/// An account that could not be imported.
#[derive(Debug, Clone)]
pub struct SkippedAccount {
    /// The name of the account in the document.
    pub name: String,
    /// Why the account was not imported.
    pub reason: AccountSkipReason,
}

/// The reason a transparent spending key in the document's secret store was
/// not registered with the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentKeySkipReason {
    /// The recorded public key is uncompressed; the wallet derives addresses
    /// only from compressed public keys.
    UncompressedPubKey,
    /// The key's pay-to-public-key-hash address does not appear under any
    /// imported account, so there is no account to register it with.
    NoOwningAccount,
}

/// A transparent spending key that was delivered to the [`SecretSink`] but
/// could not be registered with the wallet.
#[derive(Debug, Clone)]
pub struct SkippedTransparentKey {
    /// The pay-to-public-key-hash address of the key, where derivable; `None`
    /// for uncompressed public keys.
    pub address: Option<String>,
    /// Why the key was not registered.
    pub reason: TransparentKeySkipReason,
}

/// A summary of the effects of a ZeWIF document import.
#[derive(Debug, Clone, Default)]
pub struct ZewifImportReport {
    /// The accounts that were imported, in document order.
    pub imported_accounts: Vec<ImportedAccount>,
    /// The accounts that could not be imported.
    pub skipped_accounts: Vec<SkippedAccount>,
    /// The number of standalone transparent spending keys registered with
    /// imported accounts.
    pub transparent_keys_registered: usize,
    /// Transparent spending keys that were delivered to the [`SecretSink`] but
    /// could not be registered with the wallet.
    pub skipped_transparent_keys: Vec<SkippedTransparentKey>,
    /// The number of P2SH redeem scripts registered with imported accounts.
    pub redeem_scripts_registered: usize,
    /// The number of P2SH redeem scripts recorded in the document that the
    /// wallet cannot represent (for example, non-multisig scripts).
    pub redeem_scripts_not_representable: usize,
    /// The number of transparent addresses marked as exposed.
    pub addresses_marked_exposed: usize,
    /// The number of transparent addresses recorded in the document that the
    /// wallet does not recognize as receivers of any imported account, and so
    /// could not be marked as exposed.
    pub addresses_not_recognized: usize,
    /// The number of transactions from the document that were stored because
    /// they involve the imported accounts.
    pub transactions_stored: usize,
    /// The number of transactions from the document that were not stored
    /// because trial decryption found no involvement with any imported
    /// account. Such transactions are expected to be recovered by the
    /// post-import rescan if they do in fact involve the wallet.
    pub transactions_without_wallet_relevance: usize,
    /// The number of transactions in the document that carried no raw
    /// transaction data and therefore could not be stored.
    pub transactions_without_raw_data: usize,
    /// The number of address book entries present in the document. Address
    /// books have no backing store in this crate; the caller retains the
    /// document and may preserve these entries elsewhere.
    pub address_book_entries_not_imported: usize,
}

/// The secret material available for driving account import, indexed by the
/// public identifiers accounts use to reference it.
struct AvailableSecrets {
    /// Seed bytes ready for ZIP 32 derivation, keyed by the canonical Bech32m
    /// encoding of their verified seed fingerprints.
    seeds: HashMap<String, SecretVec<u8>>,
    /// The canonical encodings of Sapling extended full viewing keys whose
    /// spending keys were delivered to the sink.
    sapling_fvks: Vec<String>,
    /// The canonical encodings of unified full viewing keys whose spending keys
    /// were delivered to the sink.
    unified_fvks: Vec<String>,
}

impl AvailableSecrets {
    fn empty() -> Self {
        AvailableSecrets {
            seeds: HashMap::new(),
            sapling_fvks: vec![],
            unified_fvks: vec![],
        }
    }
}

/// Decodes a canonical `zip32seedfp` Bech32m seed fingerprint encoding.
fn decode_seed_fingerprint<S>(encoding: &str) -> Result<SeedFingerprint, ZewifImportError<S>> {
    let err = || ZewifImportError::SeedFingerprintDecoding {
        encoding: encoding.to_owned(),
    };
    let checked = CheckedHrpstring::new::<bech32::Bech32m>(encoding).map_err(|_| err())?;
    if checked.hrp().as_str() != SEED_FP_HRP {
        return Err(err());
    }
    let bytes = checked.byte_iter().collect::<Vec<_>>();
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| err())?;
    Ok(SeedFingerprint::from_bytes(bytes))
}

/// Converts the seed material of a document seed entry into the byte form used
/// for ZIP 32 derivation, verifying it against the fingerprint under which it
/// was recorded.
fn seed_entry_bytes<S>(entry: &::zewif::SeedEntry) -> Result<SecretVec<u8>, ZewifImportError<S>> {
    let claimed_encoding = entry.fingerprint().encoding();
    let claimed = decode_seed_fingerprint(claimed_encoding)?;
    let seed_bytes: Vec<u8> = match entry.material() {
        ::zewif::SeedMaterial::Bip39Mnemonic(m) => {
            mnemonic_to_seed(m).map_err(|source| ZewifImportError::InvalidMnemonic {
                fingerprint: claimed_encoding.to_owned(),
                source,
            })?
        }
        ::zewif::SeedMaterial::LegacySeed(seed) => seed.as_bytes().to_vec(),
    };
    let computed =
        SeedFingerprint::from_seed(&seed_bytes).ok_or(ZewifImportError::InvalidSeedLength {
            fingerprint: claimed_encoding.to_owned(),
        })?;
    if computed.to_bytes() != claimed.to_bytes() {
        return Err(ZewifImportError::SeedFingerprintMismatch {
            claimed: claimed_encoding.to_owned(),
        });
    }
    Ok(SecretVec::new(seed_bytes))
}

/// Converts a BIP 39 mnemonic to its 64-byte seed, using the empty passphrase
/// (as zcashd and zallet do).
fn mnemonic_to_seed(m: &::zewif::Bip39Mnemonic) -> Result<Vec<u8>, bip0039::Error> {
    use ::zewif::MnemonicLanguage as L;
    use bip0039::{
        ChineseSimplified, ChineseTraditional, Czech, French, Italian, Japanese, Korean,
        Portuguese, Spanish,
    };

    fn seed<L: bip0039::Language>(phrase: &str) -> Result<Vec<u8>, bip0039::Error> {
        Ok(Mnemonic::<L>::from_phrase(phrase)?.to_seed("").to_vec())
    }

    let phrase = m.mnemonic().as_str();
    match m.language() {
        None | Some(L::English) => seed::<English>(phrase),
        Some(L::SimplifiedChinese) => seed::<ChineseSimplified>(phrase),
        Some(L::TraditionalChinese) => seed::<ChineseTraditional>(phrase),
        Some(L::Czech) => seed::<Czech>(phrase),
        Some(L::French) => seed::<French>(phrase),
        Some(L::Italian) => seed::<Italian>(phrase),
        Some(L::Japanese) => seed::<Japanese>(phrase),
        Some(L::Korean) => seed::<Korean>(phrase),
        Some(L::Portuguese) => seed::<Portuguese>(phrase),
        Some(L::Spanish) => seed::<Spanish>(phrase),
        // An unrecognized language tag means the phrase cannot be interpreted
        // as any known wordlist.
        Some(L::Other(_)) => Err(bip0039::Error::BadWordCount(0)),
    }
}

/// Converts a zewif tree frontier into an incrementalmerkletree frontier over
/// the given node type.
fn convert_frontier<H, S, const DEPTH: u8>(
    account_name: &str,
    pool: FrontierPool,
    frontier: Option<&::zewif::Frontier>,
    read_node: impl Fn(&::zewif::MerkleNode) -> Option<H>,
) -> Result<incrementalmerkletree::frontier::Frontier<H, DEPTH>, ZewifImportError<S>>
where
    H: Clone,
{
    use incrementalmerkletree::frontier::Frontier;
    let invalid_node = || ZewifImportError::InvalidMerkleNode {
        account_name: account_name.to_owned(),
        pool,
    };
    match frontier {
        None | Some(::zewif::Frontier::Empty) => Ok(Frontier::empty()),
        Some(::zewif::Frontier::NonEmpty(data)) => {
            let leaf = read_node(data.leaf()).ok_or_else(invalid_node)?;
            let ommers = data
                .ommers()
                .iter()
                .map(&read_node)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(invalid_node)?;
            Frontier::from_parts(
                incrementalmerkletree::Position::from(data.position()),
                leaf,
                ommers,
            )
            .map_err(|source| ZewifImportError::InvalidFrontier {
                account_name: account_name.to_owned(),
                pool,
                source,
            })
        }
    }
}

/// Constructs an [`AccountBirthday`] for an account from the birthday
/// information carried by the document.
fn account_birthday<P: Parameters, S>(
    params: &P,
    account: &::zewif::Account,
) -> Result<(AccountBirthday, BirthdayBasis), ZewifImportError<S>> {
    let zewif_block_hash =
        |h: Option<::zewif::BlockHash>| h.map_or(BlockHash([0; 32]), |h| BlockHash(*h.as_bytes()));

    if let Some(cs) = account.birthday_chain_state() {
        let sapling = convert_frontier(
            account.name(),
            FrontierPool::Sapling,
            cs.sapling_tree(),
            |n| {
                let repr = *n.as_bytes();
                Option::from(::sapling::Node::from_bytes(repr))
            },
        )?;
        let orchard = convert_frontier(
            account.name(),
            FrontierPool::Orchard,
            cs.orchard_tree(),
            |n| Option::from(orchard::tree::MerkleHashOrchard::from_bytes(n.as_bytes())),
        )?;
        let ironwood = convert_frontier(
            account.name(),
            FrontierPool::Ironwood,
            cs.ironwood_tree(),
            |n| Option::from(orchard::tree::MerkleHashOrchard::from_bytes(n.as_bytes())),
        )?;
        let chain_state = ChainState::new(
            BlockHeight::from(u32::from(cs.height())),
            zewif_block_hash(cs.block_hash()),
            sapling,
            orchard,
            ironwood,
        );
        Ok((
            AccountBirthday::from_parts(
                chain_state,
                account
                    .recover_until_height()
                    .map(|h| BlockHeight::from(u32::from(h))),
            ),
            BirthdayBasis::ChainState,
        ))
    } else {
        // Without a recorded tree state, we can only choose the height at which
        // scanning begins; the note commitment trees will be rebuilt by the
        // scan itself.
        let (prior_height, basis) = match account.birthday_height() {
            Some(h) => (
                BlockHeight::from(u32::from(h)).saturating_sub(1),
                BirthdayBasis::BirthdayHeight,
            ),
            None => {
                // With no birthday information at all, scan from Sapling
                // activation so that no account history can be missed.
                let sapling_activation = params
                    .activation_height(NetworkUpgrade::Sapling)
                    .unwrap_or_else(|| BlockHeight::from(0));
                (
                    sapling_activation.saturating_sub(1),
                    BirthdayBasis::SaplingActivation,
                )
            }
        };
        Ok((
            AccountBirthday::from_parts(
                ChainState::empty(prior_height, BlockHash([0; 32])),
                account
                    .recover_until_height()
                    .map(|h| BlockHeight::from(u32::from(h))),
            ),
            basis,
        ))
    }
}

/// Delivers the document's secret store to the sink and indexes the material
/// that account import can make use of.
fn deliver_secrets<S: SecretSink>(
    document: &::zewif::Zewif,
) -> Result<Option<&::zewif::SecretStore>, ZewifImportError<S::Error>> {
    match document.secrets() {
        None => Ok(None),
        Some(::zewif::Secrets::Plain(store)) => Ok(Some(store)),
        Some(::zewif::Secrets::Encrypted(_)) => Err(ZewifImportError::EncryptedSecrets),
    }
}

/// Constructs the ZIP 32 derivation metadata recorded by a derived key source.
fn zip32_derivation<S>(
    account_name: &str,
    source: &::zewif::DerivedKeySource,
) -> Result<Zip32Derivation, ZewifImportError<S>> {
    let seed_fp = decode_seed_fingerprint(source.seed_fingerprint().encoding())?;
    let account_index = zip32::AccountId::try_from(source.account_index()).map_err(|_| {
        ZewifImportError::InvalidAccountIndex {
            account_name: account_name.to_owned(),
            index: source.account_index(),
        }
    })?;
    let legacy_address_index = source
        .legacy_address_index()
        .map(|i| {
            zcash_keys::keys::zcashd::LegacyAddressIndex::try_from(i).map_err(|_| {
                ZewifImportError::InvalidLegacyAddressIndex {
                    account_name: account_name.to_owned(),
                    index: i,
                }
            })
        })
        .transpose()?;
    Ok(Zip32Derivation::new(
        seed_fp,
        account_index,
        legacy_address_index,
    ))
}

/// Imports the contents of a ZeWIF document into the wallet database.
///
/// The database must already have been initialized (or migrated to the current
/// schema) with [`crate::wallet::init::WalletMigrator`]. All spending key
/// material carried by the document is delivered to `sink` and is not stored in
/// the wallet database; see [`SecretSink`].
///
/// Returns a report describing the accounts imported and any items that could
/// not be represented.
pub fn import_wallet<C, P, CL, R, S>(
    wdb: &mut WalletDb<C, P, CL, R>,
    document: &::zewif::Zewif,
    sink: &mut S,
) -> Result<ZewifImportReport, ZewifImportError<S::Error>>
where
    C: std::borrow::BorrowMut<rusqlite::Connection>,
    P: consensus::Parameters,
    CL: Clock,
    R: RngCore,
    S: SecretSink,
{
    let params = wdb.params().clone();
    let expected = params.network_type();

    // Verify that every wallet in the document belongs to the expected network.
    for wallet in document.wallets() {
        match (wallet.network(), expected) {
            (::zewif::Network::Mainnet, NetworkType::Main) => {}
            (::zewif::Network::Testnet, NetworkType::Test) => {}
            (::zewif::Network::Regtest(_), _) => {
                return Err(ZewifImportError::UnsupportedRegtest);
            }
            (document_network, _) => {
                return Err(ZewifImportError::NetworkMismatch {
                    document: document_network.clone(),
                    expected,
                });
            }
        }
    }

    // Deliver all secret material to the sink, indexing what account import can
    // use.
    let mut available = AvailableSecrets::empty();
    if let Some(store) = deliver_secrets::<S>(document)? {
        for entry in store.seeds() {
            sink.store_seed(entry).map_err(ZewifImportError::Sink)?;
            let seed_bytes = seed_entry_bytes(entry)?;
            // The fingerprint encoding was verified against the material by
            // `seed_entry_bytes`, so account key sources can match it by
            // string equality.
            available
                .seeds
                .insert(entry.fingerprint().encoding().to_owned(), seed_bytes);
        }
        for entry in store.transparent_keys() {
            sink.store_transparent_key(entry)
                .map_err(ZewifImportError::Sink)?;
        }
        for entry in store.sapling_keys() {
            sink.store_sapling_key(entry)
                .map_err(ZewifImportError::Sink)?;
            available
                .sapling_fvks
                .push(entry.fvk().encoding().to_owned());
        }
        for entry in store.sprout_keys() {
            sink.store_sprout_key(entry)
                .map_err(ZewifImportError::Sink)?;
        }
        for entry in store.unified_keys() {
            sink.store_unified_key(entry)
                .map_err(ZewifImportError::Sink)?;
            available
                .unified_fvks
                .push(entry.fvk().encoding().to_owned());
        }
    }

    let mut report = ZewifImportReport::default();
    let mut taddrs = TransparentAddressRecords::default();

    for wallet in document.wallets() {
        report.address_book_entries_not_imported += wallet.address_book().len();

        for account in wallet.accounts() {
            import_account(wdb, &params, account, &available, &mut taddrs, &mut report)?;
        }
    }

    register_transparent_keys(
        wdb,
        &params,
        deliver_secrets::<S>(document)?,
        &taddrs,
        &mut report,
    )?;
    mark_addresses_exposed(wdb, &params, &taddrs, &mut report)?;

    import_transactions(wdb, &params, document, &mut report)?;

    Ok(report)
}

/// The transparent addresses recorded under imported accounts, indexed for
/// standalone key registration and exposure marking.
#[derive(Default)]
struct TransparentAddressRecords {
    /// Maps each transparent address string to the account that recorded it
    /// and the height at which it is known to have been exposed.
    owners: HashMap<String, (AccountUuid, BlockHeight)>,
    /// The P2SH redeem scripts recorded on imported accounts' addresses.
    redeem_scripts: Vec<(AccountUuid, Vec<u8>)>,
}

/// Decodes a WIF-encoded transparent spending key, returning the secret key
/// and whether the corresponding public key uses the compressed encoding.
fn decode_wif(expected_prefix: u8, wif: &str) -> Option<(secp256k1::SecretKey, bool)> {
    let payload = bs58::decode(wif).with_check(None).into_vec().ok()?;
    match payload.as_slice() {
        [prefix, key_data @ ..] if *prefix == expected_prefix && key_data.len() == 32 => {
            Some((secp256k1::SecretKey::from_slice(key_data).ok()?, false))
        }
        [prefix, key_data @ .., 0x01] if *prefix == expected_prefix && key_data.len() == 32 => {
            Some((secp256k1::SecretKey::from_slice(key_data).ok()?, true))
        }
        _ => None,
    }
}

/// Registers the secret store's standalone transparent spending keys with the
/// accounts that record their addresses, and the recorded P2SH redeem scripts
/// with the accounts that carry them.
fn register_transparent_keys<C, P, CL, R, S>(
    wdb: &mut WalletDb<C, P, CL, R>,
    params: &P,
    store: Option<&::zewif::SecretStore>,
    taddrs: &TransparentAddressRecords,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    C: std::borrow::BorrowMut<rusqlite::Connection>,
    P: consensus::Parameters,
    CL: Clock,
    R: RngCore,
    S: std::error::Error,
{
    let wif_prefix = match params.network_type() {
        NetworkType::Main => 0x80,
        NetworkType::Test | NetworkType::Regtest => 0xEF,
    };
    let secp = secp256k1::Secp256k1::new();

    for entry in store.map_or(&[][..], |s| s.transparent_keys()) {
        if !entry.pubkey().is_compressed() {
            report.skipped_transparent_keys.push(SkippedTransparentKey {
                address: None,
                reason: TransparentKeySkipReason::UncompressedPubKey,
            });
            continue;
        }
        let pubkey = secp256k1::PublicKey::from_slice(entry.pubkey().as_slice())
            .map_err(|source| ZewifImportError::InvalidTransparentPubKey { source })?;
        let address = TransparentAddress::from_pubkey(&pubkey).encode(params);

        // Verify that the spending key corresponds to the recorded public key.
        let (secret_key, _compressed) = decode_wif(wif_prefix, entry.spending_key().encoding())
            .ok_or_else(|| ZewifImportError::InvalidTransparentKeyEncoding {
                address: address.clone(),
            })?;
        if secret_key.public_key(&secp) != pubkey {
            return Err(ZewifImportError::TransparentKeyMismatch { address });
        }

        match taddrs.owners.get(&address) {
            Some((account_uuid, _)) => {
                wdb.import_standalone_transparent_pubkey(*account_uuid, pubkey)
                    .map_err(ZewifImportError::Wallet)?;
                report.transparent_keys_registered += 1;
            }
            None => {
                report.skipped_transparent_keys.push(SkippedTransparentKey {
                    address: Some(address),
                    reason: TransparentKeySkipReason::NoOwningAccount,
                });
            }
        }
    }

    for (account_uuid, script_bytes) in &taddrs.redeem_scripts {
        use zcash_script::script::{Code, Redeem};
        let parsed = Redeem::parse(&Code(script_bytes.clone()));
        match parsed {
            Ok(redeem) => {
                match wdb.import_standalone_transparent_script(*account_uuid, redeem) {
                    Ok(()) => report.redeem_scripts_registered += 1,
                    // The wallet can only represent a subset of redeem scripts
                    // (e.g. multisig within the P2SH size limit); scripts it
                    // rejects remain recoverable from the document.
                    Err(SqliteClientError::BadAccountData(_)) => {
                        report.redeem_scripts_not_representable += 1;
                    }
                    Err(e) => return Err(ZewifImportError::Wallet(e)),
                }
            }
            Err(_) => {
                report.redeem_scripts_not_representable += 1;
            }
        }
    }

    Ok(())
}

/// Marks the transparent addresses recorded in the document as exposed, so
/// that address-based recovery includes them.
///
/// Only addresses the wallet recognizes as receivers of an imported account
/// can be marked; unrecognized addresses are counted in the report.
fn mark_addresses_exposed<C, P, CL, R, S>(
    wdb: &mut WalletDb<C, P, CL, R>,
    params: &P,
    taddrs: &TransparentAddressRecords,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    C: std::borrow::BorrowMut<rusqlite::Connection>,
    P: consensus::Parameters,
    CL: Clock,
    R: RngCore,
    S: std::error::Error,
{
    use zcash_client_backend::data_api::WalletRead;

    // The upstream API rejects the entire batch if any address is not a known
    // receiver, so restrict the batch to the receivers the wallet recognizes.
    let mut known = std::collections::HashSet::new();
    let accounts: std::collections::HashSet<AccountUuid> =
        taddrs.owners.values().map(|(uuid, _)| *uuid).collect();
    for account_uuid in accounts {
        known.extend(
            wdb.get_transparent_receivers(account_uuid, true, true)
                .map_err(ZewifImportError::Wallet)?
                .into_keys(),
        );
    }

    let mut exposures: Vec<(TransparentAddress, BlockHeight)> = vec![];
    for (address_str, (_, exposure_height)) in &taddrs.owners {
        match TransparentAddress::decode(params, address_str) {
            Ok(taddr) if known.contains(&taddr) => {
                exposures.push((taddr, *exposure_height));
            }
            _ => {
                report.addresses_not_recognized += 1;
            }
        }
    }
    exposures.sort();

    if !exposures.is_empty() {
        wdb.mark_transparent_addresses_exposed(&exposures)
            .map_err(ZewifImportError::Wallet)?;
    }
    report.addresses_marked_exposed = exposures.len();

    Ok(())
}

/// Stores the document's transactions in the wallet database.
///
/// Transactions are processed in ascending order of mined height (unmined
/// transactions last) so that funding transactions generally precede the
/// transactions that spend them. Each transaction carrying raw data is parsed
/// under the consensus branch in force at its mined height (or, for unmined
/// transactions, at its expiry height when known, and otherwise at a height
/// just past the highest mined height in the document, falling back to the
/// document's export height), verified against its recorded transaction id,
/// and trial-decrypted against the wallet's tracked viewing keys.
///
/// [`decrypt_and_store_transaction`] stores a transaction only when trial
/// decryption or transparent-output matching shows wallet involvement, so the
/// count of stored transactions is determined by querying for each transaction
/// id after the attempt.
fn import_transactions<C, P, CL, R, S>(
    wdb: &mut WalletDb<C, P, CL, R>,
    params: &P,
    document: &::zewif::Zewif,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    C: std::borrow::BorrowMut<rusqlite::Connection>,
    P: consensus::Parameters,
    CL: Clock,
    R: RngCore,
    S: std::error::Error,
{
    let mut txs: Vec<&::zewif::Transaction> = document.transactions().values().collect();
    txs.sort_by_key(|tx| {
        (
            tx.mined_height().map_or(u32::MAX, u32::from),
            *tx.txid().as_bytes(),
        )
    });

    // The height at which a transaction of unknown mined height is assumed to
    // have entered the mempool, for consensus branch id selection.
    let assumed_mempool_height = txs
        .iter()
        .filter_map(|tx| tx.mined_height())
        .max()
        .map_or(document.export_height(), |h| h + 1);

    for tx in txs {
        let raw = match tx.tx_data() {
            Some(::zewif::TransactionData::Raw(raw)) => raw.data(),
            // Compact transaction data does not contain the full transaction,
            // so it cannot be stored; the post-import rescan will recover the
            // transaction if it involves the wallet.
            Some(::zewif::TransactionData::Compact(_)) | None => {
                report.transactions_without_raw_data += 1;
                continue;
            }
        };
        let recorded_txid = zcash_protocol::TxId::from_bytes(*tx.txid().as_bytes());
        let mined_height = tx.mined_height().map(|h| BlockHeight::from(u32::from(h)));
        let branch_height = mined_height.unwrap_or_else(|| {
            BlockHeight::from(u32::from(
                tx.expiry_height()
                    .filter(|h| u32::from(*h) != 0)
                    .unwrap_or(assumed_mempool_height),
            ))
        });
        let parsed = Transaction::read(raw.as_slice(), BranchId::for_height(params, branch_height))
            .map_err(|source| ZewifImportError::TransactionParse {
                txid: recorded_txid,
                source,
            })?;
        if parsed.txid() != recorded_txid {
            return Err(ZewifImportError::TxidMismatch {
                recorded: recorded_txid,
                parsed: parsed.txid(),
            });
        }

        decrypt_and_store_transaction(params, wdb, &parsed, mined_height)
            .map_err(ZewifImportError::Wallet)?;

        let stored = wdb
            .conn
            .borrow()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM transactions WHERE txid = :txid)",
                rusqlite::named_params![":txid": recorded_txid.as_ref()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|e| ZewifImportError::Wallet(SqliteClientError::from(e)))?;
        if stored {
            report.transactions_stored += 1;
        } else {
            report.transactions_without_wallet_relevance += 1;
        }
    }

    Ok(())
}

/// Imports a single account, choosing the import path appropriate to its
/// viewing capability and available secret material.
fn import_account<C, P, CL, R, S>(
    wdb: &mut WalletDb<C, P, CL, R>,
    params: &P,
    account: &::zewif::Account,
    available: &AvailableSecrets,
    taddrs: &mut TransparentAddressRecords,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    C: std::borrow::BorrowMut<rusqlite::Connection>,
    P: consensus::Parameters,
    CL: Clock,
    R: RngCore,
    S: std::error::Error,
{
    let (birthday, birthday_basis) = account_birthday(params, account)?;
    let key_source = account.provenance().or(Some("zewif"));

    // The seed bytes available for this account, when its key source records a
    // ZIP 32 derivation from a seed present in the document's secret store.
    let derived_source = match account.key_source() {
        Some(::zewif::KeySource::Derived(d)) => Some(d),
        _ => None,
    };
    let available_seed = derived_source
        .and_then(|d| available.seeds.get(d.seed_fingerprint().encoding()))
        .map(|seed| (seed, derived_source.expect("checked above")));

    let account_uuid = match account.viewing_key() {
        ::zewif::AccountViewingKey::Ufvk(ufvk) => {
            if let Some((seed, source)) = available_seed {
                // Re-derive the account from its seed, preserving the recorded
                // ZIP 32 account index.
                let account_index =
                    zip32::AccountId::try_from(source.account_index()).map_err(|_| {
                        ZewifImportError::InvalidAccountIndex {
                            account_name: account.name().to_owned(),
                            index: source.account_index(),
                        }
                    })?;
                let (imported, _usk) = wdb
                    .import_account_hd(account.name(), seed, account_index, &birthday, key_source)
                    .map_err(ZewifImportError::Wallet)?;
                imported.id()
            } else {
                let decoded =
                    UnifiedFullViewingKey::decode(params, ufvk.encoding()).map_err(|message| {
                        ZewifImportError::UfvkDecoding {
                            account_name: account.name().to_owned(),
                            message,
                        }
                    })?;
                let purpose = account_purpose(
                    account,
                    available.unified_fvks.iter().any(|s| s == ufvk.encoding()),
                    derived_source,
                )?;
                let imported = wdb
                    .import_account_ufvk(account.name(), &decoded, &birthday, purpose, key_source)
                    .map_err(ZewifImportError::Wallet)?;
                imported.id()
            }
        }
        ::zewif::AccountViewingKey::SaplingExtFvk(efvk) => {
            let decoded = zcash_keys::encoding::decode_extended_full_viewing_key(
                params
                    .network_type()
                    .hrp_sapling_extended_full_viewing_key(),
                efvk.encoding(),
            )
            .map_err(|_| ZewifImportError::SaplingFvkDecoding {
                account_name: account.name().to_owned(),
            })?;
            let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(decoded)
                .map_err(|e| ZewifImportError::UfvkDecoding {
                    account_name: account.name().to_owned(),
                    message: e.to_string(),
                })?;
            let purpose = account_purpose(
                account,
                available.sapling_fvks.iter().any(|s| s == efvk.encoding()),
                derived_source,
            )?;
            let imported = wdb
                .import_account_ufvk(account.name(), &ufvk, &birthday, purpose, key_source)
                .map_err(ZewifImportError::Wallet)?;
            imported.id()
        }
        ::zewif::AccountViewingKey::SproutViewingKey(_) => {
            report.skipped_accounts.push(SkippedAccount {
                name: account.name().to_owned(),
                reason: AccountSkipReason::SproutViewingKey,
            });
            return Ok(());
        }
        ::zewif::AccountViewingKey::TransparentAddressSet => {
            if let Some((seed, source)) = available_seed {
                // A transparent-only account (e.g. the zcashd legacy account)
                // whose contents can be re-derived from its seed.
                let account_index =
                    zip32::AccountId::try_from(source.account_index()).map_err(|_| {
                        ZewifImportError::InvalidAccountIndex {
                            account_name: account.name().to_owned(),
                            index: source.account_index(),
                        }
                    })?;
                let (imported, _usk) = wdb
                    .import_account_hd(account.name(), seed, account_index, &birthday, key_source)
                    .map_err(ZewifImportError::Wallet)?;
                imported.id()
            } else {
                report.skipped_accounts.push(SkippedAccount {
                    name: account.name().to_owned(),
                    reason: AccountSkipReason::TransparentAddressSetWithoutSeed,
                });
                return Ok(());
            }
        }
    };

    // Record the account's transparent addresses for standalone key
    // registration and exposure marking.
    for address in account.addresses() {
        if let ::zewif::ProtocolAddress::Transparent(taddr) = address.address() {
            let exposure_height = address
                .exposed_at_height()
                .map_or(birthday.height(), |h| BlockHeight::from(u32::from(h)));
            taddrs
                .owners
                .insert(taddr.address().to_owned(), (account_uuid, exposure_height));
            if let Some(script) = taddr.redeem_script() {
                taddrs
                    .redeem_scripts
                    .push((account_uuid, script.as_ref().to_vec()));
            }
        }
    }

    report.imported_accounts.push(ImportedAccount {
        name: account.name().to_owned(),
        account_uuid,
        birthday_basis,
    });
    Ok(())
}

/// Determines the [`AccountPurpose`] with which to import a viewing key,
/// honoring the purpose recorded in the document when present and otherwise
/// inferring spendability from the secret material delivered to the sink.
fn account_purpose<S>(
    account: &::zewif::Account,
    spending_key_available: bool,
    derived_source: Option<&::zewif::DerivedKeySource>,
) -> Result<AccountPurpose, ZewifImportError<S>> {
    let derivation = derived_source
        .map(|d| zip32_derivation(account.name(), d))
        .transpose()?;
    Ok(match account.purpose() {
        Some(::zewif::AccountPurpose::ViewOnly) => AccountPurpose::ViewOnly,
        Some(::zewif::AccountPurpose::Spending) => AccountPurpose::Spending { derivation },
        None => {
            if spending_key_available {
                AccountPurpose::Spending { derivation }
            } else {
                AccountPurpose::ViewOnly
            }
        }
    })
}
