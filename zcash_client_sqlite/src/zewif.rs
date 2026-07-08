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
use secrecy::{ExposeSecret, SecretVec};
use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
use zcash_client_backend::data_api::{
    Account as _, AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation, chain::ChainState,
};
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
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
    /// The seed and ZIP 32 account index recorded for a seed-derived account do
    /// not reproduce the unified full viewing key recorded for that account.
    DerivedKeyMismatch {
        /// The name of the account whose derivation is inconsistent.
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
            ZewifImportError::DerivedKeyMismatch { account_name } => write!(
                f,
                "The seed and account index recorded for account \"{account_name}\" do not reproduce its recorded unified full viewing key."
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

impl<S> From<rusqlite::Error> for ZewifImportError<S> {
    fn from(e: rusqlite::Error) -> Self {
        ZewifImportError::Wallet(SqliteClientError::from(e))
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
    /// The number of transactions from the document that were not stored,
    /// either because trial decryption found no involvement with any imported
    /// account, or because no imported account had established a chain tip
    /// against which to store them. Such transactions are expected to be
    /// recovered by the post-import rescan if they do in fact involve the
    /// wallet.
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
    /// Seed bytes ready for ZIP 32 derivation, keyed by the canonical 32-byte
    /// ZIP 32 seed fingerprint, so that textually-differing but equivalent
    /// fingerprint encodings resolve to the same seed.
    seeds: HashMap<[u8; 32], SecretVec<u8>>,
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
    // Bech32m permits an all-uppercase spelling; compare the human-readable
    // part case-insensitively so that such encodings are accepted.
    if checked.hrp().to_lowercase() != SEED_FP_HRP {
        return Err(err());
    }
    let bytes = checked.byte_iter().collect::<Vec<_>>();
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| err())?;
    Ok(SeedFingerprint::from_bytes(bytes))
}

/// Converts the seed material of a document seed entry into the byte form used
/// for ZIP 32 derivation, verifying it against the fingerprint under which it
/// was recorded and returning that verified fingerprint alongside the material.
fn seed_entry_bytes<S>(
    entry: &::zewif::SeedEntry,
) -> Result<(SeedFingerprint, SecretVec<u8>), ZewifImportError<S>> {
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
    Ok((claimed, SecretVec::new(seed_bytes)))
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

/// Returns the document's plaintext secret store to draw secret material from,
/// or an error if the store is encrypted. Delivery of that material to the sink
/// is performed by the caller.
fn plaintext_secret_store<E>(
    document: &::zewif::Zewif,
) -> Result<Option<&::zewif::SecretStore>, ZewifImportError<E>> {
    match document.secrets() {
        None => Ok(None),
        Some(::zewif::Secrets::Plain(store)) => Ok(Some(store)),
        Some(::zewif::Secrets::Encrypted(_)) => Err(ZewifImportError::EncryptedSecrets),
    }
}

/// Parses the ZIP 32 account index recorded by a derived key source, mapping an
/// out-of-range value to [`ZewifImportError::InvalidAccountIndex`].
fn derived_account_index<S>(
    account_name: &str,
    source: &::zewif::DerivedKeySource,
) -> Result<zip32::AccountId, ZewifImportError<S>> {
    zip32::AccountId::try_from(source.account_index()).map_err(|_| {
        ZewifImportError::InvalidAccountIndex {
            account_name: account_name.to_owned(),
            index: source.account_index(),
        }
    })
}

/// Constructs the ZIP 32 derivation metadata recorded by a derived key source.
fn zip32_derivation<S>(
    account_name: &str,
    source: &::zewif::DerivedKeySource,
) -> Result<Zip32Derivation, ZewifImportError<S>> {
    let seed_fp = decode_seed_fingerprint(source.seed_fingerprint().encoding())?;
    let account_index = derived_account_index(account_name, source)?;
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
/// The database is populated within a single transaction: if the import fails,
/// no partial state is committed and the import can be retried. Secret material
/// delivered to `sink` is external to the database and is not covered by that
/// rollback, so `sink` should be idempotent under re-delivery.
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
    let secret_store = plaintext_secret_store::<S::Error>(document)?;
    let mut available = AvailableSecrets::empty();
    if let Some(store) = secret_store {
        for entry in store.seeds() {
            sink.store_seed(entry).map_err(ZewifImportError::Sink)?;
            let (fingerprint, seed_bytes) = seed_entry_bytes(entry)?;
            // The material was verified against its fingerprint by
            // `seed_entry_bytes`; index it by the canonical fingerprint bytes so
            // that account key sources resolve to it regardless of how their
            // fingerprint encoding is spelled.
            available.seeds.insert(fingerprint.to_bytes(), seed_bytes);
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

    // Populate the wallet database within a single transaction, so that any
    // failure rolls back cleanly and leaves the database untouched (rather than
    // partially imported, which would collide on a retry). Secret delivery to
    // the sink above is external to the database and is not covered by this
    // rollback; sinks are expected to be idempotent under re-delivery.
    wdb.transactionally::<_, _, ZewifImportError<S::Error>>(|wdb| {
        let mut report = ZewifImportReport::default();
        let mut taddrs = TransparentAddressRecords::default();

        for wallet in document.wallets() {
            report.address_book_entries_not_imported += wallet.address_book().len();

            for account in wallet.accounts() {
                import_account(wdb, &params, account, &available, &mut taddrs, &mut report)?;
            }
        }

        register_transparent_keys(wdb, &params, secret_store, &taddrs, &mut report)?;
        mark_addresses_exposed(wdb, &params, &taddrs, &mut report)?;
        import_transactions(wdb, &params, document, &mut report)?;

        Ok(report)
    })
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

/// Decodes a WIF-encoded transparent spending key, accepting both the
/// uncompressed and the compressed (`0x01`-suffixed) payload forms.
fn decode_wif(expected_prefix: u8, wif: &str) -> Option<secp256k1::SecretKey> {
    let payload = bs58::decode(wif).with_check(None).into_vec().ok()?;
    match payload.as_slice() {
        [prefix, key_data @ ..] if *prefix == expected_prefix && key_data.len() == 32 => {
            secp256k1::SecretKey::from_slice(key_data).ok()
        }
        [prefix, key_data @ .., 0x01] if *prefix == expected_prefix && key_data.len() == 32 => {
            secp256k1::SecretKey::from_slice(key_data).ok()
        }
        _ => None,
    }
}

/// Registers the secret store's standalone transparent spending keys with the
/// accounts that record their addresses, and the recorded P2SH redeem scripts
/// with the accounts that carry them.
fn register_transparent_keys<DbT, P, S>(
    wdb: &mut DbT,
    params: &P,
    store: Option<&::zewif::SecretStore>,
    taddrs: &TransparentAddressRecords,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    DbT: WalletWrite<AccountId = AccountUuid, Error = SqliteClientError>,
    P: consensus::Parameters,
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
        let secret_key =
            decode_wif(wif_prefix, entry.spending_key().encoding()).ok_or_else(|| {
                ZewifImportError::InvalidTransparentKeyEncoding {
                    address: address.clone(),
                }
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
fn mark_addresses_exposed<DbT, P, S>(
    wdb: &mut DbT,
    params: &P,
    taddrs: &TransparentAddressRecords,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    DbT: WalletWrite<AccountId = AccountUuid, Error = SqliteClientError>,
    P: consensus::Parameters,
    S: std::error::Error,
{
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
/// id after the attempt. Storage additionally requires a known chain tip, which
/// only an imported account establishes; if none was imported, every
/// transaction is deferred to the post-import rescan.
fn import_transactions<DbT, P, S>(
    wdb: &mut DbT,
    params: &P,
    document: &::zewif::Zewif,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    DbT: WalletWrite<AccountId = AccountUuid, Error = SqliteClientError>,
    P: consensus::Parameters,
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

    // Storing a decrypted transaction requires a known chain tip, which is only
    // established once an imported account has seeded the scan queue from its
    // birthday. Without one (for example, a document whose only accounts were
    // skipped, or that carries no accounts at all), the transactions cannot be
    // stored here and are deferred to the post-import rescan.
    let chain_tip_known = wdb
        .chain_height()
        .map_err(ZewifImportError::Wallet)?
        .is_some();

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
        if !chain_tip_known {
            // No chain tip against which to store the transaction; defer it to
            // the post-import rescan.
            report.transactions_without_wallet_relevance += 1;
            continue;
        }
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

        // `decrypt_and_store_transaction` persists the transaction only when it
        // is relevant to the wallet, so its presence afterward determines the
        // stored/deferred tally.
        let stored = wdb
            .get_transaction(recorded_txid)
            .map_err(ZewifImportError::Wallet)?
            .is_some();
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
fn import_account<DbT, P, S>(
    wdb: &mut DbT,
    params: &P,
    account: &::zewif::Account,
    available: &AvailableSecrets,
    taddrs: &mut TransparentAddressRecords,
    report: &mut ZewifImportReport,
) -> Result<(), ZewifImportError<S>>
where
    DbT: WalletWrite<AccountId = AccountUuid, Error = SqliteClientError>,
    P: consensus::Parameters,
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
    let available_seed = derived_source.and_then(|d| {
        let fingerprint = decode_seed_fingerprint::<S>(d.seed_fingerprint().encoding()).ok()?;
        available
            .seeds
            .get(&fingerprint.to_bytes())
            .map(|seed| (seed, d))
    });

    // A UFVK or transparent-only account whose derivation record points at a
    // seed present in the document is re-derived by HD derivation; both variants
    // take the identical import path.
    let hd_derivation = match account.viewing_key() {
        ::zewif::AccountViewingKey::Ufvk(_) | ::zewif::AccountViewingKey::TransparentAddressSet => {
            available_seed
        }
        _ => None,
    };

    let account_uuid = if let Some((seed, source)) = hd_derivation {
        // Re-derive the account from its seed, preserving the recorded ZIP 32
        // account index.
        let account_index = derived_account_index(account.name(), source)?;
        // For a UFVK account, confirm the recorded derivation actually
        // reproduces the account's recorded viewing key before creating it, so
        // that a corrupt derivation record cannot silently import an account for
        // a different key.
        if let ::zewif::AccountViewingKey::Ufvk(ufvk) = account.viewing_key() {
            verify_hd_derivation(params, account.name(), ufvk, seed, account_index)?;
        }
        let (imported, _usk) = wdb
            .import_account_hd(account.name(), seed, account_index, &birthday, key_source)
            .map_err(ZewifImportError::Wallet)?;
        imported.id()
    } else {
        match account.viewing_key() {
            ::zewif::AccountViewingKey::Ufvk(ufvk) => {
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
                // A transparent-only account with no seed available cannot be
                // re-derived from a seed, so it is skipped.
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

/// Returns `true` when every key component present in both unified full viewing
/// keys is byte-for-byte identical.
///
/// A component present on only one side is ignored, so a recorded viewing key
/// that omits a receiver the seed-derived key includes is still consistent; a
/// component present on both sides that differs is not. Because a seed-derived
/// key always carries every component, a mismatched account index (which changes
/// all derived components) is always detected.
fn ufvk_components_consistent(
    derived: &UnifiedFullViewingKey,
    recorded: &UnifiedFullViewingKey,
) -> bool {
    let transparent_ok = match (derived.transparent(), recorded.transparent()) {
        (Some(a), Some(b)) => a.serialize() == b.serialize(),
        _ => true,
    };
    let sapling_ok = match (derived.sapling(), recorded.sapling()) {
        (Some(a), Some(b)) => a.to_bytes() == b.to_bytes(),
        _ => true,
    };
    let orchard_ok = match (derived.orchard(), recorded.orchard()) {
        (Some(a), Some(b)) => a.to_bytes() == b.to_bytes(),
        _ => true,
    };
    transparent_ok && sapling_ok && orchard_ok
}

/// Verifies that `seed`, derived at `account_index`, reproduces the unified full
/// viewing key recorded for the account, returning
/// [`ZewifImportError::DerivedKeyMismatch`] otherwise.
fn verify_hd_derivation<P: Parameters, S>(
    params: &P,
    account_name: &str,
    ufvk: &::zewif::UnifiedFullViewingKey,
    seed: &SecretVec<u8>,
    account_index: zip32::AccountId,
) -> Result<(), ZewifImportError<S>> {
    let recorded = UnifiedFullViewingKey::decode(params, ufvk.encoding()).map_err(|message| {
        ZewifImportError::UfvkDecoding {
            account_name: account_name.to_owned(),
            message,
        }
    })?;
    let derived = UnifiedSpendingKey::from_seed(params, seed.expose_secret(), account_index)
        .map_err(|_| ZewifImportError::DerivedKeyMismatch {
            account_name: account_name.to_owned(),
        })?
        .to_unified_full_viewing_key();
    if ufvk_components_consistent(&derived, &recorded) {
        Ok(())
    } else {
        Err(ZewifImportError::DerivedKeyMismatch {
            account_name: account_name.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bip0039::{English, Mnemonic};
    use incrementalmerkletree::Hashable as _;
    use tempfile::NamedTempFile;
    use zcash_client_backend::data_api::{Account as _, AccountPurpose, AccountSource, WalletRead};
    use zcash_keys::encoding::AddressCodec;
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_protocol::consensus;
    use zip32::fingerprint::SeedFingerprint;

    use super::*;
    use crate::testing::db::{test_clock, test_rng};
    use crate::wallet::init::WalletMigrator;

    const TEST_NETWORK: consensus::Network = consensus::Network::TestNetwork;

    /// A [`SecretSink`] that records the identifying halves of the entries
    /// delivered to it.
    #[derive(Default)]
    struct RecordingSink {
        seeds: Vec<String>,
        transparent: Vec<Vec<u8>>,
        sapling: Vec<String>,
        sprout: Vec<String>,
        unified: Vec<String>,
    }

    impl SecretSink for RecordingSink {
        type Error = core::convert::Infallible;

        fn store_seed(&mut self, entry: &::zewif::SeedEntry) -> Result<(), Self::Error> {
            self.seeds.push(entry.fingerprint().encoding().to_owned());
            Ok(())
        }

        fn store_transparent_key(
            &mut self,
            entry: &::zewif::TransparentKeyEntry,
        ) -> Result<(), Self::Error> {
            self.transparent.push(entry.pubkey().as_slice().to_vec());
            Ok(())
        }

        fn store_sapling_key(
            &mut self,
            entry: &::zewif::SaplingKeyEntry,
        ) -> Result<(), Self::Error> {
            self.sapling.push(entry.fvk().encoding().to_owned());
            Ok(())
        }

        fn store_sprout_key(&mut self, entry: &::zewif::SproutKeyEntry) -> Result<(), Self::Error> {
            self.sprout.push(entry.address().to_owned());
            Ok(())
        }

        fn store_unified_key(
            &mut self,
            entry: &::zewif::UnifiedKeyEntry,
        ) -> Result<(), Self::Error> {
            self.unified.push(entry.fvk().encoding().to_owned());
            Ok(())
        }
    }

    /// Creates an initialized empty wallet database on the test network.
    fn test_wallet_db() -> (
        NamedTempFile,
        WalletDb<
            rusqlite::Connection,
            consensus::Network,
            crate::util::testing::FixedClock,
            rand_chacha::ChaChaRng,
        >,
    ) {
        let db_file = NamedTempFile::new().unwrap();
        let mut wdb =
            WalletDb::for_path(db_file.path(), TEST_NETWORK, test_clock(), test_rng()).unwrap();
        WalletMigrator::new().init_or_migrate(&mut wdb).unwrap();
        (db_file, wdb)
    }

    /// Encodes a seed fingerprint in the canonical Bech32m form ZeWIF uses.
    fn encode_seed_fp(fp: &SeedFingerprint) -> String {
        bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse(SEED_FP_HRP).unwrap(), &fp.to_bytes())
            .unwrap()
    }

    /// A mnemonic-backed seed and the document/derived artifacts tests need.
    struct TestSeed {
        mnemonic_phrase: String,
        fingerprint_encoding: String,
        ufvk: UnifiedFullViewingKey,
    }

    fn test_seed(account_index: u32) -> TestSeed {
        let mnemonic = <Mnemonic<English>>::from_entropy([0xAB; 32]).unwrap();
        let seed = mnemonic.to_seed("");
        let fp = SeedFingerprint::from_seed(&seed).unwrap();
        let usk = UnifiedSpendingKey::from_seed(
            &TEST_NETWORK,
            &seed,
            zip32::AccountId::try_from(account_index).unwrap(),
        )
        .unwrap();
        TestSeed {
            mnemonic_phrase: mnemonic.phrase().to_owned(),
            fingerprint_encoding: encode_seed_fp(&fp),
            ufvk: usk.to_unified_full_viewing_key(),
        }
    }

    fn seed_entry(ts: &TestSeed) -> ::zewif::SeedEntry {
        ::zewif::SeedEntry::new(
            ::zewif::SeedFingerprint::new(ts.fingerprint_encoding.clone()),
            ::zewif::SeedMaterial::Bip39Mnemonic(::zewif::Bip39Mnemonic::new(
                ts.mnemonic_phrase.clone(),
                None,
            )),
        )
    }

    fn document(network: ::zewif::Network) -> (::zewif::Zewif, ::zewif::ZewifWallet) {
        let doc = ::zewif::Zewif::new(
            ::zewif::BlockHeight::from(3_000_000),
            ::zewif::BlockHash::from_bytes([0xEE; 32]),
        );
        let wallet = ::zewif::ZewifWallet::new(network);
        (doc, wallet)
    }

    #[test]
    fn network_mismatch_is_rejected() {
        let (_file, mut wdb) = test_wallet_db();
        let (mut doc, wallet) = document(::zewif::Network::Mainnet);
        doc.add_wallet(wallet);

        let result = import_wallet(&mut wdb, &doc, &mut DiscardSecrets);
        assert!(matches!(
            result,
            Err(ZewifImportError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn view_only_ufvk_account_with_chain_state_birthday() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::Ufvk(
            ::zewif::UnifiedFullViewingKey::new(ts.ufvk.encode(&TEST_NETWORK)),
        ));
        account.set_name("viewing");
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000));
        let mut chain_state = ::zewif::ChainState::new(::zewif::BlockHeight::from(2_599_999));
        chain_state.set_block_hash(::zewif::BlockHash::from_bytes([0xBB; 32]));
        chain_state.set_sapling_tree(::zewif::Frontier::NonEmpty(
            ::zewif::FrontierData::from_parts(
                0,
                ::zewif::MerkleNode::new(::sapling::Node::empty_root(0.into()).to_bytes()),
                vec![],
            ),
        ));
        chain_state.set_orchard_tree(::zewif::Frontier::Empty);
        chain_state.set_ironwood_tree(::zewif::Frontier::Empty);
        account.set_birthday_chain_state(chain_state);
        account.set_recover_until_height(::zewif::BlockHeight::from(2_900_000));

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);

        let report = import_wallet(&mut wdb, &doc, &mut DiscardSecrets).unwrap();
        assert_eq!(report.imported_accounts.len(), 1);
        assert_eq!(report.imported_accounts[0].name, "viewing");
        assert_eq!(
            report.imported_accounts[0].birthday_basis,
            BirthdayBasis::ChainState
        );

        let account_uuid = report.imported_accounts[0].account_uuid;
        let imported = wdb.get_account(account_uuid).unwrap().unwrap();
        assert!(matches!(
            imported.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::ViewOnly,
                ..
            }
        ));
        // The birthday is the height following the recorded prior chain state.
        assert_eq!(
            wdb.get_wallet_birthday().unwrap(),
            Some(consensus::BlockHeight::from(2_600_000))
        );
    }

    #[test]
    fn derived_account_is_imported_via_hd_derivation() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        let mut store = ::zewif::SecretStore::new();
        store.add_seed(seed_entry(&ts));

        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::Ufvk(
            ::zewif::UnifiedFullViewingKey::new(ts.ufvk.encode(&TEST_NETWORK)),
        ));
        account.set_name("derived");
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000));
        account.set_key_source(::zewif::KeySource::Derived(::zewif::DerivedKeySource::new(
            ::zewif::SeedFingerprint::new(ts.fingerprint_encoding.clone()),
            0,
            None,
        )));

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));

        let mut sink = RecordingSink::default();
        let report = import_wallet(&mut wdb, &doc, &mut sink).unwrap();

        assert_eq!(sink.seeds, vec![ts.fingerprint_encoding.clone()]);
        assert_eq!(report.imported_accounts.len(), 1);
        assert_eq!(
            report.imported_accounts[0].birthday_basis,
            BirthdayBasis::BirthdayHeight
        );

        let account_uuid = report.imported_accounts[0].account_uuid;
        let imported = wdb.get_account(account_uuid).unwrap().unwrap();
        match imported.source() {
            AccountSource::Derived { derivation, .. } => {
                assert_eq!(
                    derivation.seed_fingerprint().to_bytes(),
                    SeedFingerprint::from_seed(
                        &<Mnemonic<English>>::from_phrase(&ts.mnemonic_phrase)
                            .unwrap()
                            .to_seed("")
                    )
                    .unwrap()
                    .to_bytes()
                );
                assert_eq!(derivation.account_index(), zip32::AccountId::ZERO);
            }
            other => panic!("expected a derived account, got {other:?}"),
        }
        // The account's UFVK is re-derived from the seed and matches the
        // document's record of it.
        assert_eq!(
            imported.ufvk().map(|k| k.encode(&TEST_NETWORK)),
            Some(ts.ufvk.encode(&TEST_NETWORK)),
        );
    }

    #[test]
    fn sprout_accounts_are_skipped() {
        let (_file, mut wdb) = test_wallet_db();
        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::SproutViewingKey(
            ::zewif::sprout::SproutViewingKey::new("ZiVtTestViewingKey"),
        ));
        account.set_name("sprout");

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);

        let report = import_wallet(&mut wdb, &doc, &mut DiscardSecrets).unwrap();
        assert!(report.imported_accounts.is_empty());
        assert_eq!(report.skipped_accounts.len(), 1);
        assert_eq!(
            report.skipped_accounts[0].reason,
            AccountSkipReason::SproutViewingKey
        );
    }

    #[test]
    fn secrets_are_delivered_to_the_sink() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        let secp = secp256k1::Secp256k1::new();
        let secret_key = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pubkey = secret_key.public_key(&secp);
        let mut wif_payload = vec![0xEF];
        wif_payload.extend_from_slice(&secret_key.secret_bytes());
        wif_payload.push(0x01);
        let wif = bs58::encode(wif_payload).with_check().into_string();

        let mut store = ::zewif::SecretStore::new();
        store.add_seed(seed_entry(&ts));
        store.add_transparent_key(::zewif::TransparentKeyEntry::new(
            ::zewif::transparent::TransparentPubKey::from_bytes(pubkey.serialize().to_vec())
                .unwrap(),
            ::zewif::transparent::TransparentSpendingKey::new(wif),
        ));
        store.add_sapling_key(::zewif::SaplingKeyEntry::new(
            ::zewif::sapling::SaplingExtendedFullViewingKey::new("zxviewtestsapling1aaaa"),
            ::zewif::sapling::SaplingExtendedSpendingKey::new("secret-extended-key-test1aaaa"),
        ));
        store.add_sprout_key(::zewif::SproutKeyEntry::new(
            "ztTestSproutAddress",
            ::zewif::sprout::SproutSpendingKey::new("SKTestSproutKey"),
        ));

        let (mut doc, wallet) = document(::zewif::Network::Testnet);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));

        let mut sink = RecordingSink::default();
        let report = import_wallet(&mut wdb, &doc, &mut sink).unwrap();

        assert_eq!(sink.seeds.len(), 1);
        assert_eq!(sink.transparent.len(), 1);
        assert_eq!(sink.sapling.len(), 1);
        assert_eq!(sink.sprout.len(), 1);
        // The transparent key's address is under no account, so it is
        // delivered to the sink but not registered.
        assert_eq!(report.transparent_keys_registered, 0);
        assert_eq!(report.skipped_transparent_keys.len(), 1);
        assert_eq!(
            report.skipped_transparent_keys[0].reason,
            TransparentKeySkipReason::NoOwningAccount
        );
    }

    #[test]
    fn owned_transparent_key_is_registered_and_exposed() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        let secp = secp256k1::Secp256k1::new();
        let secret_key = secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pubkey = secret_key.public_key(&secp);
        let address = TransparentAddress::from_pubkey(&pubkey).encode(&TEST_NETWORK);
        let mut wif_payload = vec![0xEF];
        wif_payload.extend_from_slice(&secret_key.secret_bytes());
        wif_payload.push(0x01);
        let wif = bs58::encode(wif_payload).with_check().into_string();

        let mut store = ::zewif::SecretStore::new();
        store.add_seed(seed_entry(&ts));
        store.add_transparent_key(::zewif::TransparentKeyEntry::new(
            ::zewif::transparent::TransparentPubKey::from_bytes(pubkey.serialize().to_vec())
                .unwrap(),
            ::zewif::transparent::TransparentSpendingKey::new(wif),
        ));

        // The legacy-style account that owns the imported address.
        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::TransparentAddressSet);
        account.set_name("legacy");
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000));
        account.set_key_source(::zewif::KeySource::Derived(::zewif::DerivedKeySource::new(
            ::zewif::SeedFingerprint::new(ts.fingerprint_encoding.clone()),
            0x7FFF_FFFF,
            None,
        )));
        let mut taddr = ::zewif::transparent::Address::new(address.clone());
        taddr.set_pubkey(
            ::zewif::transparent::TransparentPubKey::from_bytes(pubkey.serialize().to_vec())
                .unwrap(),
        );
        account.add_address(::zewif::Address::new(
            ::zewif::ProtocolAddress::Transparent(taddr),
        ));

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));

        let mut sink = RecordingSink::default();
        let report = import_wallet(&mut wdb, &doc, &mut sink).unwrap();

        assert_eq!(report.imported_accounts.len(), 1);
        assert_eq!(report.transparent_keys_registered, 1);
        assert!(report.skipped_transparent_keys.is_empty());
        assert_eq!(report.addresses_marked_exposed, 1);
        assert_eq!(report.addresses_not_recognized, 0);
    }

    #[test]
    fn transactions_without_raw_data_are_counted() {
        let (_file, mut wdb) = test_wallet_db();
        let (mut doc, wallet) = document(::zewif::Network::Testnet);
        doc.add_wallet(wallet);
        let txid = ::zewif::TxId::from_bytes([0x11; 32]);
        doc.add_transaction(txid, ::zewif::Transaction::new(txid));

        let report = import_wallet(&mut wdb, &doc, &mut DiscardSecrets).unwrap();
        assert_eq!(report.transactions_without_raw_data, 1);
        assert_eq!(report.transactions_stored, 0);
        assert_eq!(report.transactions_without_wallet_relevance, 0);
    }

    /// The raw seed for a [`TestSeed`], as ZIP 32 derivation consumes it.
    fn test_seed_bytes(ts: &TestSeed) -> Vec<u8> {
        <Mnemonic<English>>::from_phrase(&ts.mnemonic_phrase)
            .unwrap()
            .to_seed("")
            .to_vec()
    }

    /// A derived-account document that re-derives account 0 of `ts` as an HD
    /// account, with the fingerprint spelled by `fingerprint_encoding` on the
    /// account's derivation record.
    fn hd_account(
        ts: &TestSeed,
        fingerprint_encoding: String,
        account_index: u32,
    ) -> ::zewif::Account {
        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::Ufvk(
            ::zewif::UnifiedFullViewingKey::new(ts.ufvk.encode(&TEST_NETWORK)),
        ));
        account.set_name("hd");
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000));
        account.set_key_source(::zewif::KeySource::Derived(::zewif::DerivedKeySource::new(
            ::zewif::SeedFingerprint::new(fingerprint_encoding),
            account_index,
            None,
        )));
        account
    }

    #[test]
    fn seed_is_matched_by_a_case_differing_fingerprint_encoding() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        let mut store = ::zewif::SecretStore::new();
        store.add_seed(seed_entry(&ts));

        // The account records the same fingerprint as the secret store, but in
        // the uppercase Bech32m spelling; canonical matching must still resolve
        // it to the delivered seed and import the account via HD derivation.
        let account = hd_account(&ts, ts.fingerprint_encoding.to_uppercase(), 0);

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));

        let mut sink = RecordingSink::default();
        let report = import_wallet(&mut wdb, &doc, &mut sink).unwrap();

        assert_eq!(report.imported_accounts.len(), 1);
        let imported = wdb
            .get_account(report.imported_accounts[0].account_uuid)
            .unwrap()
            .unwrap();
        assert!(matches!(imported.source(), AccountSource::Derived { .. }));
    }

    #[test]
    fn hd_derivation_inconsistent_with_recorded_ufvk_is_rejected() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        let mut store = ::zewif::SecretStore::new();
        store.add_seed(seed_entry(&ts));

        // The account's recorded UFVK is account 0's, but its derivation record
        // claims account index 1; re-derivation must detect the mismatch.
        let account = hd_account(&ts, ts.fingerprint_encoding.clone(), 1);

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));

        let result = import_wallet(&mut wdb, &doc, &mut RecordingSink::default());
        assert!(matches!(
            result,
            Err(ZewifImportError::DerivedKeyMismatch { .. })
        ));
    }

    #[test]
    fn unified_account_is_spending_when_its_key_was_delivered() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        // Deliver a unified spending key whose viewing key matches the account's;
        // the account (a bare UFVK with no derivation record) must then be
        // imported as spending rather than view-only.
        let mut store = ::zewif::SecretStore::new();
        store.add_unified_key(::zewif::UnifiedKeyEntry::new(
            ::zewif::UnifiedFullViewingKey::new(ts.ufvk.encode(&TEST_NETWORK)),
            ::zewif::UnifiedSpendingKey::new("usk1testspendingkey"),
        ));

        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::Ufvk(
            ::zewif::UnifiedFullViewingKey::new(ts.ufvk.encode(&TEST_NETWORK)),
        ));
        account.set_name("spending");
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000));

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));

        let report = import_wallet(&mut wdb, &doc, &mut RecordingSink::default()).unwrap();

        assert_eq!(report.imported_accounts.len(), 1);
        let imported = wdb
            .get_account(report.imported_accounts[0].account_uuid)
            .unwrap()
            .unwrap();
        assert!(matches!(
            imported.source(),
            AccountSource::Imported {
                purpose: AccountPurpose::Spending { .. },
                ..
            }
        ));
    }

    /// Builds a transparent-only transaction paying `value` zatoshis to `to`
    /// under the consensus rules in force at `height`, returning its txid and
    /// raw bytes.
    fn transparent_tx_to(
        to: &TransparentAddress,
        value: u64,
        height: u32,
    ) -> (zcash_protocol::TxId, Vec<u8>) {
        use ::transparent::address::Script;
        use ::transparent::bundle::{self as transparent, Authorized, OutPoint, TxIn, TxOut};
        use zcash_primitives::transaction::{TransactionData, TxVersion};
        use zcash_protocol::value::Zatoshis;

        let height = consensus::BlockHeight::from(height);
        let tx = TransactionData::from_parts(
            TxVersion::V5,
            BranchId::for_height(&TEST_NETWORK, height),
            0,
            height + 100,
            #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
            Zatoshis::ZERO,
            Some(transparent::Bundle {
                vin: vec![TxIn::from_parts(OutPoint::fake(), Script::default(), 0)],
                vout: vec![TxOut::new(
                    Zatoshis::const_from_u64(value),
                    to.script().into(),
                )],
                authorization: Authorized,
            }),
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();

        let mut bytes = vec![];
        tx.write(&mut bytes).unwrap();
        (tx.txid(), bytes)
    }

    /// Wraps raw transaction bytes as a mined ZeWIF transaction.
    fn raw_zewif_tx(
        txid: zcash_protocol::TxId,
        raw: &[u8],
        mined_height: u32,
    ) -> ::zewif::Transaction {
        let mut tx = ::zewif::Transaction::new(::zewif::TxId::from_bytes(*txid.as_ref()));
        tx.set_tx_data(::zewif::TransactionData::Raw(::zewif::RawTxData::new(
            ::zewif::Data::from_bytes(raw),
        )));
        tx.set_mined_height(::zewif::BlockHeight::from(mined_height));
        tx
    }

    #[test]
    fn raw_transaction_relevant_to_account_is_stored() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        // The account's default transparent receiver, which the imported HD
        // account will recognize.
        let seed = test_seed_bytes(&ts);
        let usk =
            UnifiedSpendingKey::from_seed(&TEST_NETWORK, &seed, zip32::AccountId::ZERO).unwrap();
        let (taddr, _) = usk.default_transparent_address();

        let height = 2_600_000;
        let (txid, raw) = transparent_tx_to(&taddr, 100_000, height);

        let mut store = ::zewif::SecretStore::new();
        store.add_seed(seed_entry(&ts));
        let account = hd_account(&ts, ts.fingerprint_encoding.clone(), 0);

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        doc.set_secrets(::zewif::Secrets::Plain(store));
        let tx = raw_zewif_tx(txid, &raw, height);
        doc.add_transaction(tx.txid(), tx);

        let report = import_wallet(&mut wdb, &doc, &mut RecordingSink::default()).unwrap();

        assert_eq!(report.imported_accounts.len(), 1);
        assert_eq!(report.transactions_stored, 1);
        assert_eq!(report.transactions_without_wallet_relevance, 0);
        assert_eq!(report.transactions_without_raw_data, 0);
    }

    #[test]
    fn transactions_are_deferred_when_no_account_establishes_a_chain_tip() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        // A raw transaction, but the document's only account is Sprout and so is
        // skipped; with no imported account there is no chain tip, and the
        // transaction must be deferred to the rescan rather than aborting.
        let seed = test_seed_bytes(&ts);
        let usk =
            UnifiedSpendingKey::from_seed(&TEST_NETWORK, &seed, zip32::AccountId::ZERO).unwrap();
        let (taddr, _) = usk.default_transparent_address();
        let height = 2_600_000;
        let (txid, raw) = transparent_tx_to(&taddr, 100_000, height);

        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::SproutViewingKey(
            ::zewif::sprout::SproutViewingKey::new("ZiVtTestViewingKey"),
        ));
        account.set_name("sprout");

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        let tx = raw_zewif_tx(txid, &raw, height);
        doc.add_transaction(tx.txid(), tx);

        let report = import_wallet(&mut wdb, &doc, &mut DiscardSecrets).unwrap();

        assert!(report.imported_accounts.is_empty());
        assert_eq!(report.transactions_stored, 0);
        assert_eq!(report.transactions_without_wallet_relevance, 1);
        assert_eq!(report.transactions_without_raw_data, 0);
    }

    #[test]
    fn a_failed_import_commits_nothing() {
        let (_file, mut wdb) = test_wallet_db();
        let ts = test_seed(0);

        // A valid view-only account followed by a transaction recorded under the
        // wrong txid. The account is imported first, then the txid mismatch
        // aborts the import; the whole import must roll back, leaving nothing
        // committed.
        let mut account = ::zewif::Account::new(::zewif::AccountViewingKey::Ufvk(
            ::zewif::UnifiedFullViewingKey::new(ts.ufvk.encode(&TEST_NETWORK)),
        ));
        account.set_name("viewing");
        account.set_birthday_height(::zewif::BlockHeight::from(2_600_000));

        let seed = test_seed_bytes(&ts);
        let usk =
            UnifiedSpendingKey::from_seed(&TEST_NETWORK, &seed, zip32::AccountId::ZERO).unwrap();
        let (taddr, _) = usk.default_transparent_address();
        let height = 2_600_000;
        let (_txid, raw) = transparent_tx_to(&taddr, 100_000, height);
        // Record the transaction under a txid that does not match its bytes.
        let wrong_txid = zcash_protocol::TxId::from_bytes([0xFF; 32]);

        let (mut doc, mut wallet) = document(::zewif::Network::Testnet);
        wallet.add_account(account);
        doc.add_wallet(wallet);
        let tx = raw_zewif_tx(wrong_txid, &raw, height);
        doc.add_transaction(tx.txid(), tx);

        let result = import_wallet(&mut wdb, &doc, &mut DiscardSecrets);
        assert!(matches!(result, Err(ZewifImportError::TxidMismatch { .. })));

        // Nothing was committed, so the wallet has no account and no birthday.
        assert_eq!(wdb.get_wallet_birthday().unwrap(), None);
    }
}
