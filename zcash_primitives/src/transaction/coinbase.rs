//! Types, constants, and functions related to coinbase transactions.

use alloc::vec::Vec;
use core::fmt;

use ::transparent::{
    address::Script,
    bundle::{
        Authorization as TransparentAuthorization, Authorized, Bundle, MapAuth, OutPoint, TxIn,
    },
    sighash::TransparentAuthorizingContext,
};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};
use zcash_script::{
    opcode::{Evaluable as _, PushValue},
    pattern::push_num,
    pv,
    script::{self, Evaluable as _},
};

use crate::transaction::{Authorization, TransactionData};

#[cfg(zcash_unstable = "nu8")]
use crate::transaction::TxVersion;

#[cfg(feature = "circuits")]
use ::transparent::builder::TransparentBuilder;

/// The minimum length of the coinbase transaction script.
///
/// [§ 7.1.2](https://zips.z.cash/protocol/protocol.pdf#txnconsensus) specifies:
///
/// > A coinbase transaction script MUST have length in {2 .. 100} bytes.
pub const MIN_COINBASE_SCRIPT_LEN: usize = 2;

/// The maximum length of the coinbase transaction script.
///
/// [§ 7.1.2](https://zips.z.cash/protocol/protocol.pdf#txnconsensus) specifies:
///
/// > A coinbase transaction script MUST have length in {2 .. 100} bytes.
pub const MAX_COINBASE_SCRIPT_LEN: usize = 100;

/// The maximum length of the encoded height in the coinbase transaction script.
///
/// [§ 7.1.2](https://zips.z.cash/protocol/protocol.pdf#txnconsensus) specifies:
///
/// > The length of `heightBytes` MUST be in the range {1 .. 5}. Then the encoding is the length of
/// > `heightBytes` encoded as one byte, followed by `heightBytes` itself.
pub const MAX_COINBASE_HEIGHT_LEN: usize = 6;

/// Errors related to coinbase transactions.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Encoded coinbase script exceeds [`MAX_COINBASE_SCRIPT_LEN`].
    OversizedScript,
    /// Encoded block height exceeds [`MAX_COINBASE_HEIGHT_LEN`].
    OversizedHeight,
    /// Creating a coinbase input for the genesis block is not supported.
    GenesisInputNotSupported,
    /// Coinbase transactions must contain only a dummy input.
    UnexpectedInputs,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OversizedScript => write!(
                f,
                "encoded coinbase script exceeds the limit of {MAX_COINBASE_SCRIPT_LEN} bytes",
            ),
            Error::OversizedHeight => write!(
                f,
                "encoded block height exceeds the limit of {MAX_COINBASE_HEIGHT_LEN} bytes",
            ),
            Error::GenesisInputNotSupported => write!(
                f,
                "creating a coinbase input for the genesis block is not supported",
            ),
            Error::UnexpectedInputs => {
                write!(f, "coinbase transactions must contain only a dummy input",)
            }
        }
    }
}

impl core::error::Error for Error {}

/// [`transparent::bundle::Authorization`] marker for the transparent bundle of a
/// coinbase transaction, which carries no authorizing data.
///
/// [`transparent::bundle::Authorization`]: ::transparent::bundle::Authorization
#[derive(Debug, Clone)]
pub struct Coinbase;

impl TransparentAuthorization for Coinbase {
    type ScriptSig = script::Sig;
}

impl TransparentAuthorizingContext<Zatoshis> for Coinbase {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        vec![]
    }

    fn input_scriptpubkeys(&self) -> Vec<Script> {
        vec![]
    }
}

impl MapAuth<Coinbase, Authorized> for Coinbase {
    fn map_script_sig(
        &self,
        s: <Coinbase as TransparentAuthorization>::ScriptSig,
    ) -> <Authorized as TransparentAuthorization>::ScriptSig {
        Script(script::Code(s.to_bytes()))
    }

    fn map_authorization(&self, _: Coinbase) -> Authorized {
        Authorized
    }
}

/// Creates the input of a coinbase transaction for the block at `height`.
///
/// The input's `script_sig` encodes `height`, followed by `miner_data` if it is given.
/// Without `miner_data`, a height that encodes to a single byte is followed by `OP_0`,
/// so that the script has the minimum length of [`MIN_COINBASE_SCRIPT_LEN`] bytes.
///
/// Returns:
/// - [`Error::GenesisInputNotSupported`] if `height` is 0;
/// - [`Error::OversizedHeight`] if the encoded height exceeds
///   [`MAX_COINBASE_HEIGHT_LEN`] bytes;
/// - [`Error::OversizedScript`] if the script exceeds [`MAX_COINBASE_SCRIPT_LEN`] bytes.
pub fn coinbase_input(
    height: BlockHeight,
    miner_data: Option<PushValue>,
) -> Result<TxIn<Coinbase>, Error> {
    let h = match i64::from(height) {
        0 => Err(Error::GenesisInputNotSupported),
        h => Ok(push_num(h)),
    }?;

    let h_len = h.byte_len();
    assert!(h_len > 0);

    // # Consensus
    //
    // > A coinbase transaction for a block at block height greater than 0 MUST have a script
    // > that, as its first item, encodes the block height `height` as follows. For `height` in
    // > the range {1 .. 16}, the encoding is a single byte of value `0x50` + `height`.
    // > Otherwise, let `heightBytes` be the signed little-endian representation of `height`,
    // > using the minimum nonzero number of bytes such that the most significant byte is <
    // > `0x80`. The length of `heightBytes` MUST be in the range {1 .. 5}. Then the encoding is
    // > the length of `heightBytes` encoded as one byte, followed by `heightBytes` itself. This
    // > matches the encoding used by Bitcoin in the implementation of [BIP-34] (but the
    // > description here is to be considered normative).
    //
    // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
    //
    // ## Note
    //
    // The height is encoded in `push_num`, which always returns an opcode, and every opcode
    // serializes to at least one byte, so we assert the lower bound.
    //
    // [BIP-34]: <https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki>
    if h_len > MAX_COINBASE_HEIGHT_LEN {
        return Err(Error::OversizedHeight);
    }

    let script_sig = script::Component(
        [
            Some(h),
            // Consensus rule: coinbase script must be at least 2 bytes.
            (h_len < MIN_COINBASE_SCRIPT_LEN && miner_data.is_none()).then_some(pv::_0),
            miner_data,
        ]
        .into_iter()
        .flatten()
        .collect(),
    );

    let s_len = script_sig.byte_len();
    assert!(s_len >= MIN_COINBASE_SCRIPT_LEN);

    // # Consensus
    //
    // > A coinbase transaction script MUST have length in {2 .. 100} bytes.
    //
    // <https://zips.z.cash/protocol/protocol.pdf#txnconsensus>
    //
    // ## Note
    //
    // The `miner_data` param always contains an opcode, and every opcode serializes to at least
    // one byte, so we assert the lower bound.
    if s_len > MAX_COINBASE_SCRIPT_LEN {
        return Err(Error::OversizedScript);
    }

    // We set the `prevout` argument to [`OutPoint::NULL`] since [§ 3.11] defines coinbase txs
    // as those that have a single transparent input with a null `prevout` field.
    //
    // We set the `sequence` field to [`u32::MAX`] to disable time-locking, as described in the
    // [Bitcoin Developer Reference].
    //
    // [§ 3.11]: <https://zips.z.cash/protocol/protocol.pdf#coinbasetransactions>
    // [Bitcoin Developer Reference]: <https://developer.bitcoin.org/devguide/transactions.html#locktime-and-sequence-number>
    Ok(TxIn::from_parts(OutPoint::NULL, script_sig, u32::MAX))
}

/// Returns `true` if `tx` is a coinbase transaction.
///
/// A version 7 transaction is a coinbase transaction if and only if it has a
/// coinbase-type effecting entry, including an uninterpreted variant. An earlier
/// transaction is a coinbase transaction if it has a transparent bundle with
/// exactly one input, and that input's `prevout` is [`OutPoint::NULL`]. The
/// consensus rules place further requirements on the shielded parts of a
/// coinbase transaction; this function does not check them.
pub fn is_coinbase<A: Authorization>(tx: &TransactionData<A>) -> bool {
    match tx.version() {
        #[cfg(zcash_unstable = "nu8")]
        TxVersion::V7 => {
            tx.coinbase_bundle().is_some()
                || tx
                    .uninterpreted_effect_bundles()
                    .contains_key(&super::zip248::BundleType::COINBASE)
        }
        _ => tx
            .transparent_bundle()
            .is_some_and(transparent_bundle_is_coinbase),
    }
}

/// Returns `true` if `bundle` is the transparent part of a coinbase transaction.
pub(crate) fn transparent_bundle_is_coinbase<A: TransparentAuthorization>(
    bundle: &Bundle<A, Zatoshis>,
) -> bool {
    // From `CTransaction::IsCoinBase()` in zcashd:
    //   return (vin.size() == 1 && vin[0].prevout.IsNull());
    matches!(&bundle.vin[..], [input] if input.prevout() == &OutPoint::NULL)
}

/// Builds the transparent bundle of a coinbase transaction from the outputs added to
/// `builder`.
///
/// Returns [`Error::UnexpectedInputs`] if any inputs were added to `builder`, and
/// otherwise any error of [`coinbase_input`].
#[cfg(feature = "circuits")]
pub(crate) fn build_transparent_bundle(
    builder: TransparentBuilder<Zatoshis>,
    height: BlockHeight,
    miner_data: Option<PushValue>,
) -> Result<Bundle<Coinbase, Zatoshis>, Error> {
    #[cfg(feature = "transparent-inputs")]
    if !builder.inputs().is_empty() {
        return Err(Error::UnexpectedInputs);
    }

    Ok(Bundle {
        vin: vec![coinbase_input(height, miner_data)?],
        vout: builder.outputs().to_vec(),
        authorization: Coinbase,
    })
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ::transparent::{
        address::Script,
        bundle::{Authorized, Bundle, OutPoint, TxIn},
    };
    use assert_matches::assert_matches;
    use zcash_protocol::{
        consensus::{BlockHeight, BranchId},
        value::Zatoshis,
    };
    use zcash_script::{pv, script::Evaluable as _};

    use super::{
        Error, MAX_COINBASE_HEIGHT_LEN, MAX_COINBASE_SCRIPT_LEN, coinbase_input, is_coinbase,
        transparent_bundle_is_coinbase,
    };
    use crate::transaction::{TransactionData, TxVersion};

    /// `OP_1`. Heights 1 to 16 are encoded as the single byte `0x50 + height`.
    const OP_1: u8 = 0x51;

    /// `OP_16`, the encoding of the largest height that is a single opcode.
    const OP_16: u8 = 0x60;

    /// `OP_0`, which pads a one-byte height encoding to the two-byte minimum script.
    const OP_0: u8 = 0x00;

    /// The largest height encoded as a small-integer opcode.
    const LAST_SMALL_HEIGHT: u32 = 16;

    /// The lowest height encoded as a length-prefixed number rather than a small-integer
    /// opcode.
    const FIRST_PUSHED_HEIGHT: u32 = 17;

    /// The lowest height whose one-byte encoding (`0x80`) has its top bit set, so that
    /// the signed little-endian encoding needs a zero padding byte.
    const ONE_BYTE_SIGN_PADDED_HEIGHT: u32 = 0x80;

    /// The lowest height whose two-byte encoding (`0x8000`) has its top bit set.
    const TWO_BYTE_SIGN_PADDED_HEIGHT: u32 = 0x8000;

    /// The encoded length of a height from 1 to 16.
    const SMALL_HEIGHT_LEN: usize = 1;

    /// The length of an `OP_PUSHDATA1` header: the opcode and one length byte. It
    /// precedes pushed data of 76 to 255 bytes.
    const PUSHDATA1_HEADER_LEN: usize = 2;

    /// The longest miner data that fits in a coinbase script beside a height from 1 to
    /// 16.
    const MAX_MINER_DATA_LEN: usize =
        MAX_COINBASE_SCRIPT_LEN - SMALL_HEIGHT_LEN - PUSHDATA1_HEADER_LEN;

    /// An arbitrary byte of miner data that has no single-opcode encoding.
    const MINER_DATA_BYTE: u8 = 0xab;

    #[test]
    fn genesis_is_rejected() {
        assert_matches!(
            coinbase_input(BlockHeight::from_u32(0), None),
            Err(Error::GenesisInputNotSupported)
        );
    }

    #[test]
    fn small_height_is_one_opcode_padded_to_two_bytes() {
        let txin = coinbase_input(BlockHeight::from_u32(1), None).unwrap();
        assert_eq!(txin.script_sig().to_bytes(), [OP_1, OP_0]);
        assert_eq!(txin.prevout(), &OutPoint::NULL);
        assert_eq!(txin.sequence(), u32::MAX);
    }

    #[test]
    fn larger_height_is_length_prefixed() {
        let txin = coinbase_input(BlockHeight::from_u32(FIRST_PUSHED_HEIGHT), None).unwrap();
        // One length byte, then the height as a single little-endian byte.
        assert_eq!(
            txin.script_sig().to_bytes(),
            [0x01, FIRST_PUSHED_HEIGHT as u8]
        );
    }

    #[test]
    fn largest_small_height_is_one_opcode() {
        let txin = coinbase_input(BlockHeight::from_u32(LAST_SMALL_HEIGHT), None).unwrap();
        assert_eq!(txin.script_sig().to_bytes(), [OP_16, OP_0]);
    }

    #[test]
    fn height_with_top_bit_set_is_sign_padded() {
        let txin =
            coinbase_input(BlockHeight::from_u32(ONE_BYTE_SIGN_PADDED_HEIGHT), None).unwrap();
        // A length of 2, then `0x80` and the zero byte that keeps it non-negative.
        assert_eq!(txin.script_sig().to_bytes(), [0x02, 0x80, 0x00]);

        let txin =
            coinbase_input(BlockHeight::from_u32(TWO_BYTE_SIGN_PADDED_HEIGHT), None).unwrap();
        // A length of 3, then `0x8000` in little-endian order and the zero byte.
        assert_eq!(txin.script_sig().to_bytes(), [0x03, 0x00, 0x80, 0x00]);
    }

    #[test]
    fn largest_height_is_accepted() {
        let txin = coinbase_input(BlockHeight::from_u32(u32::MAX), None).unwrap();
        let script = txin.script_sig().to_bytes();
        // A length of 5, then four `0xff` bytes and the zero byte.
        assert_eq!(script, [0x05, 0xff, 0xff, 0xff, 0xff, 0x00]);
        assert_eq!(script.len(), MAX_COINBASE_HEIGHT_LEN);
    }

    #[test]
    fn miner_data_follows_the_height_without_padding() {
        let data = pv::push_value(&[MINER_DATA_BYTE]).expect("short enough");
        let txin = coinbase_input(BlockHeight::from_u32(1), Some(data)).unwrap();
        // The height opcode, then a push of one byte.
        assert_eq!(txin.script_sig().to_bytes(), [OP_1, 0x01, MINER_DATA_BYTE]);
    }

    #[test]
    fn script_of_the_maximum_length_is_accepted() {
        let data = pv::push_value(&[0u8; MAX_MINER_DATA_LEN]).expect("short enough");
        let txin = coinbase_input(BlockHeight::from_u32(1), Some(data)).unwrap();
        assert_eq!(txin.script_sig().to_bytes().len(), MAX_COINBASE_SCRIPT_LEN);
    }

    #[test]
    fn script_one_byte_over_the_maximum_length_is_rejected() {
        let data = pv::push_value(&[0u8; MAX_MINER_DATA_LEN + 1]).expect("short enough");
        assert_matches!(
            coinbase_input(BlockHeight::from_u32(1), Some(data)),
            Err(Error::OversizedScript)
        );
    }

    fn bundle(vin: Vec<TxIn<Authorized>>) -> Bundle<Authorized, Zatoshis> {
        Bundle {
            vin,
            vout: vec![],
            authorization: Authorized,
        }
    }

    fn input(prevout: OutPoint) -> TxIn<Authorized> {
        TxIn::from_parts(prevout, Script::default(), u32::MAX)
    }

    #[test]
    fn coinbase_bundle_has_exactly_one_null_prevout() {
        assert!(transparent_bundle_is_coinbase(&bundle(vec![input(
            OutPoint::NULL
        )])));
        assert!(!transparent_bundle_is_coinbase(&bundle(vec![input(
            OutPoint::fake()
        )])));
        assert!(!transparent_bundle_is_coinbase(&bundle(vec![
            input(OutPoint::NULL),
            input(OutPoint::NULL)
        ])));
        assert!(!transparent_bundle_is_coinbase(&bundle(vec![])));
    }

    /// A lock time of zero, which places no restriction on when a transaction is mined.
    const NO_LOCK_TIME: u32 = 0;

    /// An expiry height of zero, which means that a transaction does not expire.
    const NO_EXPIRY_HEIGHT: u32 = 0;

    /// Returns a transaction that has only the given transparent bundle.
    fn transaction(
        transparent_bundle: Option<Bundle<Authorized, Zatoshis>>,
    ) -> TransactionData<crate::transaction::Authorized> {
        TransactionData::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            NO_LOCK_TIME,
            BlockHeight::from_u32(NO_EXPIRY_HEIGHT),
            transparent_bundle,
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
        )
    }

    #[test]
    fn transaction_is_coinbase_exactly_when_its_transparent_bundle_is() {
        assert!(is_coinbase(&transaction(Some(bundle(vec![input(
            OutPoint::NULL
        )])))));
        assert!(!is_coinbase(&transaction(Some(bundle(vec![input(
            OutPoint::fake()
        )])))));
        assert!(!is_coinbase(&transaction(None)));
    }

    /// A version 7 transaction with the given transparent bundle, coinbase or not.
    #[cfg(zcash_unstable = "nu8")]
    fn v7_transaction(
        transparent_bundle: Option<Bundle<Authorized, Zatoshis>>,
        coinbase: bool,
    ) -> TransactionData<crate::transaction::Authorized> {
        let coinbase_bundle = coinbase.then(|| {
            crate::transaction::zip248::CoinbaseBundle::from_parts(
                BlockHeight::from_u32(100),
                Zatoshis::const_from_u64(1_000),
                Zatoshis::ZERO,
                vec![],
                vec![],
                None,
            )
            .unwrap()
        });

        TransactionData::from_parts_with_value_pool_deltas(
            TxVersion::V7,
            BranchId::Nu8,
            NO_LOCK_TIME,
            BlockHeight::from_u32(100),
            crate::transaction::zip248::ValuePoolDeltas::empty(),
            transparent_bundle,
            None,
            #[cfg(feature = "sapling")]
            None,
            #[cfg(feature = "orchard")]
            None,
            #[cfg(feature = "orchard")]
            None,
            coinbase_bundle,
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
            #[cfg(zcash_unstable = "nu8")]
            Default::default(),
        )
        .unwrap()
    }

    /// A v7 transaction is a coinbase transaction exactly when it has a coinbase
    /// bundle, whether or not it has a transparent bundle.
    #[test]
    #[cfg(zcash_unstable = "nu8")]
    fn v7_coinbase_is_identified_by_its_coinbase_bundle() {
        assert!(is_coinbase(&v7_transaction(None, true)));
        assert!(is_coinbase(&v7_transaction(
            Some(bundle(vec![input(OutPoint::fake())])),
            true
        )));
    }

    /// A v7 non-coinbase transaction is not a coinbase transaction even when it has
    /// the legacy null-prevout input.
    #[test]
    #[cfg(zcash_unstable = "nu8")]
    fn v7_non_coinbase_ignores_the_null_prevout_rule() {
        assert!(!is_coinbase(&v7_transaction(None, false)));
        assert!(!is_coinbase(&v7_transaction(
            Some(bundle(vec![input(OutPoint::NULL)])),
            false
        )));
    }
}
