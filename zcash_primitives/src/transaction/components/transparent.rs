//! Functions for parsing, serialization, and value accounting of the transparent
//! components of a transaction.

use corez::io::{self, Read, Write};

use ::transparent::{
    address::Script,
    bundle::{Authorization, Authorized, Bundle, OutPoint, TxIn, TxOut},
};
use zcash_encoding::Vector;
use zcash_protocol::value::{BalanceError, ZatBalance, Zatoshis};
use zcash_script::script;

/// The length of a transaction ID in the transaction encoding.
const TXID_SIZE: usize = 32;

/// Reads an [`OutPoint`] from its transaction encoding: a 32-byte txid followed by the
/// output index as a little-endian `u32`.
///
/// Returns an error if the reader fails or the input is truncated.
pub fn read_outpoint<R: Read>(mut reader: R) -> io::Result<OutPoint> {
    let mut hash = [0u8; TXID_SIZE];
    reader.read_exact(&mut hash)?;
    let mut n = [0u8; size_of::<u32>()];
    reader.read_exact(&mut n)?;
    Ok(OutPoint::new(hash, u32::from_le_bytes(n)))
}

/// Writes `outpoint` in its transaction encoding: a 32-byte txid followed by the output
/// index as a little-endian `u32`.
///
/// Returns an error only if `writer` fails.
pub fn write_outpoint<W: Write>(mut writer: W, outpoint: &OutPoint) -> io::Result<()> {
    writer.write_all(outpoint.hash())?;
    writer.write_all(&outpoint.n().to_le_bytes())
}

/// Reads a CompactSize-prefixed script.
///
/// Returns an error for an invalid length prefix or a reader failure, including
/// [`io::ErrorKind::UnexpectedEof`] if the prefix or the script bytes are truncated.
pub fn read_script<R: Read>(reader: R) -> io::Result<Script> {
    let script = Vector::read_bytes(reader)?;
    Ok(Script(script::Code(script)))
}

/// Writes `script` with a CompactSize length prefix.
///
/// Returns an error only if `writer` fails.
pub fn write_script<W: Write>(mut writer: W, script: &Script) -> io::Result<()> {
    Vector::write_bytes(&mut writer, &script.0.0)
}

/// Returns the length of `script` as encoded, including its CompactSize length prefix.
pub fn script_serialized_size(script: &Script) -> usize {
    Vector::serialized_size_of_u8_vec(&script.0.0)
}

/// Reads a transparent input: an outpoint, a `scriptSig`, and a little-endian `u32`
/// sequence number.
///
/// Returns an error if the reader fails, the input is truncated, or the `scriptSig` has
/// an invalid length prefix.
pub fn read_txin<R: Read>(mut reader: R) -> io::Result<TxIn<Authorized>> {
    let prevout = read_outpoint(&mut reader)?;
    let script_sig = read_script(&mut reader)?;
    let mut sequence = [0u8; size_of::<u32>()];
    reader.read_exact(&mut sequence)?;
    Ok(TxIn::from_parts(
        prevout,
        script_sig,
        u32::from_le_bytes(sequence),
    ))
}

/// Writes a transparent input: an outpoint, a `scriptSig`, and a little-endian `u32`
/// sequence number.
///
/// Returns an error only if `writer` fails.
pub fn write_txin<W: Write>(mut writer: W, txin: &TxIn<Authorized>) -> io::Result<()> {
    write_outpoint(&mut writer, txin.prevout())?;
    write_script(&mut writer, txin.script_sig())?;
    writer.write_all(&txin.sequence().to_le_bytes())
}

/// Reads a transparent output: an 8-byte little-endian value followed by a
/// `scriptPubKey`.
///
/// Returns [`io::ErrorKind::InvalidData`] if the value is negative or exceeds the
/// maximum money supply. Returns an error if the reader fails, the input is truncated,
/// or the `scriptPubKey` has an invalid length prefix.
pub fn read_txout<R: Read>(mut reader: R) -> io::Result<TxOut> {
    let mut value = [0u8; size_of::<i64>()];
    reader.read_exact(&mut value)?;
    let value = Zatoshis::from_nonnegative_i64_le_bytes(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "value out of range"))?;
    let script_pubkey = read_script(&mut reader)?;
    Ok(TxOut::new(value, script_pubkey))
}

/// Writes a transparent output: an 8-byte little-endian value followed by a
/// `scriptPubKey`.
///
/// Returns an error only if `writer` fails.
pub fn write_txout<W: Write>(mut writer: W, txout: &TxOut) -> io::Result<()> {
    writer.write_all(&txout.value().to_i64_le_bytes())?;
    write_script(&mut writer, txout.script_pubkey())
}

/// Returns the amount of value that `bundle` adds to or removes from the transparent
/// pool.
///
/// A positive result means the containing transaction moves funds out of the
/// transparent pool, into shielded pools or to fees. A negative result means it moves
/// funds into the transparent pool.
///
/// `get_prevout_value` returns the value of the output that a given outpoint refers to,
/// or `None` if it is not known. The result is `Ok(None)` if the value of any input is
/// not known.
///
/// Returns an error if a sum overflows or underflows, or if `get_prevout_value` fails.
pub fn value_balance<A, E, F>(
    bundle: &Bundle<A>,
    mut get_prevout_value: F,
) -> Result<Option<ZatBalance>, E>
where
    A: Authorization,
    E: From<BalanceError>,
    F: FnMut(&OutPoint) -> Result<Option<Zatoshis>, E>,
{
    let mut input_sum = Zatoshis::ZERO;
    for txin in &bundle.vin {
        if let Some(v) = get_prevout_value(txin.prevout())? {
            input_sum = (input_sum + v).ok_or(BalanceError::Overflow)?;
        } else {
            return Ok(None);
        }
    }

    let output_sum = bundle
        .vout
        .iter()
        .map(|p| ZatBalance::from(p.value()))
        .sum::<Option<ZatBalance>>()
        .ok_or(BalanceError::Overflow)?;

    let balance = (ZatBalance::from(input_sum) - output_sum).ok_or(BalanceError::Underflow)?;
    Ok(Some(balance))
}

#[cfg(test)]
mod tests {
    use corez::io;
    use proptest::prelude::*;

    use ::transparent::{
        address::Script,
        bundle::{
            Authorized, Bundle, OutPoint, TxIn, TxOut,
            testing::{arb_outpoint, arb_script_pubkey, arb_txin, arb_txout},
        },
    };
    use zcash_protocol::value::{BalanceError, MAX_MONEY, ZatBalance, Zatoshis};
    use zcash_script::script;

    use super::{
        read_outpoint, read_script, read_txin, read_txout, script_serialized_size, value_balance,
        write_outpoint, write_script, write_txin, write_txout,
    };

    /// The serialized length of an outpoint: a 32-byte txid and a 4-byte output index.
    const OUTPOINT_LEN: usize = 32 + 4;

    /// The encoding of an empty script: a zero length prefix.
    const EMPTY_SCRIPT: u8 = 0x00;

    /// A txid whose bytes differ from every other byte in the vectors below.
    const TXID: [u8; 32] = [0xaa; 32];

    /// An output index whose little-endian bytes are `01 02 03 04`.
    const OUTPUT_INDEX: u32 = 0x0403_0201;

    /// A sequence number whose little-endian bytes are `05 06 07 08`.
    const SEQUENCE: u32 = 0x0807_0605;

    /// `OP_1`, used as a one-byte script.
    const OP_1: u8 = 0x51;

    /// The larger of the two values used in the balance tests, in zatoshis.
    const LARGER_ZATS: u64 = 50_000;

    /// The smaller of the two values used in the balance tests, in zatoshis.
    const SMALLER_ZATS: u64 = 20_000;

    /// [`LARGER_ZATS`] as an amount.
    const LARGER: Zatoshis = Zatoshis::const_from_u64(LARGER_ZATS);

    /// [`SMALLER_ZATS`] as an amount.
    const SMALLER: Zatoshis = Zatoshis::const_from_u64(SMALLER_ZATS);

    /// The difference between [`LARGER`] and [`SMALLER`].
    const DIFFERENCE: ZatBalance = ZatBalance::const_from_u64(LARGER_ZATS - SMALLER_ZATS);

    fn fake_input() -> TxIn<Authorized> {
        TxIn::from_parts(OutPoint::fake(), Script::default(), u32::MAX)
    }

    /// Returns a bundle with one input and one output of the given value.
    fn spend_one_create(created: Zatoshis) -> Bundle<Authorized> {
        Bundle {
            vin: vec![fake_input()],
            vout: vec![TxOut::new(created, Script::default())],
            authorization: Authorized,
        }
    }

    #[test]
    fn value_balance_is_inputs_minus_outputs() {
        let balance =
            value_balance::<_, BalanceError, _>(&spend_one_create(SMALLER), |_| Ok(Some(LARGER)));
        assert_eq!(balance, Ok(Some(DIFFERENCE)));
    }

    #[test]
    fn value_balance_is_negative_when_outputs_exceed_inputs() {
        let balance =
            value_balance::<_, BalanceError, _>(&spend_one_create(LARGER), |_| Ok(Some(SMALLER)));
        assert_eq!(balance, Ok(Some(-DIFFERENCE)));
    }

    #[test]
    fn value_balance_is_unknown_when_a_prevout_is_unknown() {
        let balance = value_balance::<_, BalanceError, _>(&spend_one_create(SMALLER), |_| Ok(None));
        assert_eq!(balance, Ok(None));
    }

    #[test]
    fn value_balance_reports_overflow_of_the_input_sum() {
        let two_inputs = Bundle {
            vin: vec![fake_input(), fake_input()],
            vout: vec![],
            authorization: Authorized,
        };
        let balance = value_balance::<_, BalanceError, _>(&two_inputs, |_| {
            Ok(Some(Zatoshis::const_from_u64(MAX_MONEY)))
        });
        assert_eq!(balance, Err(BalanceError::Overflow));
    }

    #[test]
    fn outpoint_layout() {
        let outpoint = OutPoint::new(TXID, OUTPUT_INDEX);
        let mut expected = TXID.to_vec();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut bytes = vec![];
        write_outpoint(&mut bytes, &outpoint).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(read_outpoint(&expected[..]).unwrap(), outpoint);
    }

    #[test]
    fn script_layout() {
        let script = Script(script::Code(vec![OP_1]));
        // A length prefix of 1, then the script byte.
        let expected = [0x01, OP_1];

        let mut bytes = vec![];
        write_script(&mut bytes, &script).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(read_script(&expected[..]).unwrap(), script);
    }

    #[test]
    fn empty_script_layout() {
        let script = Script::default();

        let mut bytes = vec![];
        write_script(&mut bytes, &script).unwrap();
        assert_eq!(bytes, [EMPTY_SCRIPT]);
        assert_eq!(read_script(&bytes[..]).unwrap(), script);
        assert_eq!(script_serialized_size(&script), bytes.len());
    }

    #[test]
    fn txin_layout() {
        let txin = TxIn::from_parts(
            OutPoint::new(TXID, OUTPUT_INDEX),
            Script(script::Code(vec![OP_1])),
            SEQUENCE,
        );
        // The outpoint, then the length-prefixed script, then the sequence number.
        let mut expected = TXID.to_vec();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.extend_from_slice(&[0x01, OP_1]);
        expected.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]);

        let mut bytes = vec![];
        write_txin(&mut bytes, &txin).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(read_txin(&expected[..]).unwrap(), txin);
    }

    #[test]
    fn txout_layout() {
        let txout = TxOut::new(Zatoshis::const_from_u64(1), Script::default());
        // One zatoshi as an 8-byte little-endian integer, then an empty script.
        let expected = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, EMPTY_SCRIPT];

        let mut bytes = vec![];
        write_txout(&mut bytes, &txout).unwrap();
        assert_eq!(bytes, expected);
        assert_eq!(read_txout(&expected[..]).unwrap(), txout);
    }

    proptest! {
        #[test]
        fn outpoint_round_trips(outpoint in arb_outpoint()) {
            let mut bytes = vec![];
            write_outpoint(&mut bytes, &outpoint).unwrap();
            prop_assert_eq!(bytes.len(), OUTPOINT_LEN);
            prop_assert_eq!(read_outpoint(&bytes[..]).unwrap(), outpoint);
        }

        #[test]
        fn script_round_trips(script in arb_script_pubkey()) {
            let mut bytes = vec![];
            write_script(&mut bytes, &script).unwrap();
            prop_assert_eq!(bytes.len(), script_serialized_size(&script));
            prop_assert_eq!(read_script(&bytes[..]).unwrap(), script);
        }

        #[test]
        fn txin_round_trips(txin in arb_txin()) {
            let mut bytes = vec![];
            write_txin(&mut bytes, &txin).unwrap();
            prop_assert_eq!(read_txin(&bytes[..]).unwrap(), txin);
        }

        #[test]
        fn txout_round_trips(txout in arb_txout()) {
            let mut bytes = vec![];
            write_txout(&mut bytes, &txout).unwrap();
            prop_assert_eq!(read_txout(&bytes[..]).unwrap(), txout);
        }
    }

    #[test]
    fn read_script_rejects_truncated_script() {
        // A length prefix of 5 followed by a single script byte.
        let err = read_script(&[0x05, 0x51][..]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_txout_rejects_out_of_range_value() {
        let mut too_large = (MAX_MONEY + 1).to_le_bytes().to_vec();
        too_large.push(EMPTY_SCRIPT);
        assert_eq!(
            read_txout(&too_large[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut negative = (-1i64).to_le_bytes().to_vec();
        negative.push(EMPTY_SCRIPT);
        assert_eq!(
            read_txout(&negative[..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
