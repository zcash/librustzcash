use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Read};

const COIN: i64 = 1_0000_0000;
const MAX_MONEY: i64 = 21_000_000 * COIN;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Amount(pub i64);

impl Amount {
    // Read an Amount from a signed 64-bit little-endian integer.
    pub fn read_i64<R: Read>(mut reader: R, allow_negative: bool) -> io::Result<Self> {
        let amount = reader.read_i64::<LittleEndian>()?;
        if 0 <= amount && amount <= MAX_MONEY {
            Ok(Amount(amount))
        } else if allow_negative && -MAX_MONEY <= amount && amount < 0 {
            Ok(Amount(amount))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                if allow_negative {
                    "Amount not in {-MAX_MONEY..MAX_MONEY}"
                } else {
                    "Amount not in {0..MAX_MONEY}"
                },
            ))
        }
    }

    // Read an Amount from an unsigned 64-bit little-endian integer.
    pub fn read_u64<R: Read>(mut reader: R) -> io::Result<Self> {
        let amount = reader.read_u64::<LittleEndian>()?;
        if amount <= MAX_MONEY as u64 {
            Ok(Amount(amount as i64))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Amount not in {0..MAX_MONEY}",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Amount, MAX_MONEY};

    #[test]
    fn amount_in_range() {
        let zero = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(Amount::read_u64(&zero[..]).unwrap(), Amount(0));
        assert_eq!(Amount::read_i64(&zero[..], false).unwrap(), Amount(0));
        assert_eq!(Amount::read_i64(&zero[..], true).unwrap(), Amount(0));

        let neg_one = b"\xff\xff\xff\xff\xff\xff\xff\xff";
        assert!(Amount::read_u64(&neg_one[..]).is_err());
        assert!(Amount::read_i64(&neg_one[..], false).is_err());
        assert_eq!(Amount::read_i64(&neg_one[..], true).unwrap(), Amount(-1));

        let max_money = b"\x00\x40\x07\x5a\xf0\x75\x07\x00";
        assert_eq!(Amount::read_u64(&max_money[..]).unwrap(), Amount(MAX_MONEY));
        assert_eq!(
            Amount::read_i64(&max_money[..], false).unwrap(),
            Amount(MAX_MONEY)
        );
        assert_eq!(
            Amount::read_i64(&max_money[..], true).unwrap(),
            Amount(MAX_MONEY)
        );

        let max_money_p1 = b"\x01\x40\x07\x5a\xf0\x75\x07\x00";
        assert!(Amount::read_u64(&max_money_p1[..]).is_err());
        assert!(Amount::read_i64(&max_money_p1[..], false).is_err());
        assert!(Amount::read_i64(&max_money_p1[..], true).is_err());

        let neg_max_money = b"\x00\xc0\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::read_u64(&neg_max_money[..]).is_err());
        assert!(Amount::read_i64(&neg_max_money[..], false).is_err());
        assert_eq!(
            Amount::read_i64(&neg_max_money[..], true).unwrap(),
            Amount(-MAX_MONEY)
        );

        let neg_max_money_m1 = b"\xff\xbf\xf8\xa5\x0f\x8a\xf8\xff";
        assert!(Amount::read_u64(&neg_max_money_m1[..]).is_err());
        assert!(Amount::read_i64(&neg_max_money_m1[..], false).is_err());
        assert!(Amount::read_i64(&neg_max_money_m1[..], true).is_err());
    }
}
