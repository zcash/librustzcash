//! Reference implementation of the ZIP-321 standard for payment requests.
//!
//! This crate provides data structures, parsing, and rendering functions
//! for interpreting and producing valid ZIP 321 URIs.
//!
//! The specification for ZIP 321 URIs may be found at <https://zips.z.cash/zip-0321>
use core::fmt::Debug;
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    ops::{Deref, DerefMut},
};

use zcash_address::{ConversionError, ZcashAddress};
use zcash_protocol::{
    memo::{self, MemoBytes},
    value::{BalanceError, Zatoshis, COIN},
};

/// Errors that may be produced in decoding of payment requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Zip321Error {
    /// A memo value exceeded 512 bytes in length or could not be interpreted as a UTF-8 string
    /// when using a valid UTF-8 lead byte.
    MemoBytesError(memo::Error),
    /// The payment at the wrapped index attempted to include a memo when sending to a
    /// transparent recipient address, which is not supported by the protocol.
    TransparentMemo(usize),
    /// The ZIP 321 URI was malformed and failed to parse.
    ParseError(String),
}

impl<E: Display> From<ConversionError<E>> for Zip321Error {
    fn from(value: ConversionError<E>) -> Self {
        Zip321Error::ParseError(format!("Address parsing failed: {value}"))
    }
}

impl From<zip321_parse::Error> for Zip321Error {
    fn from(value: zip321_parse::Error) -> Self {
        Zip321Error::ParseError(value.to_string())
    }
}

impl Display for Zip321Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Zip321Error::MemoBytesError(err) => write!(
                f,
                "Memo exceeded maximum length or violated UTF-8 encoding restrictions: {err:?}"
            ),
            Zip321Error::TransparentMemo(idx) => write!(
                f,
                "Payment {idx} is invalid: cannot send a memo to a transparent recipient address",
                idx = idx.to_string()
            ),
            Zip321Error::ParseError(s) => write!(f, "Parse failure: {s}"),
        }
    }
}

impl std::error::Error for Zip321Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Zip321Error::MemoBytesError(err) => Some(err),
            _ => None,
        }
    }
}

/// A single payment being requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payment {
    /// The address to which the payment should be sent.
    recipient_address: ZcashAddress,
    /// The amount of the payment that is being requested.
    amount: Zatoshis,
    /// A memo that, if included, must be provided with the payment.
    /// If a memo is present and [`recipient_address`] is not a shielded
    /// address, the wallet should report an error.
    ///
    /// [`recipient_address`]: #structfield.recipient_address
    memo: Option<MemoBytes>,

    inner: zip321_parse::Payment,
}

/// Payment "inherits" all methods of [zip321_parse::Payment].
impl Deref for Payment {
    type Target = zip321_parse::Payment;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<zip321_parse::Payment> for Payment {
    fn as_ref(&self) -> &zip321_parse::Payment {
        &self.inner
    }
}

impl AsMut<zip321_parse::Payment> for Payment {
    fn as_mut(&mut self) -> &mut zip321_parse::Payment {
        &mut self.inner
    }
}

impl Payment {
    fn try_from_parse_payment(
        index: usize,
        inner: zip321_parse::Payment,
    ) -> Result<Self, Zip321Error> {
        let addy = inner.recipient_address_str();
        let recipient_address = ZcashAddress::try_from_encoded(addy).map_err(|err| {
            Zip321Error::ParseError(format!(
                "Could not interpret {addy} as a valid Zcash address: {err}"
            ))
        })?;
        let coins = inner.amount_coins();
        let zats = inner.amount_zatoshis_remainder();
        let amount = combine_zatoshis((coins, zats))?;
        let memo = if let Some(memo) = inner.memo() {
            if recipient_address.can_receive_memo() {
                Some(MemoBytes::from_bytes(memo.as_slice()).map_err(Zip321Error::MemoBytesError)?)
            } else {
                return Err(Zip321Error::TransparentMemo(index));
            }
        } else {
            None
        };
        Ok(Self {
            recipient_address,
            amount,
            memo,
            inner,
        })
    }

    /// Constructs a new [`Payment`] from its constituent parts.
    ///
    /// Returns `None` if the payment requests that a memo be sent to a recipient that cannot
    /// receive a memo.
    pub fn new(
        recipient_address: ZcashAddress,
        amount: Zatoshis,
        memo: Option<MemoBytes>,
        label: Option<String>,
        message: Option<String>,
        other_params: Vec<(String, String)>,
    ) -> Option<Self> {
        if memo.is_none() || recipient_address.can_receive_memo() {
            let inner = zip321_parse::Payment::new(
                recipient_address.encode(),
                split_zatoshis(amount),
                memo.clone()
                    .map(|m| zip321_parse::Memo::new(m.into_bytes())),
                label,
                message,
                other_params,
            );
            Some(Self {
                recipient_address,
                amount,
                memo,
                inner,
            })
        } else {
            None
        }
    }

    /// Constructs a new [`Payment`] paying the given address the specified amount.
    pub fn without_memo(recipient_address: ZcashAddress, amount: Zatoshis) -> Self {
        Self {
            inner: zip321_parse::Payment::without_memo(
                recipient_address.encode(),
                split_zatoshis(amount),
            ),
            recipient_address,
            amount,
            memo: None,
        }
    }

    /// Returns the payment address to which the payment should be sent.
    pub fn recipient_address(&self) -> &ZcashAddress {
        &self.recipient_address
    }

    /// Returns the value of the payment that is being requested, in zatoshis.
    pub fn amount(&self) -> Zatoshis {
        self.amount
    }

    /// Returns the memo that, if included, must be provided with the payment.
    pub fn memo(&self) -> Option<&MemoBytes> {
        self.memo.as_ref()
    }
}

/// Split zatoshis into integer ZEC and fraction remainder zatoshis.
fn split_zatoshis(amount: Zatoshis) -> (u64, u64) {
    let coins = u64::from(amount) / zcash_protocol::value::COIN;
    let zats = u64::from(amount) % zcash_protocol::value::COIN;
    (coins, zats)
}

/// Combine ZEC and a fractional remainder of zatoshis.
fn combine_zatoshis((zec, zats): (u64, u64)) -> Result<Zatoshis, Zip321Error> {
    zec.checked_mul(COIN)
        .and_then(|coin_zats| coin_zats.checked_add(zats))
        .ok_or(BalanceError::Overflow)
        .and_then(Zatoshis::from_u64)
        .map_err(|_| Zip321Error::ParseError(format!("Not a valid zat amount: {zec}.{zats}")))
}

/// A ZIP321 transaction request.
///
/// A ZIP 321 request may include one or more such requests for payment.
/// When constructing a transaction in response to such a request,
/// a separate output should be added to the transaction for each
/// payment value in the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRequest {
    inner: zip321_parse::TransactionRequest<Payment>,
}

impl Deref for TransactionRequest {
    type Target = zip321_parse::TransactionRequest<Payment>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TransactionRequest {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl TransactionRequest {
    /// Constructs a new transaction request that obeys the ZIP-321 invariants.
    pub fn new(payments: Vec<Payment>) -> Result<TransactionRequest, Zip321Error> {
        Ok(TransactionRequest {
            inner: zip321_parse::TransactionRequest::new_with_constructor(
                payments,
                Payment::try_from_parse_payment,
            )?,
        })
    }

    /// Constructs a new empty transaction request.
    pub fn empty() -> Self {
        Self {
            inner: Default::default(),
        }
    }

    /// Returns the total value of payments to be made.
    ///
    /// Returns `Err` in the case of overflow, or if the value is
    /// outside the range `0..=MAX_MONEY` zatoshis.
    pub fn total(&self) -> Result<Zatoshis, BalanceError> {
        self.payments()
            .values()
            .map(|p| p.amount)
            .try_fold(Zatoshis::ZERO, |acc, a| {
                (acc + a).ok_or(BalanceError::Overflow)
            })
    }

    /// Constructs a new transaction request from the provided map from payment
    /// index to payment.
    ///
    /// Payment index 0 will be mapped to the empty payment index.
    pub fn from_indexed(payments: BTreeMap<usize, Payment>) -> Result<Self, Zip321Error> {
        let inner = zip321_parse::TransactionRequest::from_indexed(payments)?;
        Ok(Self { inner })
    }

    /// Parse the provided URI to a payment request value.
    pub fn from_uri(uri: &str) -> Result<Self, Zip321Error> {
        Ok(Self {
            inner: zip321_parse::TransactionRequest::from_uri_with_constructor(
                uri,
                Payment::try_from_parse_payment,
            )?,
        })
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::collection::btree_map;
    use proptest::collection::vec;
    use proptest::option;
    use proptest::prelude::{any, prop_compose};

    use zcash_address::testing::arb_address;
    use zcash_protocol::{consensus::NetworkType, value::testing::arb_zatoshis};

    use super::{MemoBytes, Payment, TransactionRequest};
    pub const VALID_PARAMNAME: &str = "[a-zA-Z][a-zA-Z0-9+-]*";

    prop_compose! {
        pub fn arb_valid_memo()(memo in zip321_parse::testing::arb_valid_memo()) -> MemoBytes {
            MemoBytes::from_bytes(memo.as_slice()).unwrap()
        }
    }

    prop_compose! {
        /// Constructs an arbitrary zip321 Payment
        pub fn arb_zip321_payment(network: NetworkType)(
            recipient_address in arb_address(network),
            amount in arb_zatoshis(),
            memo in option::of(arb_valid_memo()),
            message in option::of(any::<String>()),
            label in option::of(any::<String>()),
            // prevent duplicates by generating a set rather than a vec
            other_params in btree_map(VALID_PARAMNAME, any::<String>(), 0..3),
        ) -> Payment {
            let memo = memo.filter(|_| recipient_address.can_receive_memo());
            Payment::new(recipient_address, amount, memo, label, message, other_params.into_iter().collect()).unwrap()
        }
    }

    prop_compose! {
        pub fn arb_zip321_request(network: NetworkType)(
            payments in btree_map(0usize..10000, arb_zip321_payment(network), 1..10)
        ) -> TransactionRequest {
            let mut req = TransactionRequest::from_indexed(payments).unwrap();
            req.normalize(); // just to make test comparisons easier
            req
        }
    }

    prop_compose! {
        pub fn arb_zip321_request_sequential(network: NetworkType)(
            payments in vec(arb_zip321_payment(network), 1..10)
        ) -> TransactionRequest {
            let mut req = TransactionRequest::new(payments).unwrap();
            req.normalize(); // just to make test comparisons easier
            req
        }
    }

    prop_compose! {
        pub fn arb_zip321_uri(network: NetworkType)(req in arb_zip321_request(network)) -> String {
            req.to_uri()
        }
    }

    prop_compose! {
        pub fn arb_addr_str(network: NetworkType)(
            recipient_address in arb_address(network)
        ) -> String {
            recipient_address.encode()
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use proptest::prelude::{any, proptest};
    use std::str::FromStr;

    use zcash_address::{testing::arb_address, ZcashAddress};
    use zcash_protocol::{
        consensus::NetworkType,
        memo::{Memo, MemoBytes},
        value::{testing::arb_zatoshis, Zatoshis},
    };
    use zip321_parse::{render::str_param, zcashparam, Param};

    use crate::combine_zatoshis;

    use super::{
        testing::{arb_addr_str, arb_valid_memo, arb_zip321_request, arb_zip321_uri},
        Payment, TransactionRequest,
    };

    /// Converts a [`MemoBytes`] value to a ZIP 321 compatible base64-encoded string.
    ///
    /// [`MemoBytes`]: zcash_protocol::memo::MemoBytes
    pub fn memo_to_base64(memo: &MemoBytes) -> String {
        BASE64_URL_SAFE_NO_PAD.encode(memo.as_slice())
    }

    /// Parse a [`MemoBytes`] value from a ZIP 321 compatible base64-encoded string.
    ///
    /// [`MemoBytes`]: zcash_protocol::memo::MemoBytes
    pub fn memo_from_base64(s: &str) -> Result<MemoBytes, String> {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|e| e.to_string())?;
        MemoBytes::from_bytes(&bytes).map_err(|e| e.to_string())
    }

    fn check_roundtrip(req: TransactionRequest) {
        let req_uri = req.to_uri();
        let parsed = TransactionRequest::from_uri(&req_uri).unwrap();
        assert_eq!(parsed, req);
    }

    fn parse_amount(i: &str) -> Zatoshis {
        let (_, zec_rem) = zip321_parse::parse_amount(&i).unwrap();
        combine_zatoshis(zec_rem).unwrap()
    }

    /// Converts a [`Zatoshis`] value to a correctly formatted decimal ZEC
    /// value for inclusion in a ZIP 321 URI.
    fn amount_str(amount: Zatoshis) -> String {
        let (coins, zats) = super::split_zatoshis(amount);
        zip321_parse::render::amount_coins_zats_str(coins, zats)
    }

    /// Constructs a "memo" key/value pair containing the base64URI-encoded memo
    /// at the specified parameter index.
    fn memo_param(value: &MemoBytes, idx: Option<usize>) -> String {
        use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
        zip321_parse::render::memo_param(&BASE64_URL_SAFE_NO_PAD.encode(value.as_slice()), idx)
    }

    #[test]
    fn test_zip321_roundtrip_simple_amounts() {
        let amounts = vec![1u64, 1000u64, 100000u64, 100000000u64, 100000000000u64];

        for amt_u64 in amounts {
            let amt = Zatoshis::const_from_u64(amt_u64);
            let amt_str = amount_str(amt);
            let zats = parse_amount(&amt_str);
            assert_eq!(amt, zats);
        }
    }

    #[test]
    fn test_zip321_parse_empty_message() {
        let fragment = "message=";

        let result = zcashparam(fragment).unwrap().1.param;
        assert_eq!(result, Param::Message("".to_string()));
    }

    #[test]
    fn test_zip321_parse_simple() {
        let uri = "zcash:ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k?amount=3768769.02796286&message=";
        let parse_result = TransactionRequest::from_uri(uri).unwrap();

        let expected = TransactionRequest::new(
            vec![
                Payment::new(
                    ZcashAddress::try_from_encoded("ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap(),
                    Zatoshis::const_from_u64(376876902796286),
                    None,
                    None,
                    Some("".to_string()),
                    vec![],
                ).unwrap()
            ]
        ).unwrap();

        assert_eq!(parse_result, expected);
    }

    #[test]
    fn test_zip321_parse_no_query_params() {
        let uri = "zcash:ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k";
        let parse_result = TransactionRequest::from_uri(uri).unwrap();

        let expected = TransactionRequest::new(
            vec![
                Payment::new (
                    ZcashAddress::try_from_encoded("ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap(),
                    Zatoshis::ZERO,
                    None,
                    None,
                    None,
                    vec![],
                ).unwrap()
            ]
        ).unwrap();

        assert_eq!(parse_result, expected);
    }

    #[test]
    fn test_zip321_roundtrip_empty_message() {
        let req = TransactionRequest::new(
            vec![
                Payment::new(
                    ZcashAddress::try_from_encoded("ztestsapling1n65uaftvs2g7075q2x2a04shfk066u3lldzxsrprfrqtzxnhc9ps73v4lhx4l9yfxj46sl0q90k").unwrap(),
                    Zatoshis::ZERO,
                    None,
                    None,
                    Some("".to_string()),
                    vec![]
                ).unwrap()
            ]
        ).unwrap();

        check_roundtrip(req);
    }

    #[test]
    fn test_zip321_memos() {
        let m_simple: MemoBytes = Memo::from_str("This is a simple memo.").unwrap().into();
        let m_simple_64 = memo_to_base64(&m_simple);
        assert_eq!(memo_from_base64(&m_simple_64).unwrap(), m_simple);

        let m_json: MemoBytes = Memo::from_str("{ \"key\": \"This is a JSON-structured memo.\" }")
            .unwrap()
            .into();
        let m_json_64 = memo_to_base64(&m_json);
        assert_eq!(memo_from_base64(&m_json_64).unwrap(), m_json);

        let m_unicode: MemoBytes = Memo::from_str("This is a unicode memo ✨🦄🏆🎉")
            .unwrap()
            .into();
        let m_unicode_64 = memo_to_base64(&m_unicode);
        assert_eq!(memo_from_base64(&m_unicode_64).unwrap(), m_unicode);
    }

    #[test]
    fn test_zip321_spec_valid_examples() {
        let valid_0 = "zcash:";
        let v0r = TransactionRequest::from_uri(valid_0).unwrap();
        assert!(v0r.payments().is_empty());

        let valid_0 = "zcash:?";
        let v0r = TransactionRequest::from_uri(valid_0).unwrap();
        assert!(v0r.payments().is_empty());

        let valid_1 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=1&memo=VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg&message=Thank%20you%20for%20your%20purchase";
        let v1r = TransactionRequest::from_uri(valid_1).unwrap();
        assert_eq!(
            v1r.payments().get(&0).map(|p| p.amount),
            Some(Zatoshis::const_from_u64(100000000))
        );

        let valid_2 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.456&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=0.789&memo.1=VGhpcyBpcyBhIHVuaWNvZGUgbWVtbyDinKjwn6aE8J-PhvCfjok";
        let mut v2r = TransactionRequest::from_uri(valid_2).unwrap();
        v2r.normalize();
        assert_eq!(
            v2r.payments().get(&0).map(|p| p.amount),
            Some(Zatoshis::const_from_u64(12345600000))
        );
        assert_eq!(
            v2r.payments().get(&1).map(|p| p.amount),
            Some(Zatoshis::const_from_u64(78900000))
        );

        // valid; amount just less than MAX_MONEY
        // 20999999.99999999
        let valid_3 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=20999999.99999999";
        let v3r = TransactionRequest::from_uri(valid_3).unwrap();
        assert_eq!(
            v3r.payments().get(&0).map(|p| p.amount),
            Some(Zatoshis::const_from_u64(2099999999999999))
        );

        // valid; MAX_MONEY
        // 21000000
        let valid_4 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=21000000";
        let v4r = TransactionRequest::from_uri(valid_4).unwrap();
        assert_eq!(
            v4r.payments().get(&0).map(|p| p.amount),
            Some(Zatoshis::const_from_u64(2100000000000000))
        );
    }

    #[test]
    fn test_zip321_spec_regtest_valid_examples() {
        let valid_1 = "zcash:zregtestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle7505hlz3?amount=1&memo=VGhpcyBpcyBhIHNpbXBsZSBtZW1vLg&message=Thank%20you%20for%20your%20purchase";
        let v1r = TransactionRequest::from_uri(valid_1).unwrap();
        assert_eq!(
            v1r.payments().get(&0).map(|p| p.amount),
            Some(Zatoshis::const_from_u64(100000000))
        );
    }

    #[test]
    fn test_zip321_spec_invalid_examples() {
        // invalid; empty string
        let invalid_0 = "";
        let i0r = TransactionRequest::from_uri(invalid_0);
        assert!(i0r.is_err());

        // invalid; missing `address=`
        let invalid_1 = "zcash:?amount=3491405.05201255&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=5740296.87793245";
        let i1r = TransactionRequest::from_uri(invalid_1);
        assert!(i1r.is_err());

        // invalid; missing `address.1=`
        let invalid_2 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=1&amount.1=2&address.2=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez";
        let i2r = TransactionRequest::from_uri(invalid_2);
        assert!(i2r.is_err());

        // invalid; `address.0=` and `amount.0=` are not permitted (leading 0s).
        let invalid_3 = "zcash:?address.0=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.0=2";
        let i3r = TransactionRequest::from_uri(invalid_3);
        assert!(i3r.is_err());

        // invalid; duplicate `amount=` field
        let invalid_4 =
            "zcash:?amount=1.234&amount=2.345&address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i4r = TransactionRequest::from_uri(invalid_4);
        assert!(i4r.is_err());

        // invalid; duplicate `amount.1=` field
        let invalid_5 =
            "zcash:?amount.1=1.234&amount.1=2.345&address.1=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i5r = TransactionRequest::from_uri(invalid_5);
        assert!(i5r.is_err());

        //invalid; memo associated with t-addr
        let invalid_6 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.456&memo=eyAia2V5IjogIlRoaXMgaXMgYSBKU09OLXN0cnVjdHVyZWQgbWVtby4iIH0&address.1=ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez&amount.1=0.789&memo.1=VGhpcyBpcyBhIHVuaWNvZGUgbWVtbyDinKjwn6aE8J-PhvCfjok";
        let i6r = TransactionRequest::from_uri(invalid_6);
        assert!(i6r.is_err());

        // invalid; amount component exceeds an i64
        // 9223372036854775808 = i64::MAX + 1
        let invalid_7 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=9223372036854775808";
        let i7r = TransactionRequest::from_uri(invalid_7);
        assert!(i7r.is_err());

        // invalid; amount component wraps into a valid small positive i64
        // 18446744073709551624
        let invalid_7a = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=18446744073709551624";
        let i7ar = TransactionRequest::from_uri(invalid_7a);
        assert!(i7ar.is_err());

        // invalid; amount component is MAX_MONEY
        // 21000000.00000001
        let invalid_8 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=21000000.00000001";
        let i8r = TransactionRequest::from_uri(invalid_8);
        assert!(i8r.is_err());

        // invalid; negative amount
        let invalid_9 = "zcash:ztestsapling10yy2ex5dcqkclhc7z7yrnjq2z6feyjad56ptwlfgmy77dmaqqrl9gyhprdx59qgmsnyfska2kez?amount=-1";
        let i9r = TransactionRequest::from_uri(invalid_9);
        assert!(i9r.is_err());

        // invalid; parameter index too large
        let invalid_10 =
            "zcash:?amount.10000=1.23&address.10000=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU";
        let i10r = TransactionRequest::from_uri(invalid_10);
        assert!(i10r.is_err());

        // invalid: bad amount format
        let invalid_11 = "zcash:?address=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU&amount=123.";
        let i11r = TransactionRequest::from_uri(invalid_11);
        assert!(i11r.is_err());
    }

    proptest! {
        #[test]
        fn prop_zip321_roundtrip_address(addr in arb_address(NetworkType::Test)) {
            let a = addr.encode();
            assert_eq!(ZcashAddress::try_from_encoded(&a), Ok(addr));
        }

        #[test]
        fn prop_zip321_roundtrip_address_str(a in arb_addr_str(NetworkType::Test)) {
            let addr = ZcashAddress::try_from_encoded(&a).unwrap();
            assert_eq!(addr.encode(), a);
        }

        #[test]
        fn prop_zip321_roundtrip_amount(amt in arb_zatoshis()) {
            let amt_str = amount_str(amt);
            assert_eq!(amt, parse_amount(&amt_str));
        }

        #[test]
        fn prop_zip321_roundtrip_str_param(
            message in any::<String>(), i in proptest::option::of(0usize..2000)) {
            let fragment = str_param("message", &message, i);
            let (rest, iparam) = zcashparam(&fragment).unwrap();
            assert_eq!(rest, "");
            assert_eq!(iparam.param, Param::Message(message));
            assert_eq!(iparam.payment_index, i.unwrap_or(0));
        }

        #[test]
        fn prop_zip321_roundtrip_memo_param(
            memo in arb_valid_memo(), i in proptest::option::of(0usize..2000)) {
            let fragment = memo_param(&memo, i);
            let (rest, iparam) = zcashparam(&fragment).unwrap();
            assert_eq!(rest, "");
            assert_eq!(iparam.param, Param::Memo(zip321_parse::Memo::new(memo.into_bytes())));
            assert_eq!(iparam.payment_index, i.unwrap_or(0));
        }

        #[test]
        fn prop_zip321_roundtrip_request(mut req in arb_zip321_request(NetworkType::Test)) {
            let req_uri = req.to_uri();
            let mut parsed = TransactionRequest::from_uri(&req_uri).unwrap();
            assert!(parsed.normalize_and_eq(&mut req));
        }

        #[test]
        fn prop_zip321_roundtrip_uri(uri in arb_zip321_uri(NetworkType::Test)) {
            let mut parsed = TransactionRequest::from_uri(&uri).unwrap();
            parsed.normalize();
            let serialized = parsed.to_uri();
            assert_eq!(serialized, uri)
        }
    }
}
