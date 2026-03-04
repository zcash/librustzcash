//! High-level API for EIP-681 transaction requests.
//!
//! This module provides ergonomic types for working with common EIP-681 transaction
//! request patterns:
//!
//! - [`NativeRequest`]: Native ETH/chain token transfers
//! - [`Erc20Request`]: ERC-20 token transfers via `transfer(address,uint256)`
//! - [`TransactionRequest`]: Enum that auto-detects the request type

use primitive_types::U256;
use snafu::prelude::*;

use crate::error::{
    AbiParameterAddressIsNotAnAddressSnafu, AbiParameterLenSnafu, AbiParameterNameSnafu,
    AbiParameterUint256Snafu, ChainIdInvalidSnafu, Error, FnNameSnafu, HasAbiParametersSnafu,
    HasFunctionNameSnafu, MissingFnSnafu, NativeTransferError, ParameterInvalidSnafu,
    ParameterNotNumberSnafu, RecipientAddressInvalidSnafu, UnexpectedLeftoverInputSnafu,
};
use crate::parse::RawTransactionRequest;

/// A parsed EIP-681 transaction request.
///
/// This enum automatically categorizes parsed requests into common patterns:
///
/// - [`NativeRequest`]: Native transfers (no function call)
/// - [`Erc20Request`]: ERC-20 `transfer(address,uint256)` calls
/// - [`Unrecognised`](TransactionRequest::Unrecognised): Any other format
///
/// # Example
///
/// ```rust
/// use eip681::TransactionRequest;
///
/// // Parse a native transfer
/// let native = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18";
/// let request = TransactionRequest::parse(native).unwrap();
/// assert!(matches!(request, TransactionRequest::NativeRequest(_)));
///
/// // Parse an ERC-20 transfer
/// let erc20 = "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000";
/// let request = TransactionRequest::parse(erc20).unwrap();
/// assert!(matches!(request, TransactionRequest::Erc20Request(_)));
/// ```
#[derive(Debug)]
pub enum TransactionRequest {
    /// A native ETH/token transfer (no function call).
    NativeRequest(NativeRequest),
    /// An ERC-20 token transfer via `transfer(address,uint256)`.
    Erc20Request(Erc20Request),
    /// Any other transaction request format.
    Unrecognised(RawTransactionRequest),
}

impl TransactionRequest {
    /// Construct a `TransactionRequest` from `NativeRequest` parts, if possible.
    pub fn from_native_request_parts(
        schema_prefix: &str,
        has_pay: bool,
        chain_id: Option<u64>,
        recipient: &str,
        value: Option<U256>,
        gas_limit: Option<U256>,
        gas_price: Option<U256>,
    ) -> Result<Self, Error> {
        let chain_id = chain_id.map(|id| format!("@{id}")).unwrap_or_default();
        let value = value.map(|v| format!("value={v}"));
        let gas_limit = gas_limit.map(|v| format!("gasLimit={v}"));
        let gas_price = gas_price.map(|v| format!("gasPrice={v}"));
        let params: String = [value, gas_limit, gas_price]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("&");
        let pay = if has_pay { "pay-" } else { "" };
        let query = if params.is_empty() {
            String::new()
        } else {
            format!("?{params}")
        };
        let req = format!("{schema_prefix}:{pay}{recipient}{chain_id}{query}");
        Self::parse(&req)
    }

    /// Construct a `TransactionRequest` from `Erc20Request` parts, if possible.
    pub fn from_erc20_request_parts(
        schema_prefix: &str,
        has_pay: bool,
        chain_id: Option<u64>,
        token_contract_address: &str,
        recipient_address: &str,
        value: U256,
    ) -> Result<Self, Error> {
        let chain_id = chain_id.map(|id| format!("@{id}")).unwrap_or_default();
        let pay = if has_pay { "pay-" } else { "" };
        let req = format!(
            "{schema_prefix}:{pay}{token_contract_address}{chain_id}/transfer?address={recipient_address}&uint256={value}"
        );
        Self::parse(&req)
    }

    /// Parse an EIP-681 URI into a categorized transaction request.
    ///
    /// The request is automatically categorized based on its structure:
    ///
    /// - **Native**: No `function_name` and no ABI-typed parameters
    /// - **ERC-20**: `function_name` is "transfer" with exactly `address` and `uint256` parameters
    /// - **Unrecognised**: The transaction is valid via EIP-681, but unrecognised.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let (i, raw) = RawTransactionRequest::parse(input)?;

        ensure!(i.is_empty(), UnexpectedLeftoverInputSnafu { input: i });

        // Determine the type based on the parsed request
        if let Ok(native_req) = NativeRequest::try_from(&raw) {
            return Ok(TransactionRequest::NativeRequest(native_req));
        }

        // Otherwise try ERC-20.
        if let Ok(erc20_req) = Erc20Request::try_from(&raw) {
            return Ok(TransactionRequest::Erc20Request(erc20_req));
        }

        // Otherwise return the raw, Unrecognised request
        Ok(TransactionRequest::Unrecognised(raw))
    }

    /// Consume this request and return the underlying raw parsed request.
    pub fn into_raw(self) -> RawTransactionRequest {
        match self {
            TransactionRequest::NativeRequest(r) => r.inner,
            TransactionRequest::Erc20Request(r) => r.inner,
            TransactionRequest::Unrecognised(r) => r,
        }
    }

    /// Returns the underlying [`NativeRequest`], if possible.
    pub fn as_native(&self) -> Option<&NativeRequest> {
        match self {
            TransactionRequest::NativeRequest(req) => Some(req),
            _ => None,
        }
    }

    /// Returns the underlying [`Erc20Request`], if possible.
    pub fn as_erc20(&self) -> Option<&Erc20Request> {
        match self {
            TransactionRequest::Erc20Request(req) => Some(req),
            _ => None,
        }
    }

    /// Returns the underlying [`RawTransactionRequest`].
    pub fn as_raw(&self) -> &RawTransactionRequest {
        match self {
            TransactionRequest::Erc20Request(erc20_request) => &erc20_request.inner,
            TransactionRequest::NativeRequest(native_request) => &native_request.inner,
            TransactionRequest::Unrecognised(raw_transaction_request) => raw_transaction_request,
        }
    }
}

impl core::fmt::Display for TransactionRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TransactionRequest::NativeRequest(r) => r.fmt(f),
            TransactionRequest::Erc20Request(r) => r.fmt(f),
            TransactionRequest::Unrecognised(r) => r.fmt(f),
        }
    }
}

/// A native transfer request (ETH or native chain token).
///
/// Native transfers are EIP-681 URIs with:
/// - No `function_name`
/// - No ABI-typed parameters (only `value`, `gas`, `gasLimit`, `gasPrice`)
///   * `value`, `gas`, `gasLimit` and `gasPrice` parameters are valid
///     `U256` values.
///
/// # Example
///
/// ```rust
/// use eip681::{TransactionRequest, U256};
///
/// // Create a new native transfer request
/// let request = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18";
/// let tx_req = TransactionRequest::parse(request).unwrap();
/// let native_req = tx_req.as_native().unwrap();
///
/// assert_eq!(native_req.recipient_address(), "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359");
/// assert_eq!(native_req.value_atomic().unwrap().to_string(), "1000000000000000000");
/// ```
#[derive(Debug)]
pub struct NativeRequest {
    chain_id: Option<u64>,
    recipient_address: String,
    inner: RawTransactionRequest,
}

impl TryFrom<&RawTransactionRequest> for NativeRequest {
    type Error = NativeTransferError;

    fn try_from(raw: &RawTransactionRequest) -> Result<Self, Self::Error> {
        // A native request cannot have a function name
        ensure!(raw.function_name.is_none(), HasFunctionNameSnafu);

        if let Some(parameters) = &raw.parameters {
            // A native request cannot have ABI parameters
            ensure!(
                parameters.abi_parameters().next().is_none(),
                HasAbiParametersSnafu
            );

            for p in parameters.iter() {
                let v = p.value();
                let n = v
                    .as_number()
                    .context(ParameterNotNumberSnafu { key: p.key() })?;
                let _uint256 = n
                    .as_uint256()
                    .context(ParameterInvalidSnafu { key: p.key() })?;
            }
        }

        Ok(NativeRequest {
            chain_id: if let Some(chain_id_digits) = raw.chain_id.as_ref() {
                Some(chain_id_digits.as_u64().context(ChainIdInvalidSnafu)?)
            } else {
                None
            },
            recipient_address: raw
                .target_address
                .to_erc55_validated_string()
                .context(RecipientAddressInvalidSnafu)?,
            inner: raw.clone(),
        })
    }
}

impl NativeRequest {
    /// Returns the schema prefix of the request.
    pub fn schema_prefix(&self) -> &str {
        self.inner.schema_prefix.prefix()
    }

    /// Returns whether the request has a "pay-" appendage after the schema prefix.
    pub fn has_pay(&self) -> bool {
        self.inner.schema_prefix.has_pay()
    }

    /// Returns the chain ID, if specified.
    pub fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    /// Returns the recipient address as a string.
    ///
    /// If this address is a 40 character hexadecimal address, it is known at this
    /// point to be valid according to ERC-55.
    pub fn recipient_address(&self) -> &str {
        &self.recipient_address
    }

    /// Returns the transfer value in atomic units (e.g., wei), if specified.
    pub fn value_atomic(&self) -> Option<U256> {
        // Swallowing errors with `??` is ok here as we already validated these parameters
        // to construct the request.
        let value = self.inner.parameters.as_ref()?.value().ok()??;
        value.as_uint256().ok()
    }

    /// Returns the gas limit, if specified.
    pub fn gas_limit(&self) -> Option<U256> {
        // Swallowing errors with `??` is ok here as we already validated these parameters
        // to construct the request.
        let limit = self.inner.parameters.as_ref()?.gas_limit().ok()??;
        limit.as_uint256().ok()
    }

    /// Returns the gas price, if specified.
    pub fn gas_price(&self) -> Option<U256> {
        // Swallowing errors with `??` is ok here as we already validated these parameters
        // to construct the request.
        let price = self.inner.parameters.as_ref()?.gas_price().ok()??;
        price.as_uint256().ok()
    }
}

impl core::fmt::Display for NativeRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.inner.fmt(f)
    }
}

/// An ERC-20 token transfer request.
///
/// ERC-20 transfers are EIP-681 URIs with:
/// - `function_name` == "transfer"
/// - Exactly two ABI parameters: `address` (recipient) and `uint256` (amount)
///
/// # Example
///
/// ```rust
/// use eip681::TransactionRequest;
///
/// let examples = [
///     (
///         "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000",
///         "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
///         "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
///         "1000000"
///     ),
///     (
///         "ethereum:efnx.eth/transfer?address=schellsan.eth&uint256=1000000",
///         "efnx.eth",
///         "schellsan.eth",
///         "1000000"
///     )
/// ];
///
/// for (request, token_contract_address, recipient, value) in examples {
///     let req = TransactionRequest::parse(request).unwrap();
///     let erc20_req = req.as_erc20().unwrap();
///
///     assert_eq!(erc20_req.token_contract_address(), token_contract_address);
///     assert_eq!(erc20_req.recipient_address(), recipient);
///     assert_eq!(erc20_req.value_atomic().to_string(), value);
/// }
/// ```
#[derive(Debug)]
pub struct Erc20Request {
    /// Validated token contract
    token_contract_address: String,
    /// Validated recipient
    recipient: String,
    /// Validated atomic value
    value_atomic: U256,

    /// The original parsed request that the validated values
    /// originated from.
    inner: RawTransactionRequest,
}

/// A [`RawTransactionRequest`] may be an [`Erc20Request`].
///
/// Conversion requires:
/// - `function_name` == "transfer"
/// - Exactly 2 ABI parameters: `address` and `uint256` (and in that order)
impl TryFrom<&RawTransactionRequest> for Erc20Request {
    type Error = Error;

    fn try_from(raw: &RawTransactionRequest) -> Result<Self, Self::Error> {
        // Get the function name and ensure it's "transfer"
        let fn_name = raw.function_name.as_ref().context(MissingFnSnafu)?;
        let decoded = fn_name.decode()?;
        ensure!(
            decoded == "transfer",
            FnNameSnafu {
                seen: decoded.to_string()
            }
        );

        // Check ABI parameters - must have exactly address and uint256
        let abi_params: Vec<_> = raw
            .parameters
            .iter()
            .flat_map(|p| p.abi_parameters())
            .collect();
        ensure!(
            abi_params.len() == 2,
            AbiParameterLenSnafu {
                seen: abi_params.len()
            }
        );

        // Indexing is safe here because we ensured the length == 2 above
        let (param1_ty, param1_value) = abi_params[0];
        let (param2_ty, param2_value) = abi_params[1];
        let param1 = param1_ty.to_string();
        let param2 = param2_ty.to_string();

        // We expect a specific parameter count and order
        ensure!(
            param1 == "address" && param2 == "uint256",
            AbiParameterNameSnafu { param1, param2 }
        );

        Ok(Erc20Request {
            token_contract_address: raw.target_address.to_erc55_validated_string()?,
            recipient: param1_value
                .as_address_or_ens_name()
                .context(AbiParameterAddressIsNotAnAddressSnafu)?
                .to_erc55_validated_string()?,
            value_atomic: param2_value
                .as_number()
                .context(AbiParameterUint256Snafu)?
                .as_uint256()?,
            inner: raw.clone(),
        })
    }
}

impl Erc20Request {
    /// Returns the schema prefix.
    pub fn schema_prefix(&self) -> &str {
        self.inner.schema_prefix.prefix()
    }

    /// Returns whether the request shows a "pay-" appendage after the schema prefix.
    pub fn has_pay(&self) -> bool {
        self.inner.schema_prefix.has_pay()
    }

    /// Returns the chain ID, if specified.
    pub fn chain_id(&self) -> Option<u64> {
        let digits = self.inner.chain_id.as_ref()?;
        digits.as_u64().ok()
    }

    /// Returns the ERC-20 token contract address.
    ///
    /// If this address is a 40 character hexadecimal address, it is known at this
    /// point to be valid according to ERC-55.
    pub fn token_contract_address(&self) -> &str {
        &self.token_contract_address
    }

    /// Returns the transfer recipient address.
    ///
    /// This is extracted from the `address` parameter in the ERC-20 transfer call.
    ///
    /// If this address is a 40 character hexadecimal address, it is known at this
    /// point to be valid according to ERC-55.
    pub fn recipient_address(&self) -> &str {
        &self.recipient
    }

    /// Returns the transfer value in atomic units.
    ///
    /// This is extracted from the `uint256` parameter in the ERC-20 transfer parameters.
    pub fn value_atomic(&self) -> U256 {
        self.value_atomic
    }
}

impl core::fmt::Display for Erc20Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.inner.fmt(f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_native_transfer() {
        let input = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=2.014e18";
        let request = TransactionRequest::parse(input).unwrap();

        match request {
            TransactionRequest::NativeRequest(native) => {
                assert_eq!(
                    native.recipient_address(),
                    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
                );
                assert_eq!(
                    native.value_atomic(),
                    Some(U256::from(2014000000000000000u64))
                );
            }
            _ => panic!("Expected NativeRequest"),
        }
    }

    #[test]
    fn parse_erc20_transfer() {
        let input = "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/transfer?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000";
        let request = TransactionRequest::parse(input).unwrap();

        match request {
            TransactionRequest::Erc20Request(erc20) => {
                assert_eq!(
                    erc20.token_contract_address(),
                    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                );
                assert_eq!(
                    erc20.recipient_address(),
                    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
                );
                assert_eq!(erc20.value_atomic(), U256::from(1000000));
            }
            _ => panic!("Expected Erc20Request"),
        }
    }

    #[test]
    fn parse_unrecognised() {
        // A request with a different function name
        let input = "ethereum:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48/approve?address=0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359&uint256=1000000";
        let request = TransactionRequest::parse(input).unwrap();

        assert!(matches!(request, TransactionRequest::Unrecognised(_)));
    }

    #[test]
    fn display_roundtrip() {
        let input = "ethereum:0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359?value=1e18";
        let request = TransactionRequest::parse(input).unwrap();
        let output = request.to_string();

        // Parse the output and verify it produces the same data
        let reparsed = TransactionRequest::parse(&output).unwrap();

        match (request, reparsed) {
            (TransactionRequest::NativeRequest(a), TransactionRequest::NativeRequest(b)) => {
                assert_eq!(a.recipient_address(), b.recipient_address());
                assert_eq!(a.value_atomic(), b.value_atomic());
            }
            _ => panic!("Roundtrip changed request type"),
        }
    }

    use proptest::prelude::*;

    /// Valid ERC-55 addresses for use in proptests.
    const ERC55_ADDRESSES: &[&str] = &[
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    ];

    fn arb_erc55_address() -> impl Strategy<Value = &'static str> {
        prop::sample::select(ERC55_ADDRESSES)
    }

    fn arb_schema_prefix() -> impl Strategy<Value = &'static str> {
        prop::sample::select(&["ethereum", "chaos_emerald"][..])
    }

    fn arb_u256() -> impl Strategy<Value = U256> {
        (any::<u128>(), any::<u128>())
            .prop_map(|(upper, lower)| (U256::from(upper) << 128) | U256::from(lower))
    }

    fn arb_opt_u256() -> impl Strategy<Value = Option<U256>> {
        prop::option::of(arb_u256())
    }

    fn arb_opt_chain_id() -> impl Strategy<Value = Option<u64>> {
        prop::option::of(1..=u64::MAX)
    }

    proptest! {
        #[test]
        fn from_native_request_parts_roundtrip(
            schema_prefix in arb_schema_prefix(),
            has_pay in any::<bool>(),
            chain_id in arb_opt_chain_id(),
            recipient in arb_erc55_address(),
            value in arb_opt_u256(),
            gas_limit in arb_opt_u256(),
            gas_price in arb_opt_u256(),
        ) {
            let request = TransactionRequest::from_native_request_parts(
                schema_prefix,
                has_pay,
                chain_id,
                recipient,
                value,
                gas_limit,
                gas_price,
            )
            .unwrap();

            let native = request.as_native().expect("Expected NativeRequest");
            assert_eq!(native.schema_prefix(), schema_prefix);
            assert_eq!(native.has_pay(), has_pay);
            assert_eq!(native.chain_id(), chain_id);
            assert_eq!(native.recipient_address(), recipient);
            assert_eq!(native.value_atomic(), value);
            assert_eq!(native.gas_limit(), gas_limit);
            assert_eq!(native.gas_price(), gas_price);

            // Display -> reparse roundtrip
            let output = request.to_string();
            let reparsed = TransactionRequest::parse(&output).unwrap();
            let native_b = reparsed
                .as_native()
                .expect("Roundtrip changed request type");
            assert_eq!(native.schema_prefix(), native_b.schema_prefix());
            assert_eq!(native.has_pay(), native_b.has_pay());
            assert_eq!(native.chain_id(), native_b.chain_id());
            assert_eq!(native.recipient_address(), native_b.recipient_address());
            assert_eq!(native.value_atomic(), native_b.value_atomic());
            assert_eq!(native.gas_limit(), native_b.gas_limit());
            assert_eq!(native.gas_price(), native_b.gas_price());
        }
    }

    proptest! {
        #[test]
        fn from_erc20_request_parts_roundtrip(
            schema_prefix in arb_schema_prefix(),
            has_pay in any::<bool>(),
            chain_id in arb_opt_chain_id(),
            token_contract_address in arb_erc55_address(),
            recipient_address in arb_erc55_address(),
            value in arb_u256(),
        ) {
            let request = TransactionRequest::from_erc20_request_parts(
                schema_prefix,
                has_pay,
                chain_id,
                token_contract_address,
                recipient_address,
                value,
            )
            .unwrap();

            let erc20 = request.as_erc20().expect("Expected Erc20Request");
            assert_eq!(erc20.schema_prefix(), schema_prefix);
            assert_eq!(erc20.has_pay(), has_pay);
            assert_eq!(erc20.chain_id(), chain_id);
            assert_eq!(erc20.token_contract_address(), token_contract_address);
            assert_eq!(erc20.recipient_address(), recipient_address);
            assert_eq!(erc20.value_atomic(), value);

            // Display -> reparse roundtrip
            let output = request.to_string();
            let reparsed = TransactionRequest::parse(&output).unwrap();
            let erc20_b = reparsed.as_erc20().expect("Roundtrip changed request type");
            assert_eq!(erc20.schema_prefix(), erc20_b.schema_prefix());
            assert_eq!(erc20.has_pay(), erc20_b.has_pay());
            assert_eq!(erc20.chain_id(), erc20_b.chain_id());
            assert_eq!(
                erc20.token_contract_address(),
                erc20_b.token_contract_address()
            );
            assert_eq!(erc20.recipient_address(), erc20_b.recipient_address());
            assert_eq!(erc20.value_atomic(), erc20_b.value_atomic());
        }
    }
}
