//! Parser for [EIP-681](https://eips.ethereum.org/EIPS/eip-681) transaction requests.
//!
//! The top level of the parsing tree is the type [`EthereumTransactionRequest`].
//!
//! ## ABNF Syntax
//!
//! ```abnf
//! request          = schema_prefix target_address [ "@" chain_id ] [ "/" function_name ] [ "?" parameters ]
//! schema_prefix    = "ethereum" ":" [ "pay-" ]
//! target_address   = ethereum_address
//! chain_id         = 1*DIGIT
//! function_name    = STRING
//! ethereum_address = ( "0x" 40*HEXDIG ) / ENS_NAME
//! parameters       = parameter *( "&" parameter )
//! parameter        = key "=" value
//! key              = "value" / "gas" / "gasLimit" / "gasPrice" / TYPE
//! value            = number / ethereum_address / STRING
//! number           = [ "-" / "+" ] *DIGIT [ "." 1*DIGIT ] [ ( "e" / "E" ) [ 1*DIGIT ] ]
//! ```
//!
//! Where `TYPE` is a standard ABI type name, as defined in Ethereum Contract
//! ABI specification. `STRING` is a URL-encoded unicode string of arbitrary
//! length, where delimiters and the percentage symbol (%) are mandatorily
//! hex-encoded with a % prefix.
//!
//! For the syntax of `ENS_NAME`, please consult
//! [ERC-137](https://eips.ethereum.org/EIPS/eip-137) defining Ethereum Name Service.
//!
//! See
//! [ABNF core rules](https://en.wikipedia.org/wiki/Augmented_Backus%E2%80%93Naur_form#Core_rules)
//! for general information about the `ABNF` format.

pub mod error;
mod parse;
pub use parse::{
    Digits, EnsName, EthereumAbiTypeName, EthereumAddress, EthereumTransactionRequest, HexDigits,
    Number, Parameter, Parameters, SchemaPrefix, UrlEncodedUnicodeString, Value,
};
