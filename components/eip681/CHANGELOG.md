# Changelog

All notable changes to this library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this library adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Future releases are
indicated by the `PLANNED` status in order to make it possible to correctly
represent the transitive `semver` implications of changes within the enclosing
workspace.

## [Unreleased]

### Added
- `error::ParseError::NumberMissingDigits` (non-exhaustive): emitted internally
  by `Value::parse` when a `Number` candidate has no mantissa digits.
- `NativeRequest::from_parts`
- `Erc20Request::from_parts`
- `error::Error::AmbiguousEncoding`
- `testing::arb_u256` (behind the `test-dependencies` feature)

### Removed
- `TransactionRequest::from_native_request_parts` and
  `TransactionRequest::from_erc20_request_parts`. Use `NativeRequest::from_parts`
  and `Erc20Request::from_parts` instead, wrapping the result in the
  corresponding `TransactionRequest` variant where a `TransactionRequest` is
  needed. The new constructors return an error for any part that is not
  exactly one valid value of its kind, where the removed constructors could
  return `Ok(TransactionRequest::Unrecognised(..))` or a request of the other
  kind.

### Fixed
- `Value::parse` no longer classifies inputs that lack any integer digits and
  any decimal part (e.g. the lone alphabetic inputs `"e"` and `"E"`) as
  `Value::Number`. Such inputs now correctly parse as `Value::String`, matching
  the intent of the EIP-681 `value = number / ethereum_address / STRING`
  grammar. `Number::parse` itself remains permissive for its standalone
  callers.
- `parse::AddressOrEnsName::to_erc55_validated_string` now returns
  `error::ValidationError::IncorrectEthAddressLen` for a hex address that is
  not 40 digits long, instead of returning it unvalidated.
  `TransactionRequest::parse` therefore no longer produces a `NativeRequest` or
  `Erc20Request` for such an address.

## [0.1.0] - Tue 31 March 2026

- Initial release!
