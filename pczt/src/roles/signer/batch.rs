//! Postcard-encoded messages for batched external PCZT signing.
//!
//! Responses only represent Orchard-protocol spend authorization signatures for the
//! Orchard and Ironwood value pools. Sapling spend authorization signatures are not
//! represented.
//!
//! Request and response correlation is the responsibility of the application transport.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::SpendAuthSignature;
use crate::Pczt;

/// The current batched PCZT signing wire version.
pub const VERSION: u32 = 1;

/// A request to sign several PCZTs as one operation.
///
/// The PCZTs retain their caller-provided order. Protocol policy such as unique
/// PCZTs, batch size, and all-or-nothing behavior is enforced by the application
/// transporting the request.
#[derive(Clone, Debug)]
pub struct BatchSignRequest {
    pczts: Vec<Pczt>,
}

impl BatchSignRequest {
    /// Constructs a batched PCZT signing request.
    pub fn new(pczts: Vec<Pczt>) -> Self {
        Self { pczts }
    }

    /// Returns the PCZTs to sign, in request order.
    pub fn pczts(&self) -> &[Pczt] {
        &self.pczts
    }

    /// Parses a Postcard-encoded batched PCZT signing request.
    ///
    /// # Errors
    ///
    /// Returns an error if the batch encoding is invalid or contains a PCZT that
    /// cannot be parsed.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let body = parse_version(bytes)?;
        Self::try_from(parse_body::<v1::BatchSignRequest>(body)?)
    }

    /// Serializes this request using the current Postcard wire version.
    ///
    /// # Errors
    ///
    /// Returns an error if a PCZT cannot be serialized using the current PCZT
    /// encoding.
    pub fn serialize(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(serialize_versioned(&v1::BatchSignRequest::try_from(self)?))
    }
}

/// The signatures produced for a [`BatchSignRequest`], in request order.
/// Entry `i` contains the signatures produced for PCZT `i` in the request.
///
/// Only Orchard and Ironwood spend authorization signatures are represented; Sapling
/// spend authorization signatures are not supported by this response format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSignResponse {
    signatures: Vec<Vec<SpendAuthSignature>>,
}

impl BatchSignResponse {
    /// Constructs a batched PCZT signing response.
    pub fn new(signatures: Vec<Vec<SpendAuthSignature>>) -> Self {
        Self { signatures }
    }

    /// Returns the Orchard and Ironwood signatures produced for each request PCZT, in
    /// request order.
    pub fn signatures(&self) -> &[Vec<SpendAuthSignature>] {
        &self.signatures
    }

    /// Parses a Postcard-encoded batched PCZT signing response.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let body = parse_version(bytes)?;
        let response = parse_body::<v1::BatchSignResponse>(body)?;
        Self::try_from(response)
    }

    /// Serializes this response using the current Postcard wire version.
    pub fn serialize(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(serialize_versioned(&v1::BatchSignResponse::try_from(self)?))
    }
}

/// Errors that can occur while encoding batched PCZT signing messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodingError {
    /// A signature's action index cannot be represented by the v1 wire format.
    ActionIndexOutOfRange,
    /// A PCZT cannot be represented by the current PCZT encoding.
    PcztEncoding(crate::EncodingError),
}

/// Errors that can occur while parsing batched PCZT signing messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The Postcard body is invalid.
    Invalid(postcard::Error),
    /// A signature's action index cannot be represented on this platform.
    ActionIndexOutOfRange,
    /// An encoded PCZT is invalid.
    PcztParse(crate::ParseError),
    /// Bytes remain after the complete message body.
    TrailingData,
    /// The message uses an unsupported wire version.
    UnknownVersion(u32),
}

fn parse_version(bytes: &[u8]) -> Result<&[u8], ParseError> {
    let (version, body) = postcard::take_from_bytes::<u32>(bytes).map_err(ParseError::Invalid)?;
    if version != VERSION {
        return Err(ParseError::UnknownVersion(version));
    }
    Ok(body)
}

fn parse_body<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ParseError> {
    let (value, remaining) = postcard::take_from_bytes(bytes).map_err(ParseError::Invalid)?;
    if !remaining.is_empty() {
        return Err(ParseError::TrailingData);
    }
    Ok(value)
}

fn serialize_versioned<T: Serialize>(value: &T) -> Vec<u8> {
    let bytes = postcard::to_allocvec(&VERSION).expect("can serialize a wire version");
    postcard::to_extend(value, bytes).expect("can serialize into memory")
}

mod v1 {
    use super::*;
    use serde_with::serde_as;

    #[derive(Deserialize, Serialize)]
    pub(super) struct BatchSignRequest {
        pczts: Vec<Vec<u8>>,
    }

    #[derive(Deserialize, Serialize)]
    pub(super) struct BatchSignResponse {
        pub(super) signatures: Vec<Vec<SpendAuthSignature>>,
    }

    #[derive(Deserialize, Serialize)]
    pub(super) enum ValuePool {
        Orchard,
        Ironwood,
    }

    #[serde_as]
    #[derive(Deserialize, Serialize)]
    pub(super) struct SpendAuthSignature {
        pub(super) value_pool: ValuePool,
        pub(super) action_index: u32,
        #[serde_as(as = "[_; 64]")]
        pub(super) signature: [u8; 64],
    }

    impl TryFrom<&super::BatchSignRequest> for BatchSignRequest {
        type Error = EncodingError;

        fn try_from(request: &super::BatchSignRequest) -> Result<Self, Self::Error> {
            Ok(Self {
                pczts: request
                    .pczts
                    .iter()
                    .cloned()
                    .map(|pczt| pczt.serialize().map_err(EncodingError::PcztEncoding))
                    .collect::<Result<_, _>>()?,
            })
        }
    }

    impl TryFrom<BatchSignRequest> for super::BatchSignRequest {
        type Error = ParseError;

        fn try_from(request: BatchSignRequest) -> Result<Self, Self::Error> {
            Ok(Self {
                pczts: request
                    .pczts
                    .into_iter()
                    .map(|pczt| crate::parse(&pczt).map_err(ParseError::PcztParse))
                    .collect::<Result<_, _>>()?,
            })
        }
    }

    impl TryFrom<&super::BatchSignResponse> for BatchSignResponse {
        type Error = EncodingError;

        fn try_from(response: &super::BatchSignResponse) -> Result<Self, Self::Error> {
            Ok(Self {
                signatures: response
                    .signatures
                    .iter()
                    .map(|signatures| {
                        signatures
                            .iter()
                            .map(SpendAuthSignature::try_from)
                            .collect::<Result<_, _>>()
                    })
                    .collect::<Result<_, EncodingError>>()?,
            })
        }
    }

    impl TryFrom<BatchSignResponse> for super::BatchSignResponse {
        type Error = ParseError;

        fn try_from(response: BatchSignResponse) -> Result<Self, Self::Error> {
            Ok(Self {
                signatures: response
                    .signatures
                    .into_iter()
                    .map(|signatures| {
                        signatures
                            .into_iter()
                            .map(super::SpendAuthSignature::try_from)
                            .collect::<Result<_, _>>()
                    })
                    .collect::<Result<_, ParseError>>()?,
            })
        }
    }

    impl TryFrom<&super::SpendAuthSignature> for SpendAuthSignature {
        type Error = EncodingError;

        fn try_from(signature: &super::SpendAuthSignature) -> Result<Self, Self::Error> {
            Ok(Self {
                value_pool: match signature.value_pool() {
                    orchard::ValuePool::Orchard => ValuePool::Orchard,
                    orchard::ValuePool::Ironwood => ValuePool::Ironwood,
                },
                action_index: u32::try_from(signature.action_index())
                    .map_err(|_| EncodingError::ActionIndexOutOfRange)?,
                signature: *signature.signature(),
            })
        }
    }

    impl TryFrom<SpendAuthSignature> for super::SpendAuthSignature {
        type Error = ParseError;

        fn try_from(signature: SpendAuthSignature) -> Result<Self, Self::Error> {
            let value_pool = match signature.value_pool {
                ValuePool::Orchard => orchard::ValuePool::Orchard,
                ValuePool::Ironwood => orchard::ValuePool::Ironwood,
            };
            let action_index = usize::try_from(signature.action_index)
                .map_err(|_| ParseError::ActionIndexOutOfRange)?;
            Ok(Self::from_parts(
                value_pool,
                action_index,
                signature.signature,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_with::serde_as;
    use zcash_protocol::consensus::BranchId;

    use crate::roles::creator::Creator;

    fn empty_pczt(expiry_height: u32) -> Pczt {
        Creator::new(BranchId::Nu6_3.into(), expiry_height, 133, None, None)
            .unwrap()
            .build()
            .unwrap()
    }

    fn serialize_pczts(pczts: &[Pczt]) -> Vec<Vec<u8>> {
        pczts
            .iter()
            .cloned()
            .map(|pczt| pczt.serialize().unwrap())
            .collect()
    }

    #[test]
    fn request_round_trip() {
        let request = BatchSignRequest::new(vec![empty_pczt(10_000_000), empty_pczt(10_000_001)]);

        let expected_pczts = serialize_pczts(request.pczts());
        let encoded = request.serialize().unwrap();
        let decoded = BatchSignRequest::parse(&encoded).unwrap();

        assert_eq!(serialize_pczts(decoded.pczts()), expected_pczts);
    }

    #[test]
    fn request_parse_rejects_invalid_pczt() {
        #[derive(Serialize)]
        struct RawBatchSignRequest {
            pczts: Vec<Vec<u8>>,
        }

        let encoded = serialize_versioned(&RawBatchSignRequest {
            pczts: vec![b"not-a-pczt".to_vec()],
        });
        assert!(matches!(
            BatchSignRequest::parse(&encoded),
            Err(ParseError::PcztParse(crate::ParseError::NotPczt))
        ));
    }

    #[test]
    fn response_round_trip() {
        let response = BatchSignResponse::new(vec![
            vec![SpendAuthSignature::from_parts(
                orchard::ValuePool::Orchard,
                0,
                [0x11; 64],
            )],
            vec![SpendAuthSignature::from_parts(
                orchard::ValuePool::Ironwood,
                12,
                [0x22; 64],
            )],
        ]);

        let encoded = response.serialize().unwrap();
        assert_eq!(BatchSignResponse::parse(&encoded).unwrap(), response);
    }

    #[test]
    fn parse_rejects_unknown_version() {
        assert!(matches!(
            BatchSignRequest::parse(&[2, 0, 0]),
            Err(ParseError::UnknownVersion(2))
        ));
    }

    #[test]
    fn parse_rejects_trailing_data() {
        let mut encoded = BatchSignRequest::new(vec![]).serialize().unwrap();
        encoded.push(0);
        assert!(matches!(
            BatchSignRequest::parse(&encoded),
            Err(ParseError::TrailingData)
        ));
    }

    #[test]
    fn response_parse_rejects_unknown_value_pool() {
        #[derive(Serialize)]
        struct RawBatchSignResponse {
            signatures: Vec<Vec<RawSpendAuthSignature>>,
        }

        #[serde_as]
        #[derive(Serialize)]
        struct RawSpendAuthSignature {
            value_pool: u8,
            action_index: u32,
            #[serde_as(as = "[_; 64]")]
            signature: [u8; 64],
        }

        let wire = RawBatchSignResponse {
            signatures: vec![vec![RawSpendAuthSignature {
                value_pool: 2,
                action_index: 0,
                signature: [0; 64],
            }]],
        };
        let encoded = serialize_versioned(&wire);
        assert!(matches!(
            BatchSignResponse::parse(&encoded),
            Err(ParseError::Invalid(_))
        ));
    }
}
