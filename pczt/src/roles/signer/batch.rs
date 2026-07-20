//! Postcard-encoded messages for batched external PCZT signing.
//!
//! Responses only represent Orchard-protocol spend authorization signatures for the
//! Orchard and Ironwood value pools. Sapling spend authorization signatures are not
//! represented.
//!
//! Request and response correlation is the responsibility of the application transport.
//! Requests encode one shared PCZT version followed by headerless, version-specific PCZT
//! payloads, so every PCZT in a batch uses the same encoding version.
//!
//! The request encoding is `"PCZB" || batch_version_le || pczt_version_le || body`, and
//! the response encoding is `"PCZS" || batch_version_le || body`. Both version fields
//! are four-byte little-endian integers, and each body uses the Postcard wire format.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::SpendAuthSignature;
use crate::Pczt;

/// The current batched PCZT signing wire version.
pub const VERSION: u32 = 1;

const REQUEST_MAGIC_BYTES: &[u8; 4] = b"PCZB"; // PCZT batch.
const RESPONSE_MAGIC_BYTES: &[u8; 4] = b"PCZS"; // PCZT signatures.

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
        let body = parse_version(bytes, REQUEST_MAGIC_BYTES)?;
        let (pczt_version, body) = parse_pczt_version(body)?;
        match pczt_version {
            crate::PCZT_VERSION_1 => {
                Ok(parse_body::<v1::BatchSignRequest<crate::v1::Pczt>>(body)?.into())
            }
            crate::PCZT_VERSION_2 => {
                Self::try_from(parse_body::<v1::BatchSignRequest<crate::v2::Pczt>>(body)?)
            }
            _ => Err(ParseError::UnknownPcztVersion(pczt_version)),
        }
    }

    /// Serializes this request using the current Postcard wire version.
    ///
    /// # Errors
    ///
    /// Returns an error if a PCZT cannot be serialized using the current PCZT
    /// encoding.
    pub fn serialize(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(serialize_request(
            crate::PCZT_VERSION_2,
            &v1::BatchSignRequest::<crate::v2::Pczt>::try_from(self)?,
        ))
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
        let body = parse_version(bytes, RESPONSE_MAGIC_BYTES)?;
        let response = parse_body::<v1::BatchSignResponse>(body)?;
        Self::try_from(response)
    }

    /// Serializes this response using the current Postcard wire version.
    pub fn serialize(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(serialize_versioned(
            RESPONSE_MAGIC_BYTES,
            &v1::BatchSignResponse::try_from(self)?,
        ))
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
    /// The bytes do not contain the expected batched PCZT signing message.
    InvalidMagic,
    /// A signature's action index cannot be represented on this platform.
    ActionIndexOutOfRange,
    /// An encoded PCZT is invalid.
    PcztParse(crate::ParseError),
    /// Bytes remain after the complete message body.
    TrailingData,
    /// The bytes are too short to contain a batched PCZT signing message header.
    TooShort,
    /// The request uses an unsupported PCZT wire version.
    UnknownPcztVersion(u32),
    /// The message uses an unsupported wire version.
    UnknownVersion(u32),
}

fn parse_version<'a>(bytes: &'a [u8], magic: &[u8; 4]) -> Result<&'a [u8], ParseError> {
    let (version, body) = crate::parse_header(bytes, magic).map_err(|e| match e {
        crate::HeaderParseError::InvalidMagic => ParseError::InvalidMagic,
        crate::HeaderParseError::TooShort => ParseError::TooShort,
    })?;
    if version != VERSION {
        return Err(ParseError::UnknownVersion(version));
    }
    Ok(body)
}

fn parse_pczt_version(bytes: &[u8]) -> Result<(u32, &[u8]), ParseError> {
    let version = bytes
        .get(..4)
        .ok_or(ParseError::TooShort)
        .map(|version| u32::from_le_bytes(version.try_into().unwrap()))?;
    Ok((version, &bytes[4..]))
}

fn parse_body<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ParseError> {
    let (value, remaining) = postcard::take_from_bytes(bytes).map_err(ParseError::Invalid)?;
    if !remaining.is_empty() {
        return Err(ParseError::TrailingData);
    }
    Ok(value)
}

fn serialize_request<T: Serialize>(pczt_version: u32, value: &T) -> Vec<u8> {
    let mut bytes = crate::serialize_header(REQUEST_MAGIC_BYTES, VERSION);
    bytes.extend_from_slice(&pczt_version.to_le_bytes());
    postcard::to_extend(value, bytes).expect("can serialize into memory")
}

fn serialize_versioned<T: Serialize>(magic: &[u8; 4], value: &T) -> Vec<u8> {
    let bytes = crate::serialize_header(magic, VERSION);
    postcard::to_extend(value, bytes).expect("can serialize into memory")
}

mod v1 {
    use super::*;
    use serde_with::serde_as;

    #[derive(Deserialize, Serialize)]
    pub(super) struct BatchSignRequest<P> {
        pub(super) pczts: Vec<P>,
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

    impl TryFrom<&super::BatchSignRequest> for BatchSignRequest<crate::v2::Pczt> {
        type Error = EncodingError;

        fn try_from(request: &super::BatchSignRequest) -> Result<Self, Self::Error> {
            Ok(Self {
                pczts: request
                    .pczts
                    .iter()
                    .cloned()
                    .map(|pczt| {
                        crate::v2::Pczt::try_from(pczt).map_err(EncodingError::PcztEncoding)
                    })
                    .collect::<Result<_, _>>()?,
            })
        }
    }

    impl From<BatchSignRequest<crate::v1::Pczt>> for super::BatchSignRequest {
        fn from(request: BatchSignRequest<crate::v1::Pczt>) -> Self {
            Self {
                pczts: request.pczts.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl TryFrom<BatchSignRequest<crate::v2::Pczt>> for super::BatchSignRequest {
        type Error = ParseError;

        fn try_from(request: BatchSignRequest<crate::v2::Pczt>) -> Result<Self, Self::Error> {
            Ok(Self {
                pczts: request
                    .pczts
                    .into_iter()
                    .map(|pczt| pczt.into_logical().map_err(ParseError::PcztParse))
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

    fn v5_pczt(expiry_height: u32) -> Pczt {
        Creator::new(
            BranchId::Nu6.into(),
            expiry_height,
            133,
            Some([0; 32]),
            Some([0; 32]),
        )
        .unwrap()
        .build()
        .unwrap()
    }

    #[test]
    fn request_round_trip() {
        let request = BatchSignRequest::new(vec![empty_pczt(10_000_000), empty_pczt(10_000_001)]);

        let expected_pczts = request
            .pczts()
            .iter()
            .cloned()
            .map(|pczt| pczt.serialize().unwrap())
            .collect::<Vec<_>>();
        let expected_body = postcard::to_allocvec(
            &v1::BatchSignRequest::<crate::v2::Pczt>::try_from(&request).unwrap(),
        )
        .unwrap();
        let encoded = request.serialize().unwrap();
        let decoded = BatchSignRequest::parse(&encoded).unwrap();

        assert_eq!(&encoded[..4], REQUEST_MAGIC_BYTES);
        assert_eq!(
            u32::from_le_bytes(encoded[4..8].try_into().unwrap()),
            VERSION
        );
        assert_eq!(
            u32::from_le_bytes(encoded[8..12].try_into().unwrap()),
            crate::PCZT_VERSION_2
        );
        assert_eq!(&encoded[12..], expected_body);
        assert_eq!(decoded.pczts().len(), expected_pczts.len());
        for (decoded, expected) in decoded.pczts().iter().zip(expected_pczts) {
            assert_eq!(decoded.clone().serialize().unwrap(), expected);
        }
    }

    #[test]
    fn request_parse_accepts_v1_pczt_payloads() {
        let pczt = v5_pczt(10_000_000);
        let expected = crate::v1::Pczt::try_from(pczt.clone()).unwrap().serialize();
        let wire = v1::BatchSignRequest {
            pczts: vec![crate::v1::Pczt::try_from(pczt).unwrap()],
        };

        let encoded = serialize_request(crate::PCZT_VERSION_1, &wire);
        let decoded = BatchSignRequest::parse(&encoded).unwrap();

        assert_eq!(decoded.pczts().len(), 1);
        assert_eq!(
            crate::v1::Pczt::try_from(decoded.pczts()[0].clone())
                .unwrap()
                .serialize(),
            expected
        );
    }

    #[test]
    fn request_parse_rejects_invalid_body() {
        let mut encoded = crate::serialize_header(REQUEST_MAGIC_BYTES, VERSION);
        encoded.extend_from_slice(&crate::PCZT_VERSION_2.to_le_bytes());
        encoded.push(1);

        assert!(matches!(
            BatchSignRequest::parse(&encoded),
            Err(ParseError::Invalid(_))
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

        assert_eq!(&encoded[..4], RESPONSE_MAGIC_BYTES);
        assert_eq!(
            u32::from_le_bytes(encoded[4..8].try_into().unwrap()),
            VERSION
        );
        assert_eq!(BatchSignResponse::parse(&encoded).unwrap(), response);
    }

    #[test]
    fn parse_rejects_unknown_version() {
        let encoded = crate::serialize_header(REQUEST_MAGIC_BYTES, VERSION + 1);
        assert!(matches!(
            BatchSignRequest::parse(&encoded),
            Err(ParseError::UnknownVersion(2))
        ));
    }

    #[test]
    fn request_parse_rejects_unknown_pczt_version_before_parsing_body() {
        let mut encoded = crate::serialize_header(REQUEST_MAGIC_BYTES, VERSION);
        encoded.extend_from_slice(&(crate::PCZT_VERSION_2 + 1).to_le_bytes());
        encoded.extend_from_slice(b"not a Postcard body");

        assert!(matches!(
            BatchSignRequest::parse(&encoded),
            Err(ParseError::UnknownPcztVersion(3))
        ));
    }

    #[test]
    fn request_and_response_use_distinct_magic_bytes() {
        let request = BatchSignRequest::new(vec![]).serialize().unwrap();
        let response = BatchSignResponse::new(vec![]).serialize().unwrap();

        assert!(matches!(
            BatchSignResponse::parse(&request),
            Err(ParseError::InvalidMagic)
        ));
        assert!(matches!(
            BatchSignRequest::parse(&response),
            Err(ParseError::InvalidMagic)
        ));
    }

    #[test]
    fn parse_rejects_short_header() {
        assert!(matches!(
            BatchSignRequest::parse(&[0; 7]),
            Err(ParseError::TooShort)
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
        let encoded = serialize_versioned(RESPONSE_MAGIC_BYTES, &wire);
        assert!(matches!(
            BatchSignResponse::parse(&encoded),
            Err(ParseError::Invalid(_))
        ));
    }
}
