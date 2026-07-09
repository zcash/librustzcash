//! Postcard-encoded messages for batched external PCZT signing.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::OrchardSpendAuthSignature;

/// The current batched PCZT signing wire version.
pub const VERSION: u32 = 1;

/// A request to sign several PCZTs as one operation.
///
/// Protocol policy such as non-empty identifiers, unique messages, batch size,
/// and all-or-nothing behavior is enforced by the application transporting the
/// request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSignRequest {
    request_id: Vec<u8>,
    messages: Vec<BatchSignRequestMessage>,
}

impl BatchSignRequest {
    /// Constructs a batched PCZT signing request.
    pub fn new(request_id: Vec<u8>, messages: Vec<BatchSignRequestMessage>) -> Self {
        Self {
            request_id,
            messages,
        }
    }

    /// Returns the identifier that correlates this request with its response.
    pub fn request_id(&self) -> &[u8] {
        &self.request_id
    }

    /// Returns the PCZT messages to sign.
    pub fn messages(&self) -> &[BatchSignRequestMessage] {
        &self.messages
    }

    /// Parses a Postcard-encoded batched PCZT signing request.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let body = parse_version(bytes)?;
        postcard::from_bytes::<v1::BatchSignRequest>(body)
            .map(Self::from)
            .map_err(ParseError::Invalid)
    }

    /// Serializes this request using the current Postcard wire version.
    pub fn serialize(&self) -> Vec<u8> {
        serialize_versioned(&v1::BatchSignRequest::from(self))
    }
}

/// One PCZT in a [`BatchSignRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSignRequestMessage {
    message_id: Vec<u8>,
    pczt: Vec<u8>,
}

impl BatchSignRequestMessage {
    /// Constructs a PCZT signing message.
    pub fn new(message_id: Vec<u8>, pczt: Vec<u8>) -> Self {
        Self { message_id, pczt }
    }

    /// Returns the identifier that correlates this message with its signatures.
    pub fn message_id(&self) -> &[u8] {
        &self.message_id
    }

    /// Returns the encoded PCZT to sign.
    pub fn pczt(&self) -> &[u8] {
        &self.pczt
    }
}

/// The signatures produced for a [`BatchSignRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSignResponse {
    request_id: Vec<u8>,
    results: Vec<BatchSignResponseMessage>,
}

impl BatchSignResponse {
    /// Constructs a batched PCZT signing response.
    pub fn new(request_id: Vec<u8>, results: Vec<BatchSignResponseMessage>) -> Self {
        Self {
            request_id,
            results,
        }
    }

    /// Returns the identifier of the request answered by this response.
    pub fn request_id(&self) -> &[u8] {
        &self.request_id
    }

    /// Returns the signatures produced for each request message.
    pub fn results(&self) -> &[BatchSignResponseMessage] {
        &self.results
    }

    /// Parses a Postcard-encoded batched PCZT signing response.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let body = parse_version(bytes)?;
        let response =
            postcard::from_bytes::<v1::BatchSignResponse>(body).map_err(ParseError::Invalid)?;
        Self::try_from(response)
    }

    /// Serializes this response using the current Postcard wire version.
    pub fn serialize(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(serialize_versioned(&v1::BatchSignResponse::try_from(self)?))
    }
}

/// The signatures produced for one message in a [`BatchSignRequest`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSignResponseMessage {
    message_id: Vec<u8>,
    signatures: Vec<OrchardSpendAuthSignature>,
}

impl BatchSignResponseMessage {
    /// Constructs a per-message signing response.
    pub fn new(message_id: Vec<u8>, signatures: Vec<OrchardSpendAuthSignature>) -> Self {
        Self {
            message_id,
            signatures,
        }
    }

    /// Returns the identifier of the request message these signatures answer.
    pub fn message_id(&self) -> &[u8] {
        &self.message_id
    }

    /// Returns the produced Orchard-protocol spend authorization signatures.
    pub fn signatures(&self) -> &[OrchardSpendAuthSignature] {
        &self.signatures
    }
}

/// Errors that can occur while encoding batched PCZT signing messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodingError {
    /// A signature's action index cannot be represented by the v1 wire format.
    ActionIndexOutOfRange,
}

/// Errors that can occur while parsing batched PCZT signing messages.
#[derive(Debug)]
#[non_exhaustive]
pub enum ParseError {
    /// The Postcard body is invalid.
    Invalid(postcard::Error),
    /// A signature contains an unknown Orchard-protocol value pool tag.
    InvalidValuePool(u8),
    /// A signature's action index cannot be represented on this platform.
    ActionIndexOutOfRange,
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

fn serialize_versioned<T: Serialize>(value: &T) -> Vec<u8> {
    let bytes = postcard::to_allocvec(&VERSION).expect("can serialize a wire version");
    postcard::to_extend(value, bytes).expect("can serialize into memory")
}

mod v1 {
    use super::*;
    use serde_with::serde_as;

    #[derive(Deserialize, Serialize)]
    pub(super) struct BatchSignRequest {
        request_id: Vec<u8>,
        messages: Vec<BatchSignRequestMessage>,
    }

    #[derive(Deserialize, Serialize)]
    struct BatchSignRequestMessage {
        message_id: Vec<u8>,
        pczt: Vec<u8>,
    }

    #[derive(Deserialize, Serialize)]
    pub(super) struct BatchSignResponse {
        pub(super) request_id: Vec<u8>,
        pub(super) results: Vec<BatchSignResponseMessage>,
    }

    #[derive(Deserialize, Serialize)]
    pub(super) struct BatchSignResponseMessage {
        pub(super) message_id: Vec<u8>,
        pub(super) signatures: Vec<OrchardSpendAuthSignature>,
    }

    #[serde_as]
    #[derive(Deserialize, Serialize)]
    pub(super) struct OrchardSpendAuthSignature {
        pub(super) value_pool: u8,
        pub(super) action_index: u32,
        #[serde_as(as = "[_; 64]")]
        pub(super) signature: [u8; 64],
    }

    impl From<&super::BatchSignRequest> for BatchSignRequest {
        fn from(request: &super::BatchSignRequest) -> Self {
            Self {
                request_id: request.request_id.clone(),
                messages: request
                    .messages
                    .iter()
                    .map(|message| BatchSignRequestMessage {
                        message_id: message.message_id.clone(),
                        pczt: message.pczt.clone(),
                    })
                    .collect(),
            }
        }
    }

    impl From<BatchSignRequest> for super::BatchSignRequest {
        fn from(request: BatchSignRequest) -> Self {
            Self {
                request_id: request.request_id,
                messages: request
                    .messages
                    .into_iter()
                    .map(|message| super::BatchSignRequestMessage {
                        message_id: message.message_id,
                        pczt: message.pczt,
                    })
                    .collect(),
            }
        }
    }

    impl TryFrom<&super::BatchSignResponse> for BatchSignResponse {
        type Error = EncodingError;

        fn try_from(response: &super::BatchSignResponse) -> Result<Self, Self::Error> {
            Ok(Self {
                request_id: response.request_id.clone(),
                results: response
                    .results
                    .iter()
                    .map(|result| {
                        Ok(BatchSignResponseMessage {
                            message_id: result.message_id.clone(),
                            signatures: result
                                .signatures
                                .iter()
                                .map(OrchardSpendAuthSignature::try_from)
                                .collect::<Result<_, _>>()?,
                        })
                    })
                    .collect::<Result<_, EncodingError>>()?,
            })
        }
    }

    impl TryFrom<BatchSignResponse> for super::BatchSignResponse {
        type Error = ParseError;

        fn try_from(response: BatchSignResponse) -> Result<Self, Self::Error> {
            Ok(Self {
                request_id: response.request_id,
                results: response
                    .results
                    .into_iter()
                    .map(|result| {
                        Ok(super::BatchSignResponseMessage {
                            message_id: result.message_id,
                            signatures: result
                                .signatures
                                .into_iter()
                                .map(super::OrchardSpendAuthSignature::try_from)
                                .collect::<Result<_, _>>()?,
                        })
                    })
                    .collect::<Result<_, ParseError>>()?,
            })
        }
    }

    impl TryFrom<&super::OrchardSpendAuthSignature> for OrchardSpendAuthSignature {
        type Error = EncodingError;

        fn try_from(signature: &super::OrchardSpendAuthSignature) -> Result<Self, Self::Error> {
            Ok(Self {
                value_pool: match signature.value_pool() {
                    orchard::ValuePool::Orchard => 0,
                    orchard::ValuePool::Ironwood => 1,
                },
                action_index: u32::try_from(signature.action_index())
                    .map_err(|_| EncodingError::ActionIndexOutOfRange)?,
                signature: *signature.signature(),
            })
        }
    }

    impl TryFrom<OrchardSpendAuthSignature> for super::OrchardSpendAuthSignature {
        type Error = ParseError;

        fn try_from(signature: OrchardSpendAuthSignature) -> Result<Self, Self::Error> {
            let value_pool = match signature.value_pool {
                0 => orchard::ValuePool::Orchard,
                1 => orchard::ValuePool::Ironwood,
                value_pool => return Err(ParseError::InvalidValuePool(value_pool)),
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

    #[test]
    fn request_round_trip() {
        let request = BatchSignRequest::new(
            b"request".to_vec(),
            vec![
                BatchSignRequestMessage::new(b"first".to_vec(), b"pczt-1".to_vec()),
                BatchSignRequestMessage::new(b"second".to_vec(), b"pczt-2".to_vec()),
            ],
        );

        let encoded = request.serialize();
        assert_eq!(BatchSignRequest::parse(&encoded).unwrap(), request);
        assert_eq!(
            hex::encode(encoded),
            "010772657175657374020566697273740670637a742d31067365636f6e640670637a742d32"
        );
    }

    #[test]
    fn response_round_trip() {
        let response = BatchSignResponse::new(
            b"request".to_vec(),
            vec![BatchSignResponseMessage::new(
                b"first".to_vec(),
                vec![
                    OrchardSpendAuthSignature::from_parts(
                        orchard::ValuePool::Orchard,
                        0,
                        [0x11; 64],
                    ),
                    OrchardSpendAuthSignature::from_parts(
                        orchard::ValuePool::Ironwood,
                        12,
                        [0x22; 64],
                    ),
                ],
            )],
        );

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
    fn response_parse_rejects_unknown_value_pool() {
        let wire = v1::BatchSignResponse {
            request_id: vec![],
            results: vec![v1::BatchSignResponseMessage {
                message_id: vec![],
                signatures: vec![v1::OrchardSpendAuthSignature {
                    value_pool: 2,
                    action_index: 0,
                    signature: [0; 64],
                }],
            }],
        };
        let encoded = serialize_versioned(&wire);
        assert!(matches!(
            BatchSignResponse::parse(&encoded),
            Err(ParseError::InvalidValuePool(2))
        ));
    }
}
