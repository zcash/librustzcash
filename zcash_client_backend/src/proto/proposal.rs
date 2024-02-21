/// A data structure that describes a series of transactions to be created.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Proposal {
    /// The version of this serialization format.
    #[prost(uint32, tag = "1")]
    pub proto_version: u32,
    /// The fee rule used in constructing this proposal
    #[prost(enumeration = "FeeRule", tag = "2")]
    pub fee_rule: i32,
    /// The target height for which the proposal was constructed
    ///
    /// The chain must contain at least this many blocks in order for the proposal to
    /// be executed.
    #[prost(uint32, tag = "3")]
    pub min_target_height: u32,
    /// The series of transactions to be created.
    #[prost(message, repeated, tag = "4")]
    pub steps: ::prost::alloc::vec::Vec<ProposalStep>,
}
/// A data structure that describes the inputs to be consumed and outputs to
/// be produced in a proposed transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalStep {
    /// ZIP 321 serialized transaction request
    #[prost(string, tag = "1")]
    pub transaction_request: ::prost::alloc::string::String,
    /// The vector of selected payment index / output pool mappings. Payment index
    /// 0 corresponds to the payment with no explicit index.
    #[prost(message, repeated, tag = "2")]
    pub payment_output_pools: ::prost::alloc::vec::Vec<PaymentOutputPool>,
    /// The anchor height to be used in creating the transaction, if any.
    /// Setting the anchor height to zero will disallow the use of any shielded
    /// inputs.
    #[prost(uint32, tag = "3")]
    pub anchor_height: u32,
    /// The inputs to be used in creating the transaction.
    #[prost(message, repeated, tag = "4")]
    pub inputs: ::prost::alloc::vec::Vec<ProposedInput>,
    /// The total value, fee value, and change outputs of the proposed
    /// transaction
    #[prost(message, optional, tag = "5")]
    pub balance: ::core::option::Option<TransactionBalance>,
    /// A flag indicating whether the step is for a shielding transaction,
    /// used for determining which OVK to select for wallet-internal outputs.
    #[prost(bool, tag = "6")]
    pub is_shielding: bool,
}
/// A mapping from ZIP 321 payment index to the output pool that has been chosen
/// for that payment, based upon the payment address and the selected inputs to
/// the transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PaymentOutputPool {
    #[prost(uint32, tag = "1")]
    pub payment_index: u32,
    #[prost(enumeration = "ValuePool", tag = "2")]
    pub value_pool: i32,
}
/// The unique identifier and value for each proposed input that does not
/// require a back-reference to a prior step of the proposal.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ReceivedOutput {
    #[prost(bytes = "vec", tag = "1")]
    pub txid: ::prost::alloc::vec::Vec<u8>,
    #[prost(enumeration = "ValuePool", tag = "2")]
    pub value_pool: i32,
    #[prost(uint32, tag = "3")]
    pub index: u32,
    #[prost(uint64, tag = "4")]
    pub value: u64,
}
/// A reference a payment in a prior step of the proposal. This payment must
/// belong to the wallet.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PriorStepOutput {
    #[prost(uint32, tag = "1")]
    pub step_index: u32,
    #[prost(uint32, tag = "2")]
    pub payment_index: u32,
}
/// A reference a change output from a prior step of the proposal.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PriorStepChange {
    #[prost(uint32, tag = "1")]
    pub step_index: u32,
    #[prost(uint32, tag = "2")]
    pub change_index: u32,
}
/// The unique identifier and value for an input to be used in the transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposedInput {
    #[prost(oneof = "proposed_input::Value", tags = "1, 2, 3")]
    pub value: ::core::option::Option<proposed_input::Value>,
}
/// Nested message and enum types in `ProposedInput`.
pub mod proposed_input {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Value {
        #[prost(message, tag = "1")]
        ReceivedOutput(super::ReceivedOutput),
        #[prost(message, tag = "2")]
        PriorStepOutput(super::PriorStepOutput),
        #[prost(message, tag = "3")]
        PriorStepChange(super::PriorStepChange),
    }
}
/// The proposed change outputs and fee value.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransactionBalance {
    /// A list of change output values.
    #[prost(message, repeated, tag = "1")]
    pub proposed_change: ::prost::alloc::vec::Vec<ChangeValue>,
    /// The fee to be paid by the proposed transaction, in zatoshis.
    #[prost(uint64, tag = "2")]
    pub fee_required: u64,
}
/// A proposed change output. If the transparent value pool is selected,
/// the `memo` field must be null.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChangeValue {
    /// The value of a change output to be created, in zatoshis.
    #[prost(uint64, tag = "1")]
    pub value: u64,
    /// The value pool in which the change output should be created.
    #[prost(enumeration = "ValuePool", tag = "2")]
    pub value_pool: i32,
    /// The optional memo that should be associated with the newly created change output.
    /// Memos must not be present for transparent change outputs.
    #[prost(message, optional, tag = "3")]
    pub memo: ::core::option::Option<MemoBytes>,
}
/// An object wrapper for memo bytes, to facilitate representing the
/// `change_memo == None` case.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MemoBytes {
    #[prost(bytes = "vec", tag = "1")]
    pub value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ValuePool {
    /// Protobuf requires that enums have a zero discriminant as the default
    /// value. However, we need to require that a known value pool is selected,
    /// and we do not want to fall back to any default, so sending the
    /// PoolNotSpecified value will be treated as an error.
    PoolNotSpecified = 0,
    /// The transparent value pool (P2SH is not distinguished from P2PKH)
    Transparent = 1,
    /// The Sapling value pool
    Sapling = 2,
    /// The Orchard value pool
    Orchard = 3,
}
impl ValuePool {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ValuePool::PoolNotSpecified => "PoolNotSpecified",
            ValuePool::Transparent => "Transparent",
            ValuePool::Sapling => "Sapling",
            ValuePool::Orchard => "Orchard",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PoolNotSpecified" => Some(Self::PoolNotSpecified),
            "Transparent" => Some(Self::Transparent),
            "Sapling" => Some(Self::Sapling),
            "Orchard" => Some(Self::Orchard),
            _ => None,
        }
    }
}
/// The fee rule used in constructing a Proposal
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FeeRule {
    /// Protobuf requires that enums have a zero discriminant as the default
    /// value. However, we need to require that a known fee rule is selected,
    /// and we do not want to fall back to any default, so sending the
    /// FeeRuleNotSpecified value will be treated as an error.
    NotSpecified = 0,
    /// 10000 ZAT
    PreZip313 = 1,
    /// 1000 ZAT
    Zip313 = 2,
    /// MAX(10000, 5000 * logical_actions) ZAT
    Zip317 = 3,
}
impl FeeRule {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            FeeRule::NotSpecified => "FeeRuleNotSpecified",
            FeeRule::PreZip313 => "PreZip313",
            FeeRule::Zip313 => "Zip313",
            FeeRule::Zip317 => "Zip317",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FeeRuleNotSpecified" => Some(Self::NotSpecified),
            "PreZip313" => Some(Self::PreZip313),
            "Zip313" => Some(Self::Zip313),
            "Zip317" => Some(Self::Zip317),
            _ => None,
        }
    }
}
