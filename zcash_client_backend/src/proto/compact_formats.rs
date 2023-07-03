/// ChainMetadata represents information about the state of the chain as of a given block.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChainMetadata {
    /// the size of the Sapling note commitment tree as of the end of this block
    #[prost(uint32, tag = "1")]
    pub sapling_commitment_tree_size: u32,
    /// the size of the Orchard note commitment tree as of the end of this block
    #[prost(uint32, tag = "2")]
    pub orchard_commitment_tree_size: u32,
}
/// CompactBlock is a packaging of ONLY the data from a block that's needed to:
///    1. Detect a payment to your shielded Sapling address
///    2. Detect a spend of your shielded Sapling notes
///    3. Update your witnesses to generate new Sapling spend proofs.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactBlock {
    /// the version of this wire format, for storage
    #[prost(uint32, tag = "1")]
    pub proto_version: u32,
    /// the height of this block
    #[prost(uint64, tag = "2")]
    pub height: u64,
    /// the ID (hash) of this block, same as in block explorers
    #[prost(bytes = "vec", tag = "3")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    /// the ID (hash) of this block's predecessor
    #[prost(bytes = "vec", tag = "4")]
    pub prev_hash: ::prost::alloc::vec::Vec<u8>,
    /// Unix epoch time when the block was mined
    #[prost(uint32, tag = "5")]
    pub time: u32,
    /// (hash, prevHash, and time) OR (full header)
    #[prost(bytes = "vec", tag = "6")]
    pub header: ::prost::alloc::vec::Vec<u8>,
    /// zero or more compact transactions from this block
    #[prost(message, repeated, tag = "7")]
    pub vtx: ::prost::alloc::vec::Vec<CompactTx>,
    /// information about the state of the chain as of this block
    #[prost(message, optional, tag = "8")]
    pub chain_metadata: ::core::option::Option<ChainMetadata>,
}
/// CompactTx contains the minimum information for a wallet to know if this transaction
/// is relevant to it (either pays to it or spends from it) via shielded elements
/// only. This message will not encode a transparent-to-transparent transaction.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactTx {
    /// Index and hash will allow the receiver to call out to chain
    /// explorers or other data structures to retrieve more information
    /// about this transaction.
    ///
    /// the index within the full block
    #[prost(uint64, tag = "1")]
    pub index: u64,
    /// the ID (hash) of this transaction, same as in block explorers
    #[prost(bytes = "vec", tag = "2")]
    pub hash: ::prost::alloc::vec::Vec<u8>,
    /// The transaction fee: present if server can provide. In the case of a
    /// stateless server and a transaction with transparent inputs, this will be
    /// unset because the calculation requires reference to prior transactions.
    /// If there are no transparent inputs, the fee will be calculable as:
    ///     valueBalanceSapling + valueBalanceOrchard + sum(vPubNew) - sum(vPubOld) - sum(tOut)
    #[prost(uint32, tag = "3")]
    pub fee: u32,
    #[prost(message, repeated, tag = "4")]
    pub spends: ::prost::alloc::vec::Vec<CompactSaplingSpend>,
    #[prost(message, repeated, tag = "5")]
    pub outputs: ::prost::alloc::vec::Vec<CompactSaplingOutput>,
    #[prost(message, repeated, tag = "6")]
    pub actions: ::prost::alloc::vec::Vec<CompactOrchardAction>,
}
/// CompactSaplingSpend is a Sapling Spend Description as described in 7.3 of the Zcash
/// protocol specification.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactSaplingSpend {
    /// nullifier (see the Zcash protocol specification)
    #[prost(bytes = "vec", tag = "1")]
    pub nf: ::prost::alloc::vec::Vec<u8>,
}
/// output encodes the `cmu` field, `ephemeralKey` field, and a 52-byte prefix of the
/// `encCiphertext` field of a Sapling Output Description. These fields are described in
/// section 7.4 of the Zcash protocol spec:
/// <https://zips.z.cash/protocol/protocol.pdf#outputencodingandconsensus>
/// Total size is 116 bytes.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactSaplingOutput {
    /// note commitment u-coordinate
    #[prost(bytes = "vec", tag = "1")]
    pub cmu: ::prost::alloc::vec::Vec<u8>,
    /// ephemeral public key
    #[prost(bytes = "vec", tag = "2")]
    pub ephemeral_key: ::prost::alloc::vec::Vec<u8>,
    /// first 52 bytes of ciphertext
    #[prost(bytes = "vec", tag = "3")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
}
/// <https://github.com/zcash/zips/blob/main/zip-0225.rst#orchard-action-description-orchardaction>
/// (but not all fields are needed)
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CompactOrchardAction {
    /// \[32\] The nullifier of the input note
    #[prost(bytes = "vec", tag = "1")]
    pub nullifier: ::prost::alloc::vec::Vec<u8>,
    /// \[32\] The x-coordinate of the note commitment for the output note
    #[prost(bytes = "vec", tag = "2")]
    pub cmx: ::prost::alloc::vec::Vec<u8>,
    /// \[32\] An encoding of an ephemeral Pallas public key
    #[prost(bytes = "vec", tag = "3")]
    pub ephemeral_key: ::prost::alloc::vec::Vec<u8>,
    /// \[52\] The first 52 bytes of the encCiphertext field
    #[prost(bytes = "vec", tag = "4")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
}
