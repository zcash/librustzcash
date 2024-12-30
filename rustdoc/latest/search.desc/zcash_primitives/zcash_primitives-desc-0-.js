searchState.loadedDescShard("zcash_primitives", 0, "<em>General Zcash primitives.</em>\nStructs and methods for handling Zcash block headers.\nParsers and serializers for Zcash Merkle trees.\nStructs and methods for handling Zcash transactions.\nThe identifier for a Zcash block.\nA Zcash block header.\nThe information contained in a Zcash block header.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs a <code>BlockHash</code> from the given slice.\nReturns the hash of this header.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConstructs a <code>BlockHash</code> from the given slice.\nA wrapper type representing blockchain heights.\nThe Blossom network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Blossom</code>.\nA globally-unique identifier for a set of consensus rules …\nThe Canopy network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Canopy</code>.\nThe height of the genesis block on a network.\nThe Heartwood network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Heartwood</code>.\nThe production network.\nZcash Mainnet.\nMarker struct for the production network.\nZcash Mainnet.\nThe enumeration of known Zcash networks.\nConstants associated with a given Zcash network.\nThe enumeration of known Zcash network types.\nAn event that occurs at a specified height on the Zcash …\nThe Nu5 network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Nu5</code>.\nThe Nu6 network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Nu6</code>.\nThe Overwinter network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Overwinter</code>.\nZcash consensus parameters.\nPrivate integration / regression testing, used in <code>zcashd</code>.\nThe Sapling network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Sapling</code>.\nThe consensus rules at the launch of Zcash.\nThe test network.\nZcash Testnet.\nMarker struct for the test network.\nZcash Testnet.\nThe “grace period” defined in ZIP 212.\nReturns the activation height for a particular network …\nReturns the human-readable prefix for Base58Check-encoded …\nReturns the human-readable prefix for Base58Check-encoded …\nReturns the human-readable prefix for Base58Check-encoded …\nThe coin type for ZEC, as defined by SLIP 44.\nReturns the branch ID corresponding to the consensus rule …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the range of heights for the consensus epoch …\nReturns the range of heights for the consensus epoch …\nReturns the human-readable prefix for Bech32-encoded …\nReturns the human-readable prefix for Bech32-encoded …\nReturns the Bech32-encoded human-readable prefix for …\nReturns the Bech32-encoded human-readable prefix for TEX …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nDetermines whether the specified network upgrade is active …\nReturns the type of network configured by this set of …\nSubtracts the provided value from this height, returning <code>H0</code>…\nConstants for the Zcash main network.\nRegtest constants\nConstants for the Zcash test network.\nThe prefix for a Base58Check-encoded mainnet <code>PublicKeyHash</code>.\nThe prefix for a Base58Check-encoded mainnet <code>ScriptHash</code>.\nThe prefix for a Base58Check-encoded mainnet Sprout …\nThe mainnet coin type for ZEC, as defined by SLIP 44.\nThe HRP for a Bech32-encoded mainnet <code>ExtendedFullViewingKey</code>…\nThe HRP for a Bech32-encoded mainnet Sapling …\nThe HRP for a Bech32-encoded mainnet Sapling <code>PaymentAddress</code>…\nThe HRP for a Bech32m-encoded mainnet ZIP 320 TEX address.\nThe prefix for a Base58Check-encoded regtest transparent …\nThe prefix for a Base58Check-encoded regtest transparent …\nThe prefix for a Base58Check-encoded regtest Sprout …\nThe regtest cointype reuses the testnet cointype\nThe HRP for a Bech32-encoded regtest Sapling …\nThe HRP for a Bech32-encoded regtest Sapling …\nThe HRP for a Bech32-encoded regtest Sapling <code>PaymentAddress</code>…\nThe HRP for a Bech32m-encoded regtest ZIP 320 TEX address.\nThe prefix for a Base58Check-encoded testnet transparent …\nThe prefix for a Base58Check-encoded testnet transparent …\nThe prefix for a Base58Check-encoded testnet Sprout …\nThe testnet coin type for ZEC, as defined by SLIP 44.\nThe HRP for a Bech32-encoded testnet Sapling …\nThe HRP for a Bech32-encoded testnet Sapling …\nThe HRP for a Bech32-encoded testnet Sapling <code>PaymentAddress</code>…\nThe HRP for a Bech32m-encoded testnet ZIP 320 TEX address.\nA serialized script, used inside transparent inputs and …\nA transparent address corresponding to either a public key …\nReturns the address that this Script contains, if any.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nGenerate the <code>scriptPubKey</code> corresponding to this address.\nReturns the length of this script as encoded (including …\nA BIP44 private key at the account path level …\nA BIP44 public key at the account path level …\nThe scope used to derive keys for ephemeral transparent …\nThe scope used to derive keys for external transparent …\nAn incoming viewing key at the “ephemeral” path …\nAn incoming viewing key at the BIP44 “external” path …\nExternal outgoing viewing key used by <code>zcashd</code> for …\nThe scope used to derive keys for internal wallet …\nTrait representing a transparent “incoming viewing key”…\nAn incoming viewing key at the BIP44 “internal” path …\nInternal outgoing viewing key used for autoshielding.\nA child index for a derived transparent address.\nThe scope of a transparent key.\nReturns an arbitrary custom <code>TransparentKeyScope</code>.\nSearches the space of child indexes for an index that will …\nDerives a transparent address at the provided child index.\nDerives the BIP44 public key at the “address level” …\nDerives a transparent address at the provided child index.\nDerives the public key at the “ephemeral” path …\nDerives the BIP44 public key at the external “change …\nDerives the BIP44 private spending key for the external …\nDerives the BIP44 public key at the internal “change …\nDerives the BIP44 private spending key for the internal …\nDerives the public key corresponding to the given full BIP …\nDerives the BIP44 private spending key for the child path …\nDerives the external ovk corresponding to this transparent …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nDecodes the <code>AccountPrivKey</code> from the encoding specified for …\nParses the given ZIP 32 child index.\nPerforms derivation of the extended private key for the …\nReturns the index as a 32-bit integer.\nDerives the internal ovk corresponding to this transparent …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nDerives the internal ovk and external ovk corresponding to …\nDerives the P2PKH transparent address corresponding to the …\nReturns the <code>AccountPrivKey</code> serialized using the encoding …\nA memo field containing arbitrary bytes.\nAn empty memo field.\nErrors that may result from attempting to construct an …\nSome unknown memo format from ✨<em>the future</em>✨ that we can…\nAn unencrypted memo received alongside a shielded note in …\nThe unencrypted memo bytes received alongside a shielded …\nA memo field containing a UTF-8 string.\nType-safe wrapper around String to enforce memo length …\nReturns the raw byte array containing the memo bytes, …\nReturns a slice of the raw bytes, excluding null padding.\nCreates a <code>MemoBytes</code> indicating that no memo is present.\nSerializes the <code>Memo</code> per ZIP 302.\nReturns the argument unchanged.\nSerializes the <code>Memo</code> per ZIP 302.\nSerializes the <code>Memo</code> per ZIP 302.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreates a <code>MemoBytes</code> from a slice, exactly as provided.\nParses a <code>Memo</code> from its ZIP 302 serialization.\nReturns a <code>Memo</code> containing the given string, or an error if …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nParses a <code>Memo</code> from its ZIP 302 serialization.\nParses a <code>Memo</code> from its ZIP 302 serialization.\nA hashable node within a Merkle tree.\nReads a Merkle path from its serialized form.\nParses a node from the given byte source.\nReads a legacy <code>CommitmentTree</code> from its serialized form.\nReads an <code>IncrementalWitness</code> from its serialized form.\nReads a usize value encoded as a u64 in little-endian …\nSerializes this node.\nSerializes a legacy <code>CommitmentTree</code> as an array of bytes.\nSerializes an <code>IncrementalWitness</code> as an array of bytes.\nWrites a usize value encoded as a u64 in little-endian …\nAuthorization state for a bundle of transaction data.\n<code>Authorization</code> marker type for fully-authorized …\nA Zcash transaction.\nThe information contained in a Zcash transaction.\nThe identifier for a Zcash transaction.\nThe set of defined transaction format versions.\n<code>Authorization</code> marker type for transactions without …\nStructs for building transactions.\nStructs representing the components within Zcash …\nReturns the Zcash epoch that this transaction can be mined …\nReturns the total fees paid by the transaction, given a …\nAbstractions and types related to fee calculations.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs a <code>TransactionData</code> from its constituent parts.\nReturns <code>true</code> if this transaction version supports the …\nReturns <code>true</code> if this transaction version supports the …\nReturns <code>true</code> if this transaction version supports the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nMaps the bundles from one type to another.\nSuggests the transaction version that should be used in …\nMaps the bundles from one type to another with fallible …\nReturns the transaction version.\nAn overflow or underflow occurred when computing value …\nRules for how the builder should be configured for each …\nThe result of a transaction build operation, which …\nGenerates a <code>Transaction</code> from its inputs and outputs.\nThe transaction has inputs in excess of outputs and fees; …\nSince Blossom activation, the default transaction expiry …\nErrors that can occur during transaction construction.\nAn error occurred in computing the fees for a transaction.\nErrors that can occur during fee calculation.\nInsufficient funds were provided to the transaction …\nAn error occurred in constructing the Orchard parts of a …\nThe builder was constructed with a target height before …\nAn error occurred in adding an Orchard Output to a …\nAn error occurred in adding an Orchard Spend to a …\nThe components of a PCZT.\nThe result of <code>Builder::build_for_pczt</code>.\nReports on the progress made by the builder towards …\nAn error occurred in constructing the Sapling parts of a …\nThe builder was constructed without support for the …\nAn error occurred in constructing the transparent parts of …\nAdds an Orchard recipient to the transaction.\nAdds an Orchard note to be spent in this bundle.\nAdds a Sapling address to send funds to.\nAdds a Sapling note to be spent in this transaction.\nAdds a transparent coin to be spent in this transaction.\nAdds a transparent address to send funds to.\nBuilds a transaction from the configured spends and …\nBuilds a PCZT from the configured spends and outputs.\nReturns the number of steps completed so far while …\nReturns the total expected number of steps before this …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReports the calculated fee given the specified fee rule.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nBuild the transaction using mocked randomness and proving …\nCreates a new <code>Builder</code> targeted for inclusion in the block …\nReturns the Orchard bundle type and anchor for this …\nReturns the mapping from Orchard inputs and outputs to the …\nReturns the network parameters that the builder has been …\nReturns the Sapling bundle type and anchor for this …\nReturns the set of Sapling inputs currently committed to …\nReturns the mapping from Sapling inputs and outputs to …\nReturns the set of Sapling outputs currently set to be …\nReturns the target height of the transaction under …\nReturns the transaction that was constructed by the …\nReturns the set of transparent inputs currently committed …\nReturns the set of transparent outputs currently set to be …\nSets the notifier channel, where progress of building the …\nStructs representing the components within Zcash …\nReads an <code>orchard::Bundle</code> from a v5 transaction format.\nWrites an <code>orchard::Bundle</code> in the v5 transaction format.\nA map from one bundle authorization to another.\nConsensus rules (§7.3) &amp; (§7.4):\nConsensus rules (§4.4) &amp; (§4.5):\nReads the Sapling components of a v4 transaction.\nWrites the Sapling components of a v4 transaction.\nReturns the enforcement policy for ZIP 212 at the given …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe net value for the JoinSplit. When this is positive, …\nThe value balance for the bundle. When this is positive, …\nMarker type for a bundle that contains no authorizing …\nConstructs a fake <code>OutPoint</code> for use in tests.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the byte representation of the txid of the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns <code>true</code> if this bundle matches the definition of a …\nReturns the output index of this <code>OutPoint</code>.\nConstructs an <code>OutPoint</code> for the output at index <code>n</code> in the …\nReturns the address to which the TxOut was sent, if this …\nReturns the txid of the transaction containing this …\nThe amount of value added to or removed from the …\nA bundle could not be built because a required signing …\nA set of transparent signing keys.\nAdds a coin (the output of a previous transaction) to be …\nAdds a signing key to the set.\nBuilds a bundle containing the given inputs and outputs, …\nConstructs a new TransparentBuilder\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the list of transparent inputs that will be …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConstructs an empty set of signing keys.\nReturns the transparent outputs that will be produced by …\nThe BIP 32 derivation path at which a key can be found.\nPCZT fields that are specific to producing the transaction…\nInformation about a transparent spend within a transaction.\nAn updater for a transparent PCZT input.\nAn out-of-bounds index was provided when looking up an …\nAn invalid <code>sighash_type</code> was provided.\nAn invalid <code>value</code> was provided.\nThe Transaction Extractor role requires all <code>script_sig</code> …\n<code>partial_signatures</code> contained no signatures.\nA <code>redeem_script</code> can only be set on a P2SH coin.\nA <code>redeem_script</code> can only be set on a P2SH coin.\nInformation about a transparent output within a …\nAn updater for a transparent PCZT output.\nErrors that can occur while parsing a PCZT bundle.\nErrors that can occur while signing a transparent input in …\nErrors that can occur while finalizing the transparent …\nErrors that can occur while extracting a regular …\nAuthorizing data for a transparent bundle in a transaction …\n<code>partial_signatures</code> contained unexpected signatures.\nThe <code>script_pubkey</code> kind is unsupported.\nThe <code>script_pubkey</code> kind is unsupported.\nAn updater for a transparent PCZT bundle.\nErrors that can occur while signing a transparent input in …\nErrors that can occur while verifying a PCZT bundle.\nThe provided <code>redeem_script</code> does not match the input’s …\nThe provided <code>redeem_script</code> does not match the input’s …\nThe provided <code>sk</code> does not match any pubkey involved with …\nA map from a pubkey to the BIP 32 derivation path at which …\nA map from a pubkey to the BIP 32 derivation path at which …\nProvides read access to the bundle being updated.\nThe sequence of indices corresponding to the HD path.\nExtracts a fully authorized regular <code>Bundle</code> from this PCZT …\nExtracts the BIP 44 account index, scope, and address …\nExtracts the effects of this PCZT bundle as a regular …\nFinalizes the spends for this bundle.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nMappings of the form <code>key = RIPEMD160(SHA256(value))</code>.\nMappings of the form <code>key = SHA256(SHA256(value))</code>.\nThe transparent inputs in this bundle.\nReturns a mutable reference to the inputs in this bundle.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nThe transparent outputs in this bundle.\nParses a PCZT bundle from its component parts.\nParses a PCZT input from its component parts.\nParses a PCZT output from its component parts.\nParses a BIP 32 derivation path from its component parts.\nA map from a pubkey to a signature created by it.\nThe index of the entry in the <code>vout</code> field of the previous …\nThe ID of the previous transaction containing the …\nProprietary fields related to the transparent coin being …\nProprietary fields related to the transparent coin being …\nThe script required to spend this output, if it is P2SH.\nThe script required to spend this output, if it is P2SH.\nThe minimum block height that this input requires to be …\nThe minimum Unix timstamp that this input requires to be …\nMappings of the form <code>key = RIPEMD160(value)</code>.\nThe <code>script_pubkey</code> of the input being spent.\nThe script constraining how spending of this output must …\nA satisfying witness for the <code>script_pubkey</code> of the input …\nThe ZIP 32 seed fingerprint.\nThe sequence number of this input.\nSets the BIP 32 derivation path for the given pubkey.\nSets the BIP 32 derivation path for the given pubkey.\nStores the given value along with …\nStores the given value along with …\nStores the given proprietary value at the given key.\nStores the given proprietary value at the given key.\nSets the redeem script for this input.\nSets the redeem script for this output.\nStores the given value along with <code>key = RIPEMD160(value)</code>.\nStores the given value along with <code>key = SHA256(value)</code>.\nSets the user-facing address that the new note is being …\nMappings of the form <code>key = SHA256(value)</code>.\nThe sighash type to be used for this input.\nSigns the transparent spend with the given spend …\nUpdates the input at the given index with information …\nUpdates the input at the given index with information …\nUpdates the bundle with information provided in the given …\nThe user-facing address to which this output is being …\nThe value of the input being spent.\nThe value of the output.\nVerifies the consistency of this transparent input.\nVerifies the consistency of this transparent output.\nA trait that represents the ability to compute the fees …\nComputes the total fee required for a transaction given …\nTypes related to computation of fees and change related to …\nTypes related to implementing a <code>FeeRule</code> provides ZIP 317 …\nA fee rule that always returns a fixed fee, irrespective …\nReturns the fixed fee amount which this rule was …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCreates a new nonstandard fixed fee rule with the …\nThe size of a transparent input, or the outpoint …\nThis trait provides a minimized view of a transparent …\nThe txin size is known.\nThis trait provides a minimized view of a transparent …\nAn <code>InputSize</code> corresponding to the upper bound on the size …\nThe size of the script required to spend this input (and …\nThe previous output being spent.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nThe outpoint to which the input refers.\nReturns the script corresponding to the newly created …\nThe size of the transparent script required to spend this …\nReturns the serialized size of the txout.\nReturns the value of the output being created.\nAn overflow or underflow of amount computation occurred.\nErrors that can occur in ZIP 317 fee computation\nA <code>FeeRule</code> implementation that implements the ZIP 317 fee …\nThe minimum number of logical actions that must be paid …\nThe standard ZIP 317 marginal fee.\nThe minimum conventional fee computed from the standard …\nTransparent inputs provided to the fee calculation …\nThe standard size of a P2PKH input, in bytes, according to …\nThe standard size of a P2PKH output, in bytes, according …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the ZIP 317 number of grace actions\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the ZIP 317 marginal fee.\nConstruct a new FeeRule instance with the specified …\nReturns the ZIP 317 standard P2PKH input size\nReturns the ZIP 317 standard P2PKH output size\nConstruct a new FeeRule using the standard ZIP 317 …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nComputes the signature hash for an input to a transaction, …\nImplements the Signature Digest section of ZIP 244\nDigester which constructs a digest of only the witness …\nA TransactionDigest implementation that commits to all of …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nAbstraction over a reader which SHA-256d-hashes the data …\nAbstraction over a writer which SHA-256d-hashes the data …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nDestroy this reader and return the hash of what was read.\nDestroy this writer and return the hash of what was …\nConstruct a new <code>HashReader</code> given an existing <code>reader</code> by …\nA type-safe wrapper for account identifiers.\nA value that is needed, in addition to a spending key, in …\nA child index for a derived key.\nThe index for a particular diversifier.\nThe error type returned when a <code>DiversifierIndex</code> increment …\nA scope used for wallet-external operations, namely …\nA scope used for wallet-internal operations, such as …\nThe scope of a viewing key or address.\nThe error type returned when a checked integral type …\nThe ID for account zero (the first account).\nReturns the byte representation of the chain code, as …\nReturns the raw bytes of the diversifier index.\nSeed Fingerprints according to ZIP 32\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nParses the given ZIP 32 child index.\nConstructs a hardened <code>ChildIndex</code> from the given value.\nIncrements this index, failing on overflow.\nReturns the index as a 32-bit integer, including the …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConstructs a <code>ChainCode</code> from the given array.\nConstructs the zero index.\nReturns the next account ID in sequence, or <code>None</code> on …\nThe fingerprint for a wallet’s seed bytes, as defined in …\nReturns the argument unchanged.\nReconstructs the fingerprint from a buffer containing a …\nDerives the fingerprint of the given seed bytes.\nCalls <code>U::from(self)</code>.\nReturns the fingerprint as a byte array.")