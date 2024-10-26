searchState.loadedDescShard("zcash_protocol", 0, "<em>A crate for Zcash protocol constants and value types.</em>\nThe Orchard protocol\nA value pool in the Zcash protocol.\nThe Sapling protocol\nA shielded value pool.\nA Zcash shielded transfer protocol.\nThe transparent value pool\nConsensus logic and parameters.\nNetwork-specific Zcash constants.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nStructs for handling encrypted memos.\nA wrapper type representing blockchain heights.\nThe Blossom network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Blossom</code>.\nA globally-unique identifier for a set of consensus rules …\nThe Canopy network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Canopy</code>.\nThe height of the genesis block on a network.\nThe Heartwood network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Heartwood</code>.\nThe production network.\nZcash Mainnet.\nMarker struct for the production network.\nZcash Mainnet.\nThe enumeration of known Zcash networks.\nConstants associated with a given Zcash network.\nThe enumeration of known Zcash network types.\nAn event that occurs at a specified height on the Zcash …\nThe Nu5 network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Nu5</code>.\nThe Nu6 network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Nu6</code>.\nThe Overwinter network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Overwinter</code>.\nZcash consensus parameters.\nPrivate integration / regression testing, used in <code>zcashd</code>.\nThe Sapling network upgrade.\nThe consensus rules deployed by <code>NetworkUpgrade::Sapling</code>.\nThe consensus rules at the launch of Zcash.\nThe test network.\nZcash Testnet.\nMarker struct for the test network.\nZcash Testnet.\nThe “grace period” defined in ZIP 212.\nReturns the activation height for a particular network …\nReturns the human-readable prefix for Base58Check-encoded …\nReturns the human-readable prefix for Base58Check-encoded …\nReturns the human-readable prefix for Base58Check-encoded …\nThe coin type for ZEC, as defined by SLIP 44.\nReturns the branch ID corresponding to the consensus rule …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the range of heights for the consensus epoch …\nReturns the range of heights for the consensus epoch …\nReturns the human-readable prefix for Bech32-encoded …\nReturns the human-readable prefix for Bech32-encoded …\nReturns the Bech32-encoded human-readable prefix for …\nReturns the Bech32-encoded human-readable prefix for TEX …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nDetermines whether the specified network upgrade is active …\nReturns the type of network configured by this set of …\nSubtracts the provided value from this height, returning <code>H0</code>…\nConstants for the Zcash main network.\nRegtest constants\nConstants for the Zcash test network.\nThe prefix for a Base58Check-encoded mainnet <code>PublicKeyHash</code>.\nThe prefix for a Base58Check-encoded mainnet <code>ScriptHash</code>.\nThe prefix for a Base58Check-encoded mainnet Sprout …\nThe mainnet coin type for ZEC, as defined by SLIP 44.\nThe HRP for a Bech32-encoded mainnet <code>ExtendedFullViewingKey</code>…\nThe HRP for a Bech32-encoded mainnet Sapling …\nThe HRP for a Bech32-encoded mainnet Sapling <code>PaymentAddress</code>…\nThe HRP for a Bech32m-encoded mainnet ZIP 320 TEX address.\nThe prefix for a Base58Check-encoded regtest transparent …\nThe prefix for a Base58Check-encoded regtest transparent …\nThe prefix for a Base58Check-encoded regtest Sprout …\nThe regtest cointype reuses the testnet cointype\nThe HRP for a Bech32-encoded regtest Sapling …\nThe HRP for a Bech32-encoded regtest Sapling …\nThe HRP for a Bech32-encoded regtest Sapling <code>PaymentAddress</code>…\nThe HRP for a Bech32m-encoded regtest ZIP 320 TEX address.\nThe prefix for a Base58Check-encoded testnet transparent …\nThe prefix for a Base58Check-encoded testnet transparent …\nThe prefix for a Base58Check-encoded testnet Sprout …\nThe testnet coin type for ZEC, as defined by SLIP 44.\nThe HRP for a Bech32-encoded testnet Sapling …\nThe HRP for a Bech32-encoded testnet Sapling …\nThe HRP for a Bech32-encoded testnet Sapling <code>PaymentAddress</code>…\nThe HRP for a Bech32m-encoded testnet ZIP 320 TEX address.\na <code>LocalNetwork</code> setup should define the activation heights …\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nA memo field containing arbitrary bytes.\nAn empty memo field.\nErrors that may result from attempting to construct an …\nSome unknown memo format from ✨<em>the future</em>✨ that we can…\nAn unencrypted memo received alongside a shielded note in …\nThe unencrypted memo bytes received alongside a shielded …\nA memo field containing a UTF-8 string.\nType-safe wrapper around String to enforce memo length …\nReturns the raw byte array containing the memo bytes, …\nReturns a slice of the raw bytes, excluding null padding.\nCreates a <code>MemoBytes</code> indicating that no memo is present.\nSerializes the <code>Memo</code> per ZIP 302.\nReturns the argument unchanged.\nSerializes the <code>Memo</code> per ZIP 302.\nReturns the argument unchanged.\nSerializes the <code>Memo</code> per ZIP 302.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreates a <code>MemoBytes</code> from a slice, exactly as provided.\nParses a <code>Memo</code> from its ZIP 302 serialization.\nReturns a <code>Memo</code> containing the given string, or an error if …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nParses a <code>Memo</code> from its ZIP 302 serialization.\nParses a <code>Memo</code> from its ZIP 302 serialization.\nA type for balance violations in amount addition and …\nA struct that provides both the quotient and remainder of …\nReturns the identity <code>Zatoshis</code>\nA type-safe representation of a Zcash value delta, in …\nA type-safe representation of some nonnegative amount of …\nCreates a constant ZatBalance from an i64.\nCreates a constant ZatBalance from a u64.\nCreates a constant Zatoshis from a u64.\nDivides this <code>Zatoshis</code> value by the given divisor and …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nCreates an ZatBalance from an i64.\nReads an ZatBalance from a signed 64-bit little-endian …\nCreates a non-negative ZatBalance from an i64.\nCreates a Zatoshis from an i64.\nReads a non-negative ZatBalance from a signed 64-bit …\nReads a Zatoshis from a signed integer represented as a two…\nCreates an ZatBalance from a u64.\nCreates a Zatoshis from a u64.\nReads an ZatBalance from an unsigned 64-bit little-endian …\nReads an Zatoshis from an unsigned 64-bit little-endian …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns this Zatoshis as a u64.\nReturns <code>true</code> if <code>self</code> is negative and <code>false</code> if the …\nReturns <code>true</code> if <code>self</code> is positive and <code>false</code> if the …\nReturns whether or not this <code>Zatoshis</code> is positive.\nReturns whether or not this <code>Zatoshis</code> is the zero value.\nReturns the quotient portion of the value.\nReturns the remainder portion of the value.\nReturns the ZatBalance encoded as a signed 64-bit …\nReturns this Zatoshis encoded as a signed two’s …\nReturns a zero-valued ZatBalance.")