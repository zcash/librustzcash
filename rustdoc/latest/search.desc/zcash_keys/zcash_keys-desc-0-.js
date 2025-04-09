searchState.loadedDescShard("zcash_keys", 0, "<em>A crate for Zcash key and address management.</em>\nStructs for handling supported address types.\nEncoding and decoding functions for Zcash key and address …\nHelper functions for managing light client key material.\nAn address that funds can be sent to.\nAn enumeration of protocol-level receiver types.\nA Sapling payment address.\nA ZIP 320 transparent-source-only P2PKH address, or “TEX …\nA transparent address corresponding to either a public key …\nA ZIP 316 Unified Address.\nA Unified Address.\nReturns whether or not this <code>Address</code> can receive funds in …\nReturns whether or not this receiver corresponds to <code>addr</code>, …\nAttempts to decode an <code>Address</code> value from its <code>ZcashAddress</code> …\nReturns the string encoding of this <code>UnifiedAddress</code> for the …\nConverts this <code>Address</code> to its encoded string representation.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nConstructs a Unified Address from a given set of receivers.\nReturns whether this address has an Orchard receiver.\nReturns whether this address has a Sapling receiver.\nReturns whether this address has a Transparent receiver.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReturns the Orchard receiver within this Unified Address, …\nReturns the set of receiver typecodes.\nReturns the Sapling receiver within this Unified Address, …\nReturns the transparent address corresponding to this …\nConverts this receiver to a <code>ZcashAddress</code> for the given …\nConverts this <code>Address</code> to its encoded <code>ZcashAddress</code> …\nReturns the transparent receiver within this Unified …\nAttempts to decode an <code>Address</code> value from its <code>ZcashAddress</code> …\nReturns the set of unknown receivers of the unified …\nA trait for encoding and decoding Zcash addresses.\nDecodes a Zcash address from its string representation.\nDecodes an <code>ExtendedFullViewingKey</code> from a Bech32-encoded …\nDecodes an <code>ExtendedSpendingKey</code> from a Bech32-encoded …\nDecodes an <code>ExtendedFullViewingKey</code> and the <code>NetworkType</code> that …\nDecodes a <code>PaymentAddress</code> from a Bech32-encoded string.\nDecodes a <code>TransparentAddress</code> from a Base58Check-encoded …\nEncode a Zcash address.\nWrites an <code>ExtendedFullViewingKey</code> as a Bech32-encoded …\nWrites an <code>ExtendedSpendingKey</code> as a Bech32-encoded string.\nWrites a <code>PaymentAddress</code> as a Bech32-encoded string.\nWrites a <code>PaymentAddress</code> as a Bech32-encoded string using …\nWrites a <code>TransparentAddress</code> as a Base58Check-encoded …\nWrites a <code>TransparentAddress</code> as a Base58Check-encoded …\nReturns the argument unchanged.\nReturns the argument unchanged.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConstructs a new unified address request that allows a …\nConstructs a new unified address request that allows a …\nErrors that can occur in the generation of unified …\nThe associated receiver should be included, if a …\nA type for errors that can occur when decoding keys from …\nThe space of available diversifier indices has been …\nA version identifier for the encoding of unified spending …\nThe diversifier index could not be mapped to a valid …\nThe requested diversifier index was outside the range of …\nThe key data could not be decoded from its string …\nA requested address typecode was recognized, but the …\nNo receiver of the associated type may be included in the …\nThe Orchard era begins at Orchard activation, and will end …\nAn enumeration of the ways in which a receiver may be …\nSpecification for how a unified address should be …\nA requested address typecode was not recognized, so we are …\nA receiver of the associated type is required to be …\nA Unified address cannot be generated without at least one …\nSpecification for how a unified address should be …\nA ZIP 316 unified full viewing key.\nA ZIP 316 unified incoming viewing key.\nA set of spending keys that are all associated with a …\nAttempts to derive the Unified Address for the given …\nAttempts to derive the Unified Address for the given …\nParses a <code>UnifiedFullViewingKey</code> from its ZIP 316 string …\nParses a <code>UnifiedFullViewingKey</code> from its ZIP 316 string …\nFind the Unified Address corresponding to the smallest …\nFind the Unified Address corresponding to the smallest …\nReturns the string encoding of this <code>UnifiedFullViewingKey</code> …\nReturns the string encoding of this <code>UnifiedFullViewingKey</code> …\nSearches the diversifier space starting at diversifier …\nSearches the diversifier space starting at diversifier …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nDecodes a <code>UnifiedSpendingKey</code> value from its serialized …\nReturns whether this uivk has an Orchard key item.\nReturns whether this uivk has a Sapling key item.\nReturns whether this uivk has a transparent key item.\nReturn the intersection of two requirements that chooses …\nConstructs a new unified address request that includes …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nConstruct a new unified address request from its …\nConstruct a new unified full viewing key.\nConstruct a new unified incoming viewing key.\nReturns the Orchard spending key component of this unified …\nReturns the <code>ReceiverRequirement</code> for inclusion of an …\nReturns the Orchard full viewing key component of this …\nReturns the Orchard IVK, if present.\nReturns the <code>ReceiverRequirement</code> for inclusion of a P2PKH …\nParses a <code>UnifiedFullViewingKey</code> from its ZIP 316 string …\nConvenience method for choosing a set of receiver …\nReturns the Sapling extended spending key component of …\nReturns the <code>ReceiverRequirement</code> for inclusion of a Sapling …\nReturns the Sapling diversifiable full viewing key …\nReturns the Sapling IVK, if present.\nReturns a binary encoding of this key suitable for …\nConstructs the <code>ReceiverRequirements</code> that requires a …\nDerives a Unified Incoming Viewing Key from this Unified …\nReturns the transparent component of the unified key at the\nReturns the transparent component of the unified key at the\nReturns the Transparent external IVK, if present.\nConstruct a new unified address request from its …\nA Sapling key that provides the capability to view …\nA Sapling extended spending key\nAttempt to produce a payment address given the specified …\nAttempts to produce a valid payment address for the given …\nReturns the internal address corresponding to the smallest …\nAttempts to decrypt the given address’s diversifier with …\nReturns the address with the lowest valid diversifier …\nReturns the payment address corresponding to the smallest …\nReturns the payment address corresponding to the smallest …\nDerives the child key at the given (hardened) index.\nDerives an internal spending key given an external …\nDerives an internal full viewing key used for internal …\nReturns the payment address corresponding to the specified …\nReturns the change address corresponding to the specified …\nSearch the diversifier space starting at diversifier index …\nFinds the next valid payment address starting from the …\nReturns the argument unchanged.\nReturns the argument unchanged.\nReturns the argument unchanged.\nDecodes the extended spending key from its serialized …\nParses a <code>DiversifiableFullViewingKey</code> from its raw byte …\nReturns the child key corresponding to the path derived …\nExposes the external <code>FullViewingKey</code> component of this …\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nCalls <code>U::from(self)</code>.\nReads and decodes the encoded form of the extended …\nDerives the ZIP 32 <code>ExtendedSpendingKey</code> for a given coin …\nEncodes the extended spending key to its serialized …\nReturns the raw encoding of this …\nDerives the external diversifiable incoming viewing key …\nReturns the internal <code>FullViewingKey</code> component of this …\nDerives an incoming viewing key corresponding to this full …\nDerives a nullifier-deriving key for the provided scope.\nDerives an outgoing viewing key corresponding to this full …\nWrites the encoded form of the extended spending key as …")