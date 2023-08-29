//! Helper functions for managing light client key material.
use orchard;
use zcash_address::unified::{self, Container, Encoding};
use zcash_primitives::{
    consensus,
    zip32::{AccountId, DiversifierIndex},
};

use crate::address::UnifiedAddress;

#[cfg(feature = "transparent-inputs")]
use {
    std::convert::TryInto,
    zcash_primitives::legacy::keys::{self as legacy, IncomingViewingKey},
};

#[cfg(all(feature = "test-dependencies", feature = "transparent-inputs"))]
use zcash_primitives::legacy::TransparentAddress;

#[cfg(feature = "unstable")]
use {
    byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt},
    std::convert::TryFrom,
    std::io::{Read, Write},
    zcash_address::unified::Typecode,
    zcash_encoding::CompactSize,
    zcash_primitives::consensus::BranchId,
};

pub mod sapling {
    pub use zcash_primitives::zip32::sapling::{
        DiversifiableFullViewingKey, ExtendedFullViewingKey, ExtendedSpendingKey,
    };
    use zcash_primitives::zip32::{AccountId, ChildIndex};

    /// Derives the ZIP 32 [`ExtendedSpendingKey`] for a given coin type and account from the
    /// given seed.
    ///
    /// # Panics
    ///
    /// Panics if `seed` is shorter than 32 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use zcash_primitives::{
    ///     constants::testnet::COIN_TYPE,
    ///     zip32::AccountId,
    /// };
    /// use zcash_client_backend::{
    ///     keys::sapling,
    /// };
    ///
    /// let extsk = sapling::spending_key(&[0; 32][..], COIN_TYPE, AccountId::from(0));
    /// ```
    /// [`ExtendedSpendingKey`]: zcash_primitives::zip32::ExtendedSpendingKey
    pub fn spending_key(seed: &[u8], coin_type: u32, account: AccountId) -> ExtendedSpendingKey {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(seed),
            &[
                ChildIndex::Hardened(32),
                ChildIndex::Hardened(coin_type),
                ChildIndex::Hardened(account.into()),
            ],
        )
    }
}

#[cfg(feature = "transparent-inputs")]
fn to_transparent_child_index(j: DiversifierIndex) -> Option<u32> {
    let (low_4_bytes, rest) = j.0.split_at(4);
    let transparent_j = u32::from_le_bytes(low_4_bytes.try_into().unwrap());
    if transparent_j > (0x7FFFFFFF) || rest.iter().any(|b| b != &0) {
        None
    } else {
        Some(transparent_j)
    }
}

#[derive(Debug)]
#[doc(hidden)]
pub enum DerivationError {
    Orchard(orchard::zip32::Error),
    #[cfg(feature = "transparent-inputs")]
    Transparent(hdwallet::error::Error),
}

/// A version identifier for the encoding of unified spending keys.
///
/// Each era corresponds to a range of block heights. During an era, the unified spending key
/// parsed from an encoded form tagged with that era's identifier is expected to provide
/// sufficient spending authority to spend any non-Sprout shielded note created in a transaction
/// within the era's block range.
#[cfg(feature = "unstable")]
#[derive(Debug, PartialEq, Eq)]
pub enum Era {
    /// The Orchard era begins at Orchard activation, and will end if a new pool that requires a
    /// change to unified spending keys is introduced.
    Orchard,
}

/// A type for errors that can occur when decoding keys from their serialized representations.
#[cfg(feature = "unstable")]
#[derive(Debug, PartialEq, Eq)]
pub enum DecodingError {
    ReadError(&'static str),
    EraInvalid,
    EraMismatch(Era),
    TypecodeInvalid,
    LengthInvalid,
    LengthMismatch(Typecode, u32),
    InsufficientData(Typecode),
    KeyDataInvalid(Typecode),
}

#[cfg(feature = "unstable")]
impl Era {
    /// Returns the unique identifier for the era.
    fn id(&self) -> u32 {
        // We use the consensus branch id of the network upgrade that introduced a
        // new USK format as the identifier for the era.
        match self {
            Era::Orchard => u32::from(BranchId::Nu5),
        }
    }

    fn try_from_id(id: u32) -> Option<Self> {
        BranchId::try_from(id).ok().and_then(|b| match b {
            BranchId::Nu5 => Some(Era::Orchard),
            _ => None,
        })
    }
}

/// A set of spending keys that are all associated with a single
/// ZIP-0032 account identifier.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct UnifiedSpendingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: legacy::AccountPrivKey,
    sapling: sapling::ExtendedSpendingKey,
    orchard: orchard::keys::SpendingKey,
}

#[doc(hidden)]
impl UnifiedSpendingKey {
    pub fn from_seed<P: consensus::Parameters>(
        params: &P,
        seed: &[u8],
        account: AccountId,
    ) -> Result<UnifiedSpendingKey, DerivationError> {
        if seed.len() < 32 {
            panic!("ZIP 32 seeds MUST be at least 32 bytes");
        }

        let orchard =
            orchard::keys::SpendingKey::from_zip32_seed(seed, params.coin_type(), account.into())
                .map_err(DerivationError::Orchard)?;

        #[cfg(feature = "transparent-inputs")]
        let transparent = legacy::AccountPrivKey::from_seed(params, seed, account)
            .map_err(DerivationError::Transparent)?;

        Ok(UnifiedSpendingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            sapling: sapling::spending_key(seed, params.coin_type(), account),
            orchard,
        })
    }

    pub fn to_unified_full_viewing_key(&self) -> UnifiedFullViewingKey {
        UnifiedFullViewingKey {
            #[cfg(feature = "transparent-inputs")]
            transparent: Some(self.transparent.to_account_pubkey()),
            sapling: Some(self.sapling.to_diversifiable_full_viewing_key()),
            orchard: Some((&self.orchard).into()),
            unknown: vec![],
        }
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> &legacy::AccountPrivKey {
        &self.transparent
    }

    /// Returns the Sapling extended spending key component of this unified spending key.
    pub fn sapling(&self) -> &sapling::ExtendedSpendingKey {
        &self.sapling
    }

    /// Returns the Orchard spending key component of this unified spending key.
    pub fn orchard(&self) -> &orchard::keys::SpendingKey {
        &self.orchard
    }

    /// Returns a binary encoding of this key suitable for decoding with [`decode`].
    ///
    /// The encoded form of a unified spending key is only intended for use
    /// within wallets when required for storage and/or crossing FFI boundaries;
    /// unified spending keys should not be exposed to users, and consequently
    /// no string-based encoding is defined. This encoding does not include any
    /// internal validation metadata (such as checksums) as keys decoded from
    /// this form will necessarily be validated when the attempt is made to
    /// spend a note that they have authority for.
    #[cfg(feature = "unstable")]
    pub fn to_bytes(&self, era: Era) -> Vec<u8> {
        let mut result = vec![];
        result.write_u32::<LittleEndian>(era.id()).unwrap();

        // orchard
        let orchard_key = self.orchard();
        CompactSize::write(&mut result, usize::try_from(Typecode::Orchard).unwrap()).unwrap();

        let orchard_key_bytes = orchard_key.to_bytes();
        CompactSize::write(&mut result, orchard_key_bytes.len()).unwrap();
        result.write_all(orchard_key_bytes).unwrap();

        // sapling
        let sapling_key = self.sapling();
        CompactSize::write(&mut result, usize::try_from(Typecode::Sapling).unwrap()).unwrap();

        let sapling_key_bytes = sapling_key.to_bytes();
        CompactSize::write(&mut result, sapling_key_bytes.len()).unwrap();
        result.write_all(&sapling_key_bytes).unwrap();

        // transparent
        #[cfg(feature = "transparent-inputs")]
        {
            let account_tkey = self.transparent();
            CompactSize::write(&mut result, usize::try_from(Typecode::P2pkh).unwrap()).unwrap();

            let account_tkey_bytes = account_tkey.to_bytes();
            CompactSize::write(&mut result, account_tkey_bytes.len()).unwrap();
            result.write_all(&account_tkey_bytes).unwrap();
        }

        result
    }

    /// Decodes a [`UnifiedSpendingKey`] value from its serialized representation.
    ///
    /// See [`to_bytes`] for additional detail about the encoded form.
    #[allow(clippy::unnecessary_unwrap)]
    #[cfg(feature = "unstable")]
    pub fn from_bytes(era: Era, encoded: &[u8]) -> Result<Self, DecodingError> {
        let mut source = std::io::Cursor::new(encoded);
        let decoded_era = source
            .read_u32::<LittleEndian>()
            .map_err(|_| DecodingError::ReadError("era"))
            .and_then(|id| Era::try_from_id(id).ok_or(DecodingError::EraInvalid))?;

        if decoded_era != era {
            return Err(DecodingError::EraMismatch(decoded_era));
        }

        let mut orchard = None;
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;
        loop {
            let tc = CompactSize::read_t::<_, u32>(&mut source)
                .map_err(|_| DecodingError::ReadError("typecode"))
                .and_then(|v| Typecode::try_from(v).map_err(|_| DecodingError::TypecodeInvalid))?;

            let len = CompactSize::read_t::<_, u32>(&mut source)
                .map_err(|_| DecodingError::ReadError("key length"))?;

            match tc {
                Typecode::Orchard => {
                    if len != 32 {
                        return Err(DecodingError::LengthMismatch(Typecode::Orchard, len));
                    }

                    let mut key = [0u8; 32];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::Orchard))?;
                    orchard = Some(
                        Option::<orchard::keys::SpendingKey>::from(
                            orchard::keys::SpendingKey::from_bytes(key),
                        )
                        .ok_or(DecodingError::KeyDataInvalid(Typecode::Orchard))?,
                    );
                }
                Typecode::Sapling => {
                    if len != 169 {
                        return Err(DecodingError::LengthMismatch(Typecode::Sapling, len));
                    }

                    let mut key = [0u8; 169];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::Sapling))?;
                    sapling = Some(
                        sapling::ExtendedSpendingKey::from_bytes(&key)
                            .map_err(|_| DecodingError::KeyDataInvalid(Typecode::Sapling))?,
                    );
                }
                #[cfg(feature = "transparent-inputs")]
                Typecode::P2pkh => {
                    if len != 64 {
                        return Err(DecodingError::LengthMismatch(Typecode::P2pkh, len));
                    }

                    let mut key = [0u8; 64];
                    source
                        .read_exact(&mut key)
                        .map_err(|_| DecodingError::InsufficientData(Typecode::P2pkh))?;
                    transparent = Some(
                        legacy::AccountPrivKey::from_bytes(&key)
                            .ok_or(DecodingError::KeyDataInvalid(Typecode::P2pkh))?,
                    );
                }
                _ => {
                    return Err(DecodingError::TypecodeInvalid);
                }
            }

            #[cfg(feature = "transparent-inputs")]
            let has_transparent = transparent.is_some();
            #[cfg(not(feature = "transparent-inputs"))]
            let has_transparent = true;

            if orchard.is_some() && sapling.is_some() && has_transparent {
                return Ok(UnifiedSpendingKey {
                    orchard: orchard.unwrap(),
                    sapling: sapling.unwrap(),
                    #[cfg(feature = "transparent-inputs")]
                    transparent: transparent.unwrap(),
                });
            }
        }
    }

    #[cfg(feature = "test-dependencies")]
    pub fn default_address(&self) -> (UnifiedAddress, DiversifierIndex) {
        self.to_unified_full_viewing_key().default_address()
    }

    #[cfg(all(feature = "test-dependencies", feature = "transparent-inputs"))]
    pub fn default_transparent_address(&self) -> (TransparentAddress, u32) {
        self.transparent()
            .to_account_pubkey()
            .derive_external_ivk()
            .unwrap()
            .default_address()
    }
}

/// A [ZIP 316](https://zips.z.cash/zip-0316) unified full viewing key.
#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct UnifiedFullViewingKey {
    #[cfg(feature = "transparent-inputs")]
    transparent: Option<legacy::AccountPubKey>,
    sapling: Option<sapling::DiversifiableFullViewingKey>,
    orchard: Option<orchard::keys::FullViewingKey>,
    unknown: Vec<(u32, Vec<u8>)>,
}

#[doc(hidden)]
impl UnifiedFullViewingKey {
    /// Construct a new unified full viewing key, if the required components are present.
    pub fn new(
        #[cfg(feature = "transparent-inputs")] transparent: Option<legacy::AccountPubKey>,
        sapling: Option<sapling::DiversifiableFullViewingKey>,
        orchard: Option<orchard::keys::FullViewingKey>,
    ) -> Option<UnifiedFullViewingKey> {
        if sapling.is_none() {
            None
        } else {
            Some(UnifiedFullViewingKey {
                #[cfg(feature = "transparent-inputs")]
                transparent,
                sapling,
                orchard,
                // We don't allow constructing new UFVKs with unknown items, but we store
                // this to allow parsing such UFVKs.
                unknown: vec![],
            })
        }
    }

    /// Parses a `UnifiedFullViewingKey` from its [ZIP 316] string encoding.
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub fn decode<P: consensus::Parameters>(params: &P, encoding: &str) -> Result<Self, String> {
        let (net, ufvk) = unified::Ufvk::decode(encoding).map_err(|e| e.to_string())?;
        let expected_net = params.address_network().expect("Unrecognized network");
        if net != expected_net {
            return Err(format!(
                "UFVK is for network {:?} but we expected {:?}",
                net, expected_net,
            ));
        }

        let mut orchard = None;
        let mut sapling = None;
        #[cfg(feature = "transparent-inputs")]
        let mut transparent = None;

        // We can use as-parsed order here for efficiency, because we're breaking out the
        // receivers we support from the unknown receivers.
        let unknown = ufvk
            .items_as_parsed()
            .iter()
            .filter_map(|receiver| match receiver {
                unified::Fvk::Orchard(data) => orchard::keys::FullViewingKey::from_bytes(data)
                    .ok_or("Invalid Orchard FVK in Unified FVK")
                    .map(|addr| {
                        orchard = Some(addr);
                        None
                    })
                    .transpose(),
                unified::Fvk::Sapling(data) => {
                    sapling::DiversifiableFullViewingKey::from_bytes(data)
                        .ok_or("Invalid Sapling FVK in Unified FVK")
                        .map(|pa| {
                            sapling = Some(pa);
                            None
                        })
                        .transpose()
                }
                #[cfg(feature = "transparent-inputs")]
                unified::Fvk::P2pkh(data) => legacy::AccountPubKey::deserialize(data)
                    .map_err(|_| "Invalid transparent FVK in Unified FVK")
                    .map(|tfvk| {
                        transparent = Some(tfvk);
                        None
                    })
                    .transpose(),
                #[cfg(not(feature = "transparent-inputs"))]
                unified::Fvk::P2pkh(data) => {
                    Some(Ok((unified::Typecode::P2pkh.into(), data.to_vec())))
                }
                unified::Fvk::Unknown { typecode, data } => Some(Ok((*typecode, data.clone()))),
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            #[cfg(feature = "transparent-inputs")]
            transparent,
            sapling,
            orchard,
            unknown,
        })
    }

    /// Returns the string encoding of this `UnifiedFullViewingKey` for the given network.
    pub fn encode<P: consensus::Parameters>(&self, params: &P) -> String {
        let items = std::iter::empty()
            .chain(
                self.orchard
                    .as_ref()
                    .map(|fvk| fvk.to_bytes())
                    .map(unified::Fvk::Orchard),
            )
            .chain(
                self.sapling
                    .as_ref()
                    .map(|dfvk| dfvk.to_bytes())
                    .map(unified::Fvk::Sapling),
            )
            .chain(
                self.unknown
                    .iter()
                    .map(|(typecode, data)| unified::Fvk::Unknown {
                        typecode: *typecode,
                        data: data.clone(),
                    }),
            );
        #[cfg(feature = "transparent-inputs")]
        let items = items.chain(
            self.transparent
                .as_ref()
                .map(|tfvk| tfvk.serialize().try_into().unwrap())
                .map(unified::Fvk::P2pkh),
        );

        let ufvk = unified::Ufvk::try_from_items(items.collect())
            .expect("UnifiedFullViewingKey should only be constructed safely");
        ufvk.encode(&params.address_network().expect("Unrecognized network"))
    }

    /// Returns the transparent component of the unified key at the
    /// BIP44 path `m/44'/<coin_type>'/<account>'`.
    #[cfg(feature = "transparent-inputs")]
    pub fn transparent(&self) -> Option<&legacy::AccountPubKey> {
        self.transparent.as_ref()
    }

    /// Returns the Sapling diversifiable full viewing key component of this unified key.
    pub fn sapling(&self) -> Option<&sapling::DiversifiableFullViewingKey> {
        self.sapling.as_ref()
    }

    /// Returns the Orchard full viewing key component of this unified key.
    pub fn orchard(&self) -> Option<&orchard::keys::FullViewingKey> {
        self.orchard.as_ref()
    }

    /// Attempts to derive the Unified Address for the given diversifier index.
    ///
    /// Returns `None` if the specified index does not produce a valid diversifier.
    // TODO: Allow filtering down by receiver types?
    pub fn address(&self, j: DiversifierIndex) -> Option<UnifiedAddress> {
        let sapling = if let Some(extfvk) = self.sapling.as_ref() {
            Some(extfvk.address(j)?)
        } else {
            None
        };

        #[cfg(feature = "transparent-inputs")]
        let transparent = if let Some(tfvk) = self.transparent.as_ref() {
            match to_transparent_child_index(j) {
                Some(transparent_j) => match tfvk
                    .derive_external_ivk()
                    .and_then(|tivk| tivk.derive_address(transparent_j))
                {
                    Ok(taddr) => Some(taddr),
                    Err(_) => return None,
                },
                // Diversifier doesn't generate a valid transparent child index.
                None => return None,
            }
        } else {
            None
        };
        #[cfg(not(feature = "transparent-inputs"))]
        let transparent = None;

        UnifiedAddress::from_receivers(None, sapling, transparent)
    }

    /// Searches the diversifier space starting at diversifier index `j` for one which will
    /// produce a valid diversifier, and return the Unified Address constructed using that
    /// diversifier along with the index at which the valid diversifier was found.
    ///
    /// Returns `None` if no valid diversifier exists
    pub fn find_address(
        &self,
        mut j: DiversifierIndex,
    ) -> Option<(UnifiedAddress, DiversifierIndex)> {
        // If we need to generate a transparent receiver, check that the user has not
        // specified an invalid transparent child index, from which we can never search to
        // find a valid index.
        #[cfg(feature = "transparent-inputs")]
        if self.transparent.is_some() && to_transparent_child_index(j).is_none() {
            return None;
        }

        // Find a working diversifier and construct the associated address.
        loop {
            let res = self.address(j);
            if let Some(ua) = res {
                break Some((ua, j));
            }
            if j.increment().is_err() {
                break None;
            }
        }
    }

    /// Returns the Unified Address corresponding to the smallest valid diversifier index,
    /// along with that index.
    pub fn default_address(&self) -> (UnifiedAddress, DiversifierIndex) {
        self.find_address(DiversifierIndex::new())
            .expect("UFVK should have at least one valid diversifier")
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use super::UnifiedSpendingKey;
    use zcash_primitives::{consensus::Network, zip32::AccountId};

    pub fn arb_unified_spending_key(params: Network) -> impl Strategy<Value = UnifiedSpendingKey> {
        prop::array::uniform32(prop::num::u8::ANY).prop_flat_map(move |seed| {
            prop::num::u32::ANY
                .prop_map(move |account| {
                    UnifiedSpendingKey::from_seed(&params, &seed, AccountId::from(account))
                })
                .prop_filter("seeds must generate valid USKs", |v| v.is_ok())
                .prop_map(|v| v.unwrap())
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::proptest;

    use super::{sapling, UnifiedFullViewingKey};
    use zcash_primitives::{consensus::MAIN_NETWORK, zip32::AccountId};

    #[cfg(feature = "transparent-inputs")]
    use {
        crate::{address::RecipientAddress, encoding::AddressCodec},
        zcash_address::test_vectors,
        zcash_primitives::{
            legacy::{
                self,
                keys::{AccountPrivKey, IncomingViewingKey},
            },
            zip32::DiversifierIndex,
        },
    };

    #[cfg(feature = "unstable")]
    use {
        super::{testing::arb_unified_spending_key, Era, UnifiedSpendingKey},
        subtle::ConstantTimeEq,
        zcash_primitives::consensus::Network,
    };

    #[cfg(feature = "transparent-inputs")]
    fn seed() -> Vec<u8> {
        let seed_hex = "6ef5f84def6f4b9d38f466586a8380a38593bd47c8cda77f091856176da47f26b5bd1c8d097486e5635df5a66e820d28e1d73346f499801c86228d43f390304f";
        hex::decode(seed_hex).unwrap()
    }

    #[test]
    #[should_panic]
    fn spending_key_panics_on_short_seed() {
        let _ = sapling::spending_key(&[0; 31][..], 0, AccountId::from(0));
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn pk_to_taddr() {
        let taddr =
            legacy::keys::AccountPrivKey::from_seed(&MAIN_NETWORK, &seed(), AccountId::from(0))
                .unwrap()
                .to_account_pubkey()
                .derive_external_ivk()
                .unwrap()
                .derive_address(0)
                .unwrap()
                .encode(&MAIN_NETWORK);
        assert_eq!(taddr, "t1PKtYdJJHhc3Pxowmznkg7vdTwnhEsCvR4".to_string());
    }

    #[test]
    fn ufvk_round_trip() {
        let account = 0.into();

        let orchard = {
            let sk = orchard::keys::SpendingKey::from_zip32_seed(&[0; 32], 0, 0).unwrap();
            Some(orchard::keys::FullViewingKey::from(&sk))
        };

        let sapling = {
            let extsk = sapling::spending_key(&[0; 32], 0, account);
            Some(extsk.to_diversifiable_full_viewing_key())
        };

        #[cfg(feature = "transparent-inputs")]
        let transparent = {
            let privkey =
                AccountPrivKey::from_seed(&MAIN_NETWORK, &[0; 32], AccountId::from(0)).unwrap();
            Some(privkey.to_account_pubkey())
        };

        let ufvk = UnifiedFullViewingKey::new(
            #[cfg(feature = "transparent-inputs")]
            transparent,
            sapling,
            orchard,
        )
        .unwrap();

        let encoded = ufvk.encode(&MAIN_NETWORK);

        // test encoded form against known values
        let encoded_with_t = "uview1tg6rpjgju2s2j37gkgjq79qrh5lvzr6e0ed3n4sf4hu5qd35vmsh7avl80xa6mx7ryqce9hztwaqwrdthetpy4pc0kce25x453hwcmax02p80pg5savlg865sft9reat07c5vlactr6l2pxtlqtqunt2j9gmvr8spcuzf07af80h5qmut38h0gvcfa9k4rwujacwwca9vu8jev7wq6c725huv8qjmhss3hdj2vh8cfxhpqcm2qzc34msyrfxk5u6dqttt4vv2mr0aajreww5yufpk0gn4xkfm888467k7v6fmw7syqq6cceu078yw8xja502jxr0jgum43lhvpzmf7eu5dmnn6cr6f7p43yw8znzgxg598mllewnx076hljlvynhzwn5es94yrv65tdg3utuz2u3sras0wfcq4adxwdvlk387d22g3q98t5z74quw2fa4wed32escx8dwh4mw35t4jwf35xyfxnu83mk5s4kw2glkgsshmxk";
        let _encoded_no_t = "uview12z384wdq76ceewlsu0esk7d97qnd23v2qnvhujxtcf2lsq8g4hwzpx44fwxssnm5tg8skyh4tnc8gydwxefnnm0hd0a6c6etmj0pp9jqkdsllkr70u8gpf7ndsfqcjlqn6dec3faumzqlqcmtjf8vp92h7kj38ph2786zx30hq2wru8ae3excdwc8w0z3t9fuw7mt7xy5sn6s4e45kwm0cjp70wytnensgdnev286t3vew3yuwt2hcz865y037k30e428dvgne37xvyeal2vu8yjnznphf9t2rw3gdp0hk5zwq00ws8f3l3j5n3qkqgsyzrwx4qzmgq0xwwk4vz2r6vtsykgz089jncvycmem3535zjwvvtvjw8v98y0d5ydwte575gjm7a7k";
        #[cfg(feature = "transparent-inputs")]
        assert_eq!(encoded, encoded_with_t);
        #[cfg(not(feature = "transparent-inputs"))]
        assert_eq!(encoded, _encoded_no_t);

        let decoded = UnifiedFullViewingKey::decode(&MAIN_NETWORK, &encoded).unwrap();
        let reencoded = decoded.encode(&MAIN_NETWORK);
        assert_eq!(encoded, reencoded);

        #[cfg(feature = "transparent-inputs")]
        assert_eq!(
            decoded.transparent.map(|t| t.serialize()),
            ufvk.transparent.as_ref().map(|t| t.serialize()),
        );
        assert_eq!(
            decoded.sapling.map(|s| s.to_bytes()),
            ufvk.sapling.map(|s| s.to_bytes()),
        );
        assert_eq!(
            decoded.orchard.map(|o| o.to_bytes()),
            ufvk.orchard.map(|o| o.to_bytes()),
        );

        let decoded_with_t = UnifiedFullViewingKey::decode(&MAIN_NETWORK, encoded_with_t).unwrap();
        #[cfg(feature = "transparent-inputs")]
        assert_eq!(
            decoded_with_t.transparent.map(|t| t.serialize()),
            ufvk.transparent.as_ref().map(|t| t.serialize()),
        );
        #[cfg(not(feature = "transparent-inputs"))]
        assert_eq!(decoded_with_t.unknown.len(), 1);
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn ufvk_derivation() {
        use super::UnifiedSpendingKey;

        for tv in test_vectors::UNIFIED {
            let usk = UnifiedSpendingKey::from_seed(
                &MAIN_NETWORK,
                &tv.root_seed,
                AccountId::from(tv.account),
            )
            .expect("seed produced a valid unified spending key");

            let d_idx = DiversifierIndex::from(tv.diversifier_index);
            let ufvk = usk.to_unified_full_viewing_key();

            // The test vectors contain some diversifier indices that do not generate
            // valid Sapling addresses, so skip those.
            if ufvk.sapling().unwrap().address(d_idx).is_none() {
                continue;
            }

            let ua = ufvk.address(d_idx).unwrap_or_else(|| panic!("diversifier index {} should have produced a valid unified address for account {}",
                tv.diversifier_index, tv.account));

            match RecipientAddress::decode(&MAIN_NETWORK, tv.unified_addr) {
                Some(RecipientAddress::Unified(tvua)) => {
                    // We always derive transparent and Sapling receivers, but not
                    // every value in the test vectors has these present.
                    if tvua.transparent().is_some() {
                        assert_eq!(tvua.transparent(), ua.transparent());
                    }
                    if tvua.sapling().is_some() {
                        assert_eq!(tvua.sapling(), ua.sapling());
                    }
                }
                _other => {
                    panic!(
                        "{} did not decode to a valid unified address",
                        tv.unified_addr
                    );
                }
            }
        }
    }

    proptest! {
        #[test]
        #[cfg(feature = "unstable")]
        fn prop_usk_roundtrip(usk in arb_unified_spending_key(Network::MainNetwork)) {
            let encoded = usk.to_bytes(Era::Orchard);
            #[cfg(not(feature = "transparent-inputs"))]
            assert_eq!(encoded.len(), 4 + 2 + 32 + 2 + 169);
            #[cfg(feature = "transparent-inputs")]
            assert_eq!(encoded.len(), 4 + 2 + 32 + 2 + 169 + 2 + 64);
            let decoded = UnifiedSpendingKey::from_bytes(Era::Orchard, &encoded);
            let decoded = decoded.unwrap_or_else(|e| panic!("Error decoding USK: {:?}", e));
            assert!(bool::from(decoded.orchard().ct_eq(usk.orchard())));
            assert_eq!(decoded.sapling(), usk.sapling());
            #[cfg(feature = "transparent-inputs")]
            assert_eq!(decoded.transparent().to_bytes(), usk.transparent().to_bytes());
        }
    }
}
