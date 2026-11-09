//! [ZIP 316] metadata items of unified viewing keys.
//!
//! [ZIP 316]: https://zips.z.cash/zip-0316

use alloc::{collections::BTreeSet, vec::Vec};
use core::fmt::{self, Display};

use zcash_address::unified::{MetadataTypecode, Typecode};
use zcash_protocol::consensus::BlockHeight;

/// The [ZIP 316] metadata items of a unified full or incoming viewing key.
///
/// A value of this type always satisfies these conditions:
/// - The birthday height, if present, is not greater than the expiry height, if present.
/// - Each unknown item has a distinct typecode that this library does not recognize, in the
///   range of metadata typecodes that a reader is not required to understand.
///
/// [ZIP 316]: https://zips.z.cash/zip-0316
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewingKeyMetadata {
    pub(super) birthday_height: Option<BlockHeight>,
    pub(super) expiry_height: Option<BlockHeight>,
    pub(super) expiry_time: Option<u64>,
    pub(super) unknown: Vec<(u32, Vec<u8>)>,
}

impl ViewingKeyMetadata {
    /// Constructs a set of viewing key metadata items.
    ///
    /// * `birthday_height`: The height of the first block that a user of the key should scan
    ///   in order to detect funds.
    /// * `expiry_height`: The block height after which addresses derived from the key expire.
    /// * `expiry_time`: The Unix time in seconds after which addresses derived from the key
    ///   expire.
    /// * `unknown`: Metadata items that this library does not recognize, as pairs of typecode
    ///   and item data.
    ///
    /// # Errors
    ///
    /// - [`MetadataError::BirthdayAfterExpiry`] if `birthday_height` is greater than
    ///   `expiry_height`.
    /// - [`MetadataError::InvalidUnknownTypecode`] if a typecode in `unknown` is not an
    ///   unrecognized metadata typecode that a reader is not required to understand.
    /// - [`MetadataError::DuplicateTypecode`] if a typecode occurs in `unknown` more than once.
    pub fn new(
        birthday_height: Option<BlockHeight>,
        expiry_height: Option<BlockHeight>,
        expiry_time: Option<u64>,
        unknown: Vec<(u32, Vec<u8>)>,
    ) -> Result<Self, MetadataError> {
        if let (Some(birthday_height), Some(expiry_height)) = (birthday_height, expiry_height)
            && birthday_height > expiry_height
        {
            return Err(MetadataError::BirthdayAfterExpiry {
                birthday_height,
                expiry_height,
            });
        }

        let mut typecodes = BTreeSet::new();
        for (typecode, _) in &unknown {
            match Typecode::try_from(*typecode) {
                Ok(Typecode::Metadata(tc @ MetadataTypecode::Unknown(_)))
                    if !tc.is_must_understand() => {}
                _ => return Err(MetadataError::InvalidUnknownTypecode(*typecode)),
            }
            if !typecodes.insert(*typecode) {
                return Err(MetadataError::DuplicateTypecode(*typecode));
            }
        }

        Ok(Self {
            birthday_height,
            expiry_height,
            expiry_time,
            unknown,
        })
    }

    /// Returns the height of the first block that a user of the key should scan in order to
    /// detect funds, if present.
    pub fn birthday_height(&self) -> Option<BlockHeight> {
        self.birthday_height
    }

    /// Returns the block height after which addresses derived from the key expire, if present.
    pub fn expiry_height(&self) -> Option<BlockHeight> {
        self.expiry_height
    }

    /// Returns the Unix time in seconds after which addresses derived from the key expire, if
    /// present.
    pub fn expiry_time(&self) -> Option<u64> {
        self.expiry_time
    }

    /// Returns the metadata items that this library does not recognize, as pairs of typecode
    /// and item data.
    pub fn unknown_items(&self) -> &[(u32, Vec<u8>)] {
        &self.unknown
    }

    /// Returns these metadata items without the items that a reader is not required to
    /// understand, except for those whose typecodes are in `include`.
    ///
    /// The result always holds every item that a reader is required to understand, such as
    /// the expiry height and expiry time. These items limit how the key can be used, so
    /// removing them would change what the key means.
    pub fn retain(self, include: &BTreeSet<MetadataTypecode>) -> Self {
        // Compare numeric typecodes, so that `MetadataTypecode::Unknown(0xC0)` also selects
        // the birthday height.
        let include: BTreeSet<u32> = include.iter().map(|tc| u32::from(*tc)).collect();
        let birthday_typecode = u32::from(MetadataTypecode::BirthdayHeight);
        Self {
            birthday_height: self
                .birthday_height
                .filter(|_| include.contains(&birthday_typecode)),
            expiry_height: self.expiry_height,
            expiry_time: self.expiry_time,
            unknown: self
                .unknown
                .into_iter()
                .filter(|(typecode, _)| include.contains(typecode))
                .collect(),
        }
    }

    /// Returns `Ok(())` if replacing `self` with `requested` only narrows the items that a
    /// reader is required to understand, and otherwise the first change that widens them.
    ///
    /// An expiry height or expiry time may be added or moved earlier, but not removed or moved
    /// later.
    pub(super) fn check_narrowing(&self, requested: &Self) -> Result<(), UnsafeMetadataChange> {
        narrowing(self.expiry_height, requested.expiry_height).map_err(|w| match w {
            Widening::Removed(current) => UnsafeMetadataChange::ExpiryHeightRemoved { current },
            Widening::Extended { current, requested } => {
                UnsafeMetadataChange::ExpiryHeightExtended { current, requested }
            }
        })?;
        narrowing(self.expiry_time, requested.expiry_time).map_err(|w| match w {
            Widening::Removed(current) => UnsafeMetadataChange::ExpiryTimeRemoved { current },
            Widening::Extended { current, requested } => {
                UnsafeMetadataChange::ExpiryTimeExtended { current, requested }
            }
        })
    }
}

/// A way in which a change to an upper bound widens it.
enum Widening<T> {
    Removed(T),
    Extended { current: T, requested: T },
}

/// Returns `Ok(())` if changing the upper bound `current` to `requested` does not widen it.
/// No bound is the widest bound.
fn narrowing<T: Ord + Copy>(current: Option<T>, requested: Option<T>) -> Result<(), Widening<T>> {
    match (current, requested) {
        (None, _) => Ok(()),
        (Some(current), None) => Err(Widening::Removed(current)),
        (Some(current), Some(requested)) if requested > current => {
            Err(Widening::Extended { current, requested })
        }
        (Some(_), Some(_)) => Ok(()),
    }
}

/// An error returned when a [`ViewingKeyMetadata`] value cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataError {
    /// The birthday height is greater than the expiry height.
    BirthdayAfterExpiry {
        birthday_height: BlockHeight,
        expiry_height: BlockHeight,
    },
    /// The typecode of an unknown item is not an unrecognized metadata typecode that a reader
    /// is not required to understand.
    InvalidUnknownTypecode(u32),
    /// More than one unknown item has this typecode.
    DuplicateTypecode(u32),
}

impl Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataError::BirthdayAfterExpiry {
                birthday_height,
                expiry_height,
            } => write!(
                f,
                "Birthday height {birthday_height} is greater than expiry height {expiry_height}"
            ),
            MetadataError::InvalidUnknownTypecode(typecode) => write!(
                f,
                "Typecode {typecode:#x} is not an unrecognized optional metadata typecode"
            ),
            MetadataError::DuplicateTypecode(typecode) => {
                write!(f, "Typecode {typecode:#x} occurs more than once")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MetadataError {}

/// A change to the metadata of a viewing key that widens an item that a reader is required to
/// understand.
///
/// Such a change can make a key usable in more circumstances than its creator intended, for
/// example by removing its expiry. Use `unsafe_with_metadata` on the key to make such a change
/// deliberately.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsafeMetadataChange {
    /// The change removes the expiry height `current`.
    ExpiryHeightRemoved { current: BlockHeight },
    /// The change moves the expiry height from `current` to the later height `requested`.
    ExpiryHeightExtended {
        current: BlockHeight,
        requested: BlockHeight,
    },
    /// The change removes the expiry time `current`.
    ExpiryTimeRemoved { current: u64 },
    /// The change moves the expiry time from `current` to the later time `requested`.
    ExpiryTimeExtended { current: u64, requested: u64 },
}

impl Display for UnsafeMetadataChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnsafeMetadataChange::ExpiryHeightRemoved { current } => {
                write!(f, "The change removes expiry height {current}")
            }
            UnsafeMetadataChange::ExpiryHeightExtended { current, requested } => write!(
                f,
                "The change moves expiry height {current} to the later height {requested}"
            ),
            UnsafeMetadataChange::ExpiryTimeRemoved { current } => {
                write!(f, "The change removes expiry time {current}")
            }
            UnsafeMetadataChange::ExpiryTimeExtended { current, requested } => write!(
                f,
                "The change moves expiry time {current} to the later time {requested}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsafeMetadataChange {}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use alloc::vec::Vec;
    use proptest::prelude::*;
    use zcash_protocol::consensus::BlockHeight;

    use super::ViewingKeyMetadata;

    /// The range of metadata typecodes that this library does not recognize and that a reader
    /// is not required to understand.
    const UNKNOWN_OPTIONAL_TYPECODES: core::ops::RangeInclusive<u32> = 0xC1..=0xDF;
    /// The largest length of unknown item data that the strategy generates.
    const MAX_UNKNOWN_DATA_LEN: usize = 16;
    /// The largest number of unknown items that the strategy generates.
    const MAX_UNKNOWN_ITEMS: usize = 3;

    /// Returns a strategy that generates valid viewing key metadata.
    pub fn arb_viewing_key_metadata() -> impl Strategy<Value = ViewingKeyMetadata> {
        (
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<u32>()),
            proptest::option::of(any::<u64>()),
            proptest::collection::btree_map(
                UNKNOWN_OPTIONAL_TYPECODES,
                proptest::collection::vec(any::<u8>(), 0..=MAX_UNKNOWN_DATA_LEN),
                0..=MAX_UNKNOWN_ITEMS,
            ),
        )
            .prop_map(|(a, b, expiry_time, unknown)| {
                // Order the two heights so that the birthday is not after the expiry.
                let (birthday_height, expiry_height) = match (a, b) {
                    (Some(a), Some(b)) => (Some(a.min(b)), Some(a.max(b))),
                    other => other,
                };
                ViewingKeyMetadata::new(
                    birthday_height.map(BlockHeight::from_u32),
                    expiry_height.map(BlockHeight::from_u32),
                    expiry_time,
                    unknown.into_iter().collect::<Vec<_>>(),
                )
                .expect("the generated items satisfy the invariants")
            })
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeSet, vec};

    use proptest::prelude::*;
    use zcash_address::unified::MetadataTypecode;
    use zcash_protocol::consensus::BlockHeight;

    use super::{MetadataError, UnsafeMetadataChange, ViewingKeyMetadata, testing};

    const UNKNOWN_OPTIONAL_TYPECODE: u32 = 0xC1;
    const UNKNOWN_MUST_UNDERSTAND_TYPECODE: u32 = 0xE2;

    #[test]
    fn new_rejects_invalid_items() {
        let height = BlockHeight::from_u32(100);
        assert_eq!(
            ViewingKeyMetadata::new(Some(height + 1), Some(height), None, vec![]),
            Err(MetadataError::BirthdayAfterExpiry {
                birthday_height: height + 1,
                expiry_height: height,
            })
        );
        assert!(ViewingKeyMetadata::new(Some(height), Some(height), None, vec![]).is_ok());

        let birthday_typecode = u32::from(MetadataTypecode::BirthdayHeight);
        for typecode in [birthday_typecode, UNKNOWN_MUST_UNDERSTAND_TYPECODE, 0x00] {
            assert_eq!(
                ViewingKeyMetadata::new(None, None, None, vec![(typecode, vec![])]),
                Err(MetadataError::InvalidUnknownTypecode(typecode))
            );
        }
        assert_eq!(
            ViewingKeyMetadata::new(
                None,
                None,
                None,
                vec![
                    (UNKNOWN_OPTIONAL_TYPECODE, vec![]),
                    (UNKNOWN_OPTIONAL_TYPECODE, vec![1])
                ]
            ),
            Err(MetadataError::DuplicateTypecode(UNKNOWN_OPTIONAL_TYPECODE))
        );
    }

    #[test]
    fn check_narrowing_rejects_widening_expiry() {
        let height = BlockHeight::from_u32(100);
        let time = 1_000_000;
        let current = ViewingKeyMetadata::new(None, Some(height), Some(time), vec![]).unwrap();

        let without_height = ViewingKeyMetadata::new(None, None, Some(time), vec![]).unwrap();
        assert_eq!(
            current.check_narrowing(&without_height),
            Err(UnsafeMetadataChange::ExpiryHeightRemoved { current: height })
        );
        let later_height =
            ViewingKeyMetadata::new(None, Some(height + 1), Some(time), vec![]).unwrap();
        assert_eq!(
            current.check_narrowing(&later_height),
            Err(UnsafeMetadataChange::ExpiryHeightExtended {
                current: height,
                requested: height + 1,
            })
        );
        let without_time = ViewingKeyMetadata::new(None, Some(height), None, vec![]).unwrap();
        assert_eq!(
            current.check_narrowing(&without_time),
            Err(UnsafeMetadataChange::ExpiryTimeRemoved { current: time })
        );
        let later_time =
            ViewingKeyMetadata::new(None, Some(height), Some(time + 1), vec![]).unwrap();
        assert_eq!(
            current.check_narrowing(&later_time),
            Err(UnsafeMetadataChange::ExpiryTimeExtended {
                current: time,
                requested: time + 1,
            })
        );

        let earlier = ViewingKeyMetadata::new(
            Some(height - 1),
            Some(height - 1),
            Some(time - 1),
            vec![(UNKNOWN_OPTIONAL_TYPECODE, vec![])],
        )
        .unwrap();
        assert_eq!(current.check_narrowing(&earlier), Ok(()));
        assert_eq!(
            ViewingKeyMetadata::default().check_narrowing(&current),
            Ok(())
        );
    }

    proptest! {
        /// Narrowing is a preorder: every value narrows itself, and narrowing composes.
        #[test]
        fn check_narrowing_is_a_preorder(
            a in testing::arb_viewing_key_metadata(),
            b in testing::arb_viewing_key_metadata(),
            c in testing::arb_viewing_key_metadata(),
        ) {
            prop_assert_eq!(a.check_narrowing(&a), Ok(()));
            if a.check_narrowing(&b).is_ok() && b.check_narrowing(&c).is_ok() {
                prop_assert_eq!(a.check_narrowing(&c), Ok(()));
            }
        }

        /// `retain` keeps every item that a reader is required to understand, so the result
        /// is always a narrowing of the input. It is idempotent, and it keeps exactly the
        /// requested optional items.
        #[test]
        fn retain_keeps_must_understand_items(
            metadata in testing::arb_viewing_key_metadata(),
            include_birthday in any::<bool>(),
        ) {
            let include: BTreeSet<MetadataTypecode> = include_birthday
                .then_some(MetadataTypecode::BirthdayHeight)
                .into_iter()
                .collect();
            let retained = metadata.clone().retain(&include);

            prop_assert_eq!(metadata.check_narrowing(&retained), Ok(()));
            prop_assert_eq!(retained.check_narrowing(&metadata), Ok(()));
            prop_assert_eq!(retained.clone().retain(&include), retained.clone());
            prop_assert_eq!(retained.expiry_height(), metadata.expiry_height());
            prop_assert_eq!(retained.expiry_time(), metadata.expiry_time());
            prop_assert_eq!(
                retained.birthday_height(),
                metadata.birthday_height().filter(|_| include_birthday)
            );
            prop_assert!(retained.unknown_items().is_empty());
            prop_assert_eq!(metadata.clone().retain(&include_all(&metadata)), metadata);
        }
    }

    /// Returns a set that holds the typecode of every item in `metadata`.
    fn include_all(metadata: &ViewingKeyMetadata) -> BTreeSet<MetadataTypecode> {
        metadata
            .unknown_items()
            .iter()
            .map(|(typecode, _)| MetadataTypecode::Unknown(*typecode))
            .chain(Some(MetadataTypecode::BirthdayHeight))
            .collect()
    }
}
