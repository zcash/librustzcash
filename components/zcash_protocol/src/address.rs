//! Types related to Zcash address encoding.

use core::fmt;

/// The revision of ZIP 316 Unified Encoding used for a particular address or viewing key.
///
/// See [ZIP 316](https://zips.z.cash/zip-0316) for details.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Revision {
    /// Revision 0 of the unified encoding format.
    ///
    /// This is the original format, which requires at least one shielded receiver
    /// in both Unified Addresses and Unified Viewing Keys.
    R0,
    /// Revision 2 of the unified encoding format.
    ///
    /// This revision adds support for metadata items (such as address expiry) and
    /// allows transparent-only Unified Viewing Keys. Unified Addresses in R2 must
    /// not contain transparent receivers and must still contain at least one shielded
    /// receiver.
    R2,
}

impl Revision {
    /// Returns the revision number as a `u32`.
    pub fn number(&self) -> u32 {
        match self {
            Revision::R0 => 0,
            Revision::R2 => 2,
        }
    }
}

impl fmt::Display for Revision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Revision::R0 => write!(f, "R0"),
            Revision::R2 => write!(f, "R2"),
        }
    }
}

impl PartialOrd for Revision {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Revision {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.number().cmp(&other.number())
    }
}

#[cfg(test)]
mod tests {
    use super::Revision;
    use alloc::string::ToString;

    #[test]
    fn display() {
        assert_eq!(Revision::R0.to_string(), "R0");
        assert_eq!(Revision::R2.to_string(), "R2");
    }

    #[test]
    fn ordering() {
        assert!(Revision::R0 < Revision::R2);
        assert!(Revision::R2 > Revision::R0);
        assert_eq!(Revision::R0, Revision::R0);
    }

    #[test]
    fn number() {
        assert_eq!(Revision::R0.number(), 0);
        assert_eq!(Revision::R2.number(), 2);
    }
}
