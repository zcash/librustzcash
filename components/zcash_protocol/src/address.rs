//! Types related to Zcash address parsing & encoding.

/// The [revision] of the Unified Address standard that an address was parsed under.
///
/// [revision]: https://zips.z.cash/zip-0316#revisions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revision {
    /// Identifier for ZIP 316 Revision 0
    R0,
    /// Identifier for ZIP 316 Revision 1
    R1,
}
