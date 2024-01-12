use std::cmp::Ordering;
use std::ops::{Not, Range};

use zcash_primitives::consensus::BlockHeight;

use crate::data_api::scanning::ScanFlags;

use super::{ScanPriority, ScanRange};

#[derive(Debug, Clone, Copy)]
enum InsertOn {
    Left,
    Right,
}

struct Insert {
    on: InsertOn,
    force_rescan: bool,
}

impl Insert {
    fn left(force_rescan: bool) -> Self {
        Insert {
            on: InsertOn::Left,
            force_rescan,
        }
    }

    fn right(force_rescan: bool) -> Self {
        Insert {
            on: InsertOn::Right,
            force_rescan,
        }
    }
}

impl Not for Insert {
    type Output = Self;

    fn not(self) -> Self::Output {
        Insert {
            on: match self.on {
                InsertOn::Left => InsertOn::Right,
                InsertOn::Right => InsertOn::Left,
            },
            force_rescan: self.force_rescan,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dominance {
    Left,
    Right,
    Equal,
}

impl From<Insert> for Dominance {
    fn from(value: Insert) -> Self {
        match value.on {
            InsertOn::Left => Dominance::Left,
            InsertOn::Right => Dominance::Right,
        }
    }
}

// This implements the dominance rule for range priority. If the inserted range's priority is
// `Verify`, this replaces any existing priority. Otherwise, if the current priority is
// `Scanned`, it remains as `Scanned`; and if the new priority is `Scanned`, it
// overrides any existing priority.
fn dominance(current: &ScanPriority, inserted: &ScanPriority, insert: Insert) -> Dominance {
    match (current.cmp(inserted), (current, inserted)) {
        (Ordering::Equal, _) => Dominance::Equal,
        (_, (_, ScanPriority::Verify | ScanPriority::Scanned)) => Dominance::from(insert),
        (_, (ScanPriority::Scanned, _)) if !insert.force_rescan => Dominance::from(!insert),
        (Ordering::Less, _) => Dominance::from(insert),
        (Ordering::Greater, _) => Dominance::from(!insert),
    }
}

/// In the comments for each alternative, `()` represents the left range and `[]` represents the right range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeOrdering {
    /// `(   ) [   ]`
    LeftFirstDisjoint,
    /// `( [   ) ]`
    LeftFirstOverlap,
    /// `[ (   ) ]`
    LeftContained,
    /// ```text
    /// (   )
    /// [   ]
    /// ```
    Equal,
    /// `( [   ] )`
    RightContained,
    /// `[ (   ] )`
    RightFirstOverlap,
    /// `[   ] (   )`
    RightFirstDisjoint,
}

impl RangeOrdering {
    fn cmp<A: Ord>(a: &Range<A>, b: &Range<A>) -> Self {
        use Ordering::*;
        assert!(a.start <= a.end && b.start <= b.end);
        match (a.start.cmp(&b.start), a.end.cmp(&b.end)) {
            _ if a.end <= b.start => RangeOrdering::LeftFirstDisjoint,
            _ if b.end <= a.start => RangeOrdering::RightFirstDisjoint,
            (Less, Less) => RangeOrdering::LeftFirstOverlap,
            (Equal, Less) | (Greater, Less) | (Greater, Equal) => RangeOrdering::LeftContained,
            (Equal, Equal) => RangeOrdering::Equal,
            (Equal, Greater) | (Less, Greater) | (Less, Equal) => RangeOrdering::RightContained,
            (Greater, Greater) => RangeOrdering::RightFirstOverlap,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Joined {
    One(ScanRange),
    Two(ScanRange, ScanRange),
    Three(ScanRange, ScanRange, ScanRange),
}

fn join_nonoverlapping(left: ScanRange, right: ScanRange) -> Joined {
    assert!(left.block_range().end <= right.block_range().start);

    if left.block_range().end == right.block_range().start {
        if left.priority() == right.priority() && left.flags() == right.flags() {
            Joined::One(ScanRange::from_parts(
                left.block_range().start..right.block_range().end,
                left.priority(),
                left.flags(),
            ))
        } else {
            Joined::Two(left, right)
        }
    } else {
        // there is a gap that will need to be filled
        let gap = ScanRange::from_parts(
            left.block_range().end..right.block_range().start,
            ScanPriority::Historic,
            ScanFlags::all(),
        );

        match join_nonoverlapping(left, gap) {
            Joined::One(merged) => join_nonoverlapping(merged, right),
            Joined::Two(left, gap) => match join_nonoverlapping(gap, right) {
                Joined::One(merged) => Joined::Two(left, merged),
                Joined::Two(gap, right) => Joined::Three(left, gap, right),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }
}

fn insert(current: ScanRange, to_insert: ScanRange, force_rescans: bool) -> Joined {
    fn join_overlapping(left: ScanRange, right: ScanRange, insert: Insert) -> Joined {
        assert!(
            left.block_range().start <= right.block_range().start
                && left.block_range().end > right.block_range().start
        );

        // recompute the range dominance based upon the queue entry priorities
        let dominance = match insert.on {
            InsertOn::Left => dominance(&right.priority(), &left.priority(), insert),
            InsertOn::Right => dominance(&left.priority(), &right.priority(), insert),
        };

        let pre_overlap = left.truncate_end(right.block_range().start);
        let overlap = left
            .truncate_start(right.block_range().start)
            .and_then(|mid| {
                // If the right argument is fully contained in the left range, then
                // we have to truncate its end
                mid.truncate_end(right.block_range().end).map(|mid| {
                    mid.with_flags(left.flags() | right.flags())
                        .with_priority(match dominance {
                            Dominance::Left | Dominance::Equal => left.priority(),
                            Dominance::Right => right.priority(),
                        })
                })
            });
        let post_overlap = right
            .truncate_start(left.block_range().end)
            .or_else(|| left.truncate_start(right.block_range().end));

        match (pre_overlap, overlap, post_overlap) {
            (Some(pre), Some(mid), Some(post)) => match join_nonoverlapping(pre, mid) {
                Joined::One(l) => join_nonoverlapping(l, post),
                Joined::Two(l, m) => match join_nonoverlapping(m, post) {
                    Joined::One(r) => Joined::Two(l, r),
                    Joined::Two(m, r) => Joined::Three(l, m, r),
                    _ => unreachable!(),
                },
                _ => unreachable!(),
            },
            (Some(pre), Some(mid), None) => join_nonoverlapping(pre, mid),
            (None, Some(mid), Some(post)) => join_nonoverlapping(mid, post),
            (None, Some(mid), None) => Joined::One(mid),
            _ => unreachable!(
                "The assertion at the start of this function ensures that some overlap exists."
            ),
        }
    }

    use RangeOrdering::*;
    match RangeOrdering::cmp(to_insert.block_range(), current.block_range()) {
        LeftFirstDisjoint => join_nonoverlapping(to_insert, current),
        LeftFirstOverlap | RightContained => {
            join_overlapping(to_insert, current, Insert::left(force_rescans))
        }
        Equal => {
            let dom = dominance(
                &current.priority(),
                &to_insert.priority(),
                Insert::right(force_rescans),
            );
            Joined::One(ScanRange::from_parts(
                to_insert.block_range().clone(),
                match dom {
                    Dominance::Left | Dominance::Equal => current.priority(),
                    Dominance::Right => to_insert.priority(),
                },
                match dom {
                    Dominance::Left => current.flags(),
                    Dominance::Equal => to_insert.flags() | current.flags(),
                    Dominance::Right => to_insert.flags(),
                },
            ))
        }
        RightFirstOverlap | LeftContained => {
            join_overlapping(current, to_insert, Insert::right(force_rescans))
        }
        RightFirstDisjoint => join_nonoverlapping(current, to_insert),
    }
}

#[derive(Debug, Clone)]
#[cfg(feature = "unstable-spanning-tree")]
pub enum SpanningTree {
    Leaf(ScanRange),
    Parent {
        span: Range<BlockHeight>,
        left: Box<SpanningTree>,
        right: Box<SpanningTree>,
    },
}

#[cfg(feature = "unstable-spanning-tree")]
impl SpanningTree {
    fn span(&self) -> Range<BlockHeight> {
        match self {
            SpanningTree::Leaf(entry) => entry.block_range().clone(),
            SpanningTree::Parent { span, .. } => span.clone(),
        }
    }

    fn from_joined(joined: Joined) -> Self {
        match joined {
            Joined::One(entry) => SpanningTree::Leaf(entry),
            Joined::Two(left, right) => SpanningTree::Parent {
                span: left.block_range().start..right.block_range().end,
                left: Box::new(SpanningTree::Leaf(left)),
                right: Box::new(SpanningTree::Leaf(right)),
            },
            Joined::Three(left, mid, right) => SpanningTree::Parent {
                span: left.block_range().start..right.block_range().end,
                left: Box::new(SpanningTree::Leaf(left)),
                right: Box::new(SpanningTree::Parent {
                    span: mid.block_range().start..right.block_range().end,
                    left: Box::new(SpanningTree::Leaf(mid)),
                    right: Box::new(SpanningTree::Leaf(right)),
                }),
            },
        }
    }

    fn from_insert(
        left: Box<Self>,
        right: Box<Self>,
        to_insert: ScanRange,
        insert: Insert,
    ) -> Self {
        let (left, right) = match insert.on {
            InsertOn::Left => (Box::new(left.insert(to_insert, insert.force_rescan)), right),
            InsertOn::Right => (left, Box::new(right.insert(to_insert, insert.force_rescan))),
        };
        SpanningTree::Parent {
            span: left.span().start..right.span().end,
            left,
            right,
        }
    }

    fn from_split(
        left: Self,
        right: Self,
        to_insert: ScanRange,
        split_point: BlockHeight,
        force_rescans: bool,
    ) -> Self {
        let (l_insert, r_insert) = to_insert
            .split_at(split_point)
            .expect("Split point is within the range of to_insert");
        let left = Box::new(left.insert(l_insert, force_rescans));
        let right = Box::new(right.insert(r_insert, force_rescans));
        SpanningTree::Parent {
            span: left.span().start..right.span().end,
            left,
            right,
        }
    }

    pub fn insert(self, to_insert: ScanRange, force_rescans: bool) -> Self {
        match self {
            SpanningTree::Leaf(cur) => Self::from_joined(insert(cur, to_insert, force_rescans)),
            SpanningTree::Parent { span, left, right } => {
                // This algorithm always preserves the existing partition point, and does not do
                // any rebalancing or unification of ranges within the tree. This should be okay
                // because `into_vec` performs such unification, and the tree being unbalanced
                // should be fine given the relatively small number of ranges we should ordinarily
                // be concerned with.
                use RangeOrdering::*;
                match RangeOrdering::cmp(&span, to_insert.block_range()) {
                    LeftFirstDisjoint => {
                        // extend the right-hand branch
                        Self::from_insert(left, right, to_insert, Insert::right(force_rescans))
                    }
                    LeftFirstOverlap => {
                        let split_point = left.span().end;
                        if split_point > to_insert.block_range().start {
                            Self::from_split(*left, *right, to_insert, split_point, force_rescans)
                        } else {
                            // to_insert is fully contained in or equals the right child
                            Self::from_insert(left, right, to_insert, Insert::right(force_rescans))
                        }
                    }
                    RightContained => {
                        // to_insert is fully contained within the current span, so we will insert
                        // into one or both sides
                        let split_point = left.span().end;
                        if to_insert.block_range().start >= split_point {
                            // to_insert is fully contained in the right
                            Self::from_insert(left, right, to_insert, Insert::right(force_rescans))
                        } else if to_insert.block_range().end <= split_point {
                            // to_insert is fully contained in the left
                            Self::from_insert(left, right, to_insert, Insert::left(force_rescans))
                        } else {
                            // to_insert must be split.
                            Self::from_split(*left, *right, to_insert, split_point, force_rescans)
                        }
                    }
                    Equal => {
                        let split_point = left.span().end;
                        if split_point > to_insert.block_range().start {
                            Self::from_split(*left, *right, to_insert, split_point, force_rescans)
                        } else {
                            // to_insert is fully contained in the right subtree
                            right.insert(to_insert, force_rescans)
                        }
                    }
                    LeftContained => {
                        // the current span is fully contained within to_insert, so we will extend
                        // or overwrite both sides
                        let split_point = left.span().end;
                        Self::from_split(*left, *right, to_insert, split_point, force_rescans)
                    }
                    RightFirstOverlap => {
                        let split_point = left.span().end;
                        if split_point < to_insert.block_range().end {
                            Self::from_split(*left, *right, to_insert, split_point, force_rescans)
                        } else {
                            // to_insert is fully contained in or equals the left child
                            Self::from_insert(left, right, to_insert, Insert::left(force_rescans))
                        }
                    }
                    RightFirstDisjoint => {
                        // extend the left-hand branch
                        Self::from_insert(left, right, to_insert, Insert::left(force_rescans))
                    }
                }
            }
        }
    }

    pub fn into_vec(self) -> Vec<ScanRange> {
        fn go(acc: &mut Vec<ScanRange>, tree: SpanningTree) {
            match tree {
                SpanningTree::Leaf(entry) => {
                    if !entry.is_empty() {
                        if let Some(top) = acc.pop() {
                            match join_nonoverlapping(top, entry) {
                                Joined::One(merged) => acc.push(merged),
                                Joined::Two(l, r) => {
                                    acc.push(l);
                                    acc.push(r);
                                }
                                _ => unreachable!(),
                            }
                        } else {
                            acc.push(entry);
                        }
                    }
                }
                SpanningTree::Parent { left, right, .. } => {
                    go(acc, *left);
                    go(acc, *right);
                }
            }
        }

        let mut acc = vec![];
        go(&mut acc, self);
        acc
    }
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use std::ops::Range;

    use zcash_primitives::consensus::BlockHeight;

    use crate::data_api::scanning::{ScanFlags, ScanPriority, ScanRange};

    pub fn scan_range(range: Range<u32>, priority: ScanPriority, flags: ScanFlags) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from(range.start)..BlockHeight::from(range.end),
            priority,
            flags,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use zcash_primitives::consensus::BlockHeight;

    use super::{join_nonoverlapping, testing::scan_range, Joined, RangeOrdering, SpanningTree};
    use crate::data_api::scanning::{ScanFlags, ScanPriority, ScanRange};

    const NO_FLAGS: ScanFlags = ScanFlags::empty();

    #[test]
    fn test_join_nonoverlapping() {
        fn test_range(left: ScanRange, right: ScanRange, expected_joined: Joined) {
            let joined = join_nonoverlapping(left, right);

            assert_eq!(joined, expected_joined);
        }

        macro_rules! range {
            ( $start:expr, $end:expr; $priority:ident ) => {
                ScanRange::from_parts(
                    BlockHeight::from($start)..BlockHeight::from($end),
                    ScanPriority::$priority,
                    NO_FLAGS,
                )
            };
            ( $start:expr, $end:expr; $priority:ident; $flags:expr ) => {
                ScanRange::from_parts(
                    BlockHeight::from($start)..BlockHeight::from($end),
                    ScanPriority::$priority,
                    $flags,
                )
            };
        }

        macro_rules! joined {
            (
                ($a_start:expr, $a_end:expr; $a_priority:ident)
            ) => {
                Joined::One(
                    range!($a_start, $a_end; $a_priority)
                )
            };
            (
                ($a_start:expr, $a_end:expr; $a_priority:ident),
                ($b_start:expr, $b_end:expr; $b_priority:ident)
            ) => {
                Joined::Two(
                    range!($a_start, $a_end; $a_priority),
                    range!($b_start, $b_end; $b_priority)
                )
            };
            (
                ($a_start:expr, $a_end:expr; $a_priority:ident),
                ($b_start:expr, $b_end:expr; $b_priority:ident),
                ($c_start:expr, $c_end:expr; $c_priority:ident)

            ) => {
                Joined::Three(
                    range!($a_start, $a_end; $a_priority),
                    range!($b_start, $b_end; $b_priority),
                    range!($c_start, $c_end; $c_priority)
                )
            };
            (
                ($a_start:expr, $a_end:expr; $a_priority:ident),
                ($b_start:expr, $b_end:expr; $b_priority:ident; $flags:expr),
                ($c_start:expr, $c_end:expr; $c_priority:ident)

            ) => {
                Joined::Three(
                    range!($a_start, $a_end; $a_priority),
                    range!($b_start, $b_end; $b_priority; $flags),
                    range!($c_start, $c_end; $c_priority)
                )
            };
        }

        // Scan ranges have the same priority and
        // line up.
        test_range(
            range!(1, 9; OpenAdjacent),
            range!(9, 15; OpenAdjacent),
            joined!(
                (1, 15; OpenAdjacent)
            ),
        );

        // Scan ranges have different priorities,
        // so we cannot merge them even though they
        // line up.
        test_range(
            range!(1, 9; OpenAdjacent),
            range!(9, 15; ChainTip),
            joined!(
                (1, 9; OpenAdjacent),
                (9, 15; ChainTip)
            ),
        );

        // Scan ranges have the same priority but
        // do not line up.
        test_range(
            range!(1, 9; OpenAdjacent),
            range!(13, 15; OpenAdjacent),
            joined!(
                (1, 9; OpenAdjacent),
                (9, 13; Historic; ScanFlags::all()),
                (13, 15; OpenAdjacent)
            ),
        );

        test_range(
            range!(1, 9; Historic),
            range!(13, 15; OpenAdjacent),
            joined!(
                (1, 9; Historic),
                (9, 13; Historic; ScanFlags::all()),
                (13, 15; OpenAdjacent)
            ),
        );

        test_range(
            range!(1, 9; OpenAdjacent),
            range!(13, 15; Historic),
            joined!(
                (1, 9; OpenAdjacent),
                (9, 13; Historic; ScanFlags::all()),
                (13, 15; Historic)
            ),
        );
    }

    #[test]
    fn range_ordering() {
        use super::RangeOrdering::*;
        // Equal
        assert_eq!(RangeOrdering::cmp(&(0..1), &(0..1)), Equal);

        // Disjoint or contiguous
        assert_eq!(RangeOrdering::cmp(&(0..1), &(1..2)), LeftFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(1..2), &(0..1)), RightFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(0..1), &(2..3)), LeftFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(2..3), &(0..1)), RightFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(1..2), &(2..2)), LeftFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(2..2), &(1..2)), RightFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(1..1), &(1..2)), LeftFirstDisjoint);
        assert_eq!(RangeOrdering::cmp(&(1..2), &(1..1)), RightFirstDisjoint);

        // Contained
        assert_eq!(RangeOrdering::cmp(&(1..2), &(0..3)), LeftContained);
        assert_eq!(RangeOrdering::cmp(&(0..3), &(1..2)), RightContained);
        assert_eq!(RangeOrdering::cmp(&(0..1), &(0..3)), LeftContained);
        assert_eq!(RangeOrdering::cmp(&(0..3), &(0..1)), RightContained);
        assert_eq!(RangeOrdering::cmp(&(2..3), &(0..3)), LeftContained);
        assert_eq!(RangeOrdering::cmp(&(0..3), &(2..3)), RightContained);

        // Overlap
        assert_eq!(RangeOrdering::cmp(&(0..2), &(1..3)), LeftFirstOverlap);
        assert_eq!(RangeOrdering::cmp(&(1..3), &(0..2)), RightFirstOverlap);
    }

    fn spanning_tree(to_insert: &[(Range<u32>, ScanPriority, ScanFlags)]) -> Option<SpanningTree> {
        to_insert
            .iter()
            .fold(None, |acc, (range, priority, flags)| {
                let scan_range = scan_range(range.clone(), *priority, *flags);
                match acc {
                    None => Some(SpanningTree::Leaf(scan_range)),
                    Some(t) => Some(t.insert(scan_range, false)),
                }
            })
    }

    #[test]
    fn spanning_tree_insert_adjacent() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            (3..6, Scanned, NO_FLAGS),
            (6..8, ChainTip, NO_FLAGS),
            (8..10, ChainTip, NO_FLAGS),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic, NO_FLAGS),
                scan_range(3..6, Scanned, NO_FLAGS),
                scan_range(6..10, ChainTip, NO_FLAGS),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_overlaps() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            (2..5, Scanned, NO_FLAGS),
            // 5..6 mind the gap!
            (6..8, ChainTip, NO_FLAGS),
            (7..10, Scanned, NO_FLAGS),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Historic, NO_FLAGS),
                scan_range(2..5, Scanned, NO_FLAGS),
                scan_range(5..6, Historic, ScanFlags::all()),
                scan_range(6..7, ChainTip, NO_FLAGS),
                scan_range(7..10, Scanned, NO_FLAGS),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_empty() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            (3..6, Scanned, NO_FLAGS),
            (6..6, FoundNote, NO_FLAGS),
            (6..8, Scanned, NO_FLAGS),
            (8..10, ChainTip, NO_FLAGS),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic, NO_FLAGS),
                scan_range(3..8, Scanned, NO_FLAGS),
                scan_range(8..10, ChainTip, NO_FLAGS),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_gaps() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            // 3..6 mind the gap!
            (6..8, ChainTip, NO_FLAGS),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic, NO_FLAGS),
                scan_range(3..6, Historic, ScanFlags::all()),
                scan_range(6..8, ChainTip, NO_FLAGS),
            ]
        );

        let t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            (3..4, Verify, NO_FLAGS),
            // 4..6 mind the gap!
            (6..8, ChainTip, NO_FLAGS),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic, NO_FLAGS),
                scan_range(3..4, Verify, NO_FLAGS),
                scan_range(4..6, Historic, ScanFlags::all()),
                scan_range(6..8, ChainTip, NO_FLAGS),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_rfd_span() {
        use ScanPriority::*;

        // This sequence of insertions causes a RightFirstDisjoint on the last insertion,
        // which originally had a bug that caused the parent's span to only cover its left
        // child. The bug was otherwise unobservable as the insertion logic was able to
        // heal this specific kind of bug.
        let t = spanning_tree(&[
            // 6..8
            (6..8, Scanned, NO_FLAGS),
            //       6..12
            // 6..8        8..12
            //         8..10  10..12
            (10..12, ChainTip, NO_FLAGS),
            //          3..12
            //    3..8        8..12
            // 3..6  6..8  8..10  10..12
            (3..6, Historic, NO_FLAGS),
        ])
        .unwrap();

        assert_eq!(t.span(), (3.into())..(12.into()));
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(3..6, Historic, NO_FLAGS),
                scan_range(6..8, Scanned, NO_FLAGS),
                scan_range(8..10, Historic, ScanFlags::all()),
                scan_range(10..12, ChainTip, NO_FLAGS),
            ]
        );
    }

    #[test]
    fn spanning_tree_dominance() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Verify, NO_FLAGS),
            (2..8, Scanned, NO_FLAGS),
            (6..10, Verify, NO_FLAGS),
        ])
        .unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Verify, NO_FLAGS),
                scan_range(2..6, Scanned, NO_FLAGS),
                scan_range(6..10, Verify, NO_FLAGS),
            ]
        );

        let t = spanning_tree(&[
            (0..3, Verify, NO_FLAGS),
            (2..8, Historic, NO_FLAGS),
            (6..10, Verify, NO_FLAGS),
        ])
        .unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Verify, NO_FLAGS),
                scan_range(3..6, Historic, NO_FLAGS),
                scan_range(6..10, Verify, NO_FLAGS),
            ]
        );

        let t = spanning_tree(&[
            (0..3, Scanned, NO_FLAGS),
            (2..8, Verify, NO_FLAGS),
            (6..10, Scanned, NO_FLAGS),
        ])
        .unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Scanned, NO_FLAGS),
                scan_range(2..6, Verify, NO_FLAGS),
                scan_range(6..10, Scanned, NO_FLAGS),
            ]
        );

        let t = spanning_tree(&[
            (0..3, Scanned, NO_FLAGS),
            (2..8, Historic, NO_FLAGS),
            (6..10, Scanned, NO_FLAGS),
        ])
        .unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Scanned, NO_FLAGS),
                scan_range(3..6, Historic, NO_FLAGS),
                scan_range(6..10, Scanned, NO_FLAGS),
            ]
        );

        // a `ChainTip` insertion should not overwrite a scanned range.
        let mut t = spanning_tree(&[
            (0..3, ChainTip, NO_FLAGS),
            (3..5, Scanned, NO_FLAGS),
            (5..7, ChainTip, NO_FLAGS),
        ])
        .unwrap();
        t = t.insert(scan_range(0..7, ChainTip, NO_FLAGS), false);
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, ChainTip, NO_FLAGS),
                scan_range(3..5, Scanned, NO_FLAGS),
                scan_range(5..7, ChainTip, NO_FLAGS),
            ]
        );

        let mut t = spanning_tree(&[
            (280300..280310, FoundNote, NO_FLAGS),
            (280310..280320, Scanned, NO_FLAGS),
        ])
        .unwrap();
        assert_eq!(
            t.clone().into_vec(),
            vec![
                scan_range(280300..280310, FoundNote, NO_FLAGS),
                scan_range(280310..280320, Scanned, NO_FLAGS)
            ]
        );
        t = t.insert(scan_range(280300..280340, ChainTip, NO_FLAGS), false);
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(280300..280310, ChainTip, NO_FLAGS),
                scan_range(280310..280320, Scanned, NO_FLAGS),
                scan_range(280320..280340, ChainTip, NO_FLAGS)
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_coalesce_scanned() {
        use ScanPriority::*;

        let mut t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            (2..5, Scanned, NO_FLAGS),
            // 5..6 mind the gap
            (6..8, ChainTip, NO_FLAGS),
            (7..10, Scanned, NO_FLAGS),
        ])
        .unwrap();

        t = t.insert(scan_range(0..3, Scanned, NO_FLAGS), false);
        t = t.insert(scan_range(5..8, Scanned, NO_FLAGS), false);
        assert_eq!(t.into_vec(), vec![scan_range(0..10, Scanned, NO_FLAGS)]);
    }

    #[test]
    fn spanning_tree_force_rescans() {
        use ScanPriority::*;

        let mut t = spanning_tree(&[
            (0..3, Historic, NO_FLAGS),
            (3..5, Scanned, NO_FLAGS),
            (5..7, ChainTip, NO_FLAGS),
            (7..10, Scanned, NO_FLAGS),
        ])
        .unwrap();

        t = t.insert(scan_range(4..9, OpenAdjacent, NO_FLAGS), true);

        let expected = vec![
            scan_range(0..3, Historic, NO_FLAGS),
            scan_range(3..4, Scanned, NO_FLAGS),
            scan_range(4..5, OpenAdjacent, NO_FLAGS),
            scan_range(5..7, ChainTip, NO_FLAGS),
            scan_range(7..9, OpenAdjacent, NO_FLAGS),
            scan_range(9..10, Scanned, NO_FLAGS),
        ];
        assert_eq!(t.clone().into_vec(), expected);

        // An insert of an ignored range should not override a scanned range; the existing
        // priority should prevail, and so the expected state of the tree is unchanged.
        t = t.insert(scan_range(2..5, Ignored, NO_FLAGS), true);
        assert_eq!(t.into_vec(), expected);
    }
}
