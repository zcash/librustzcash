use std::cmp::{max, Ordering};
use std::ops::{Not, Range};

use zcash_primitives::consensus::BlockHeight;

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
        if left.priority() == right.priority() {
            Joined::One(ScanRange::from_parts(
                left.block_range().start..right.block_range().end,
                left.priority(),
            ))
        } else {
            Joined::Two(left, right)
        }
    } else {
        // there is a gap that will need to be filled
        let gap = ScanRange::from_parts(
            left.block_range().end..right.block_range().start,
            ScanPriority::Historic,
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

        match dominance {
            Dominance::Left => {
                if let Some(right) = right.truncate_start(left.block_range().end) {
                    Joined::Two(left, right)
                } else {
                    Joined::One(left)
                }
            }
            Dominance::Equal => Joined::One(ScanRange::from_parts(
                left.block_range().start..max(left.block_range().end, right.block_range().end),
                left.priority(),
            )),
            Dominance::Right => match (
                left.truncate_end(right.block_range().start),
                left.truncate_start(right.block_range().end),
            ) {
                (Some(before), Some(after)) => Joined::Three(before, right, after),
                (Some(before), None) => Joined::Two(before, right),
                (None, Some(after)) => Joined::Two(right, after),
                (None, None) => Joined::One(right),
            },
        }
    }

    use RangeOrdering::*;
    match RangeOrdering::cmp(to_insert.block_range(), current.block_range()) {
        LeftFirstDisjoint => join_nonoverlapping(to_insert, current),
        LeftFirstOverlap | RightContained => {
            join_overlapping(to_insert, current, Insert::left(force_rescans))
        }
        Equal => Joined::One(ScanRange::from_parts(
            to_insert.block_range().clone(),
            match dominance(
                &current.priority(),
                &to_insert.priority(),
                Insert::right(force_rescans),
            ) {
                Dominance::Left | Dominance::Equal => current.priority(),
                Dominance::Right => to_insert.priority(),
            },
        )),
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

    use crate::data_api::scanning::{ScanPriority, ScanRange};

    pub fn scan_range(range: Range<u32>, priority: ScanPriority) -> ScanRange {
        ScanRange::from_parts(
            BlockHeight::from(range.start)..BlockHeight::from(range.end),
            priority,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use zcash_primitives::consensus::BlockHeight;

    use super::{join_nonoverlapping, testing::scan_range, Joined, RangeOrdering, SpanningTree};
    use crate::data_api::scanning::{ScanPriority, ScanRange};

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
                (9, 13; Historic),
                (13, 15; OpenAdjacent)
            ),
        );

        test_range(
            range!(1, 9; Historic),
            range!(13, 15; OpenAdjacent),
            joined!(
                (1, 13; Historic),
                (13, 15; OpenAdjacent)
            ),
        );

        test_range(
            range!(1, 9; OpenAdjacent),
            range!(13, 15; Historic),
            joined!(
                (1, 9; OpenAdjacent),
                (9, 15; Historic)
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

    fn spanning_tree(to_insert: &[(Range<u32>, ScanPriority)]) -> Option<SpanningTree> {
        to_insert.iter().fold(None, |acc, (range, priority)| {
            let scan_range = scan_range(range.clone(), *priority);
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
            (0..3, Historic),
            (3..6, Scanned),
            (6..8, ChainTip),
            (8..10, ChainTip),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic),
                scan_range(3..6, Scanned),
                scan_range(6..10, ChainTip),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_overlaps() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic),
            (2..5, Scanned),
            (6..8, ChainTip),
            (7..10, Scanned),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Historic),
                scan_range(2..5, Scanned),
                scan_range(5..6, Historic),
                scan_range(6..7, ChainTip),
                scan_range(7..10, Scanned),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_empty() {
        use ScanPriority::*;

        let t = spanning_tree(&[
            (0..3, Historic),
            (3..6, Scanned),
            (6..6, FoundNote),
            (6..8, Scanned),
            (8..10, ChainTip),
        ])
        .unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic),
                scan_range(3..8, Scanned),
                scan_range(8..10, ChainTip),
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_gaps() {
        use ScanPriority::*;

        let t = spanning_tree(&[(0..3, Historic), (6..8, ChainTip)]).unwrap();

        assert_eq!(
            t.into_vec(),
            vec![scan_range(0..6, Historic), scan_range(6..8, ChainTip),]
        );

        let t = spanning_tree(&[(0..3, Historic), (3..4, Verify), (6..8, ChainTip)]).unwrap();

        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Historic),
                scan_range(3..4, Verify),
                scan_range(4..6, Historic),
                scan_range(6..8, ChainTip),
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
            (6..8, Scanned),
            //       6..12
            // 6..8        8..12
            //         8..10  10..12
            (10..12, ChainTip),
            //          3..12
            //    3..8        8..12
            // 3..6  6..8  8..10  10..12
            (3..6, Historic),
        ])
        .unwrap();

        assert_eq!(t.span(), (3.into())..(12.into()));
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(3..6, Historic),
                scan_range(6..8, Scanned),
                scan_range(8..10, Historic),
                scan_range(10..12, ChainTip),
            ]
        );
    }

    #[test]
    fn spanning_tree_dominance() {
        use ScanPriority::*;

        let t = spanning_tree(&[(0..3, Verify), (2..8, Scanned), (6..10, Verify)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Verify),
                scan_range(2..6, Scanned),
                scan_range(6..10, Verify),
            ]
        );

        let t = spanning_tree(&[(0..3, Verify), (2..8, Historic), (6..10, Verify)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Verify),
                scan_range(3..6, Historic),
                scan_range(6..10, Verify),
            ]
        );

        let t = spanning_tree(&[(0..3, Scanned), (2..8, Verify), (6..10, Scanned)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..2, Scanned),
                scan_range(2..6, Verify),
                scan_range(6..10, Scanned),
            ]
        );

        let t = spanning_tree(&[(0..3, Scanned), (2..8, Historic), (6..10, Scanned)]).unwrap();
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, Scanned),
                scan_range(3..6, Historic),
                scan_range(6..10, Scanned),
            ]
        );

        // a `ChainTip` insertion should not overwrite a scanned range.
        let mut t = spanning_tree(&[(0..3, ChainTip), (3..5, Scanned), (5..7, ChainTip)]).unwrap();
        t = t.insert(scan_range(0..7, ChainTip), false);
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(0..3, ChainTip),
                scan_range(3..5, Scanned),
                scan_range(5..7, ChainTip),
            ]
        );

        let mut t =
            spanning_tree(&[(280300..280310, FoundNote), (280310..280320, Scanned)]).unwrap();
        assert_eq!(
            t.clone().into_vec(),
            vec![
                scan_range(280300..280310, FoundNote),
                scan_range(280310..280320, Scanned)
            ]
        );
        t = t.insert(scan_range(280300..280340, ChainTip), false);
        assert_eq!(
            t.into_vec(),
            vec![
                scan_range(280300..280310, ChainTip),
                scan_range(280310..280320, Scanned),
                scan_range(280320..280340, ChainTip)
            ]
        );
    }

    #[test]
    fn spanning_tree_insert_coalesce_scanned() {
        use ScanPriority::*;

        let mut t = spanning_tree(&[
            (0..3, Historic),
            (2..5, Scanned),
            (6..8, ChainTip),
            (7..10, Scanned),
        ])
        .unwrap();

        t = t.insert(scan_range(0..3, Scanned), false);
        t = t.insert(scan_range(5..8, Scanned), false);

        assert_eq!(t.into_vec(), vec![scan_range(0..10, Scanned)]);
    }

    #[test]
    fn spanning_tree_force_rescans() {
        use ScanPriority::*;

        let mut t = spanning_tree(&[
            (0..3, Historic),
            (3..5, Scanned),
            (5..7, ChainTip),
            (7..10, Scanned),
        ])
        .unwrap();

        t = t.insert(scan_range(4..9, OpenAdjacent), true);

        let expected = vec![
            scan_range(0..3, Historic),
            scan_range(3..4, Scanned),
            scan_range(4..5, OpenAdjacent),
            scan_range(5..7, ChainTip),
            scan_range(7..9, OpenAdjacent),
            scan_range(9..10, Scanned),
        ];
        assert_eq!(t.clone().into_vec(), expected);

        // An insert of an ignored range should not override a scanned range; the existing
        // priority should prevail, and so the expected state of the tree is unchanged.
        t = t.insert(scan_range(2..5, Ignored), true);
        assert_eq!(t.into_vec(), expected);
    }
}
