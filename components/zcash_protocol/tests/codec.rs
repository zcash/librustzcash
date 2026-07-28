//! Exercises the `Encodable`/`Decodable` prototype, and in particular how far the container
//! impls in `zcash_encoding::codec` replace the `Vector` / `Optional` / `Array` combinators.
//!
//! Nothing below writes a codec for a container: every container codec is derived from its
//! element codec by a blanket impl.

use nonempty::NonEmpty;
use proptest::prelude::*;

use zcash_encoding::{
    Codec, Decodable, Encodable,
    codec::{Unprefixed, UnprefixedArgs},
    testing::{check_canonical, check_codec_roundtrip, check_codec_roundtrip_with},
};
use zcash_protocol::{
    TxId,
    value::{MAX_MONEY, Zatoshis},
};

prop_compose! {
    fn arb_txid()(bytes in prop::array::uniform32(any::<u8>())) -> TxId {
        TxId::from_bytes(bytes)
    }
}

prop_compose! {
    fn arb_zatoshis()(v in 0u64..=MAX_MONEY) -> Zatoshis {
        Zatoshis::const_from_u64(v)
    }
}

/// The two base codecs.
#[test]
fn base_codecs_roundtrip() {
    check_codec_roundtrip(&TxId::from_bytes([7u8; 32]));
    check_codec_roundtrip(&Zatoshis::const_from_u64(12_345));
}

/// `Vec<T>` replaces `Vector::read`/`Vector::write`: the length prefix and the element loop
/// come from the blanket impl, not from a closure passed at the call site.
#[test]
fn vector_combinator_is_subsumed() {
    let v: Vec<TxId> = (0..4).map(|i| TxId::from_bytes([i as u8; 32])).collect();
    check_codec_roundtrip(&v);
    check_codec_roundtrip(&Vec::<TxId>::new());
}

/// `Option<T>` replaces `Optional::read`/`Optional::write`.
#[test]
fn optional_combinator_is_subsumed() {
    check_codec_roundtrip(&Some(Zatoshis::const_from_u64(1)));
    check_codec_roundtrip(&None::<Zatoshis>);
}

/// `NonEmpty<T>` replaces `Vector::write_nonempty`.
#[test]
fn nonempty_combinator_is_subsumed() {
    let ne = NonEmpty::from_vec(vec![
        Zatoshis::const_from_u64(1),
        Zatoshis::const_from_u64(2),
    ])
    .unwrap();
    check_codec_roundtrip_with(&ne, ());
}

/// The combinators compose without any per-combination code.
#[test]
fn combinators_compose() {
    let nested: Vec<Option<TxId>> = vec![
        Some(TxId::from_bytes([1u8; 32])),
        None,
        Some(TxId::from_bytes([2u8; 32])),
    ];
    check_codec_roundtrip(&nested);

    let deep: Option<Vec<Vec<Zatoshis>>> = Some(vec![
        vec![Zatoshis::const_from_u64(1)],
        vec![],
        vec![Zatoshis::const_from_u64(2), Zatoshis::const_from_u64(3)],
    ]);
    check_codec_roundtrip(&deep);
}

/// A generic function over the trait: this is what the closure-passing form cannot express,
/// because there the element codec is a value rather than a resolved bound.
fn roundtrip_any<T: Codec + PartialEq + core::fmt::Debug>(value: &T) {
    check_codec_roundtrip(value);
}

#[test]
fn generic_over_the_trait() {
    roundtrip_any(&TxId::from_bytes([9u8; 32]));
    roundtrip_any(&vec![Zatoshis::const_from_u64(5)]);
    roundtrip_any(&Some(vec![TxId::from_bytes([0u8; 32])]));
}

/// The bytes really are the pre-existing wire format, not a new one.
#[test]
fn encoding_matches_the_existing_format() {
    let txid = TxId::from_bytes([0xABu8; 32]);

    let mut via_trait = Vec::new();
    Encodable::write(&txid, &mut via_trait).unwrap();

    let mut via_inherent = Vec::new();
    TxId::write(&txid, &mut via_inherent).unwrap();

    assert_eq!(via_trait, via_inherent);

    // A `Vec<TxId>` must match what `Vector::write` produces for the same elements.
    let items = vec![txid, TxId::from_bytes([0x01u8; 32])];
    let mut via_trait = Vec::new();
    Encodable::write(&items, &mut via_trait).unwrap();

    let mut via_combinator = Vec::new();
    zcash_encoding::Vector::write(&mut via_combinator, &items, |w, e| TxId::write(e, w)).unwrap();

    assert_eq!(via_trait, via_combinator);
}

/// `Array` cannot be a second `Decodable for Vec<T>`; it needs its own type. This checks the
/// wrapper both round-trips and threads the count through `Args`.
#[test]
fn array_combinator_needs_its_own_type() {
    let items = vec![TxId::from_bytes([3u8; 32]), TxId::from_bytes([4u8; 32])];
    let arr = Unprefixed(items.clone());

    check_codec_roundtrip_with(
        &arr,
        UnprefixedArgs {
            count: 2,
            element: (),
        },
    );

    // No length prefix: the encoding must be exactly the concatenated elements.
    let mut bytes = Vec::new();
    Encodable::write(&arr, &mut bytes).unwrap();
    assert_eq!(bytes.len(), 64);

    let mut via_combinator = Vec::new();
    zcash_encoding::Array::write(&mut via_combinator, &items, |w, e| TxId::write(e, w)).unwrap();
    assert_eq!(bytes, via_combinator);
}

// ---------------------------------------------------------------------------
// The `Args<'a>` case: context that is a *borrow*, which is the `Block::read(r, &params)`
// shape. If the GAT could not carry a lifetime, `Block` could not implement the trait.
// ---------------------------------------------------------------------------

/// Stands in for `consensus::Parameters`: decoding needs it, but it is not in the byte stream.
struct Network {
    coin_type: u32,
}

#[derive(Debug, PartialEq, Eq)]
struct AddressIndex {
    coin_type: u32,
    index: u32,
}

impl Encodable for AddressIndex {
    fn write<W: corez::io::Write>(&self, mut writer: W) -> corez::io::Result<()> {
        // Only `index` goes on the wire; `coin_type` comes from the decoding context.
        writer.write_all(&self.index.to_le_bytes())
    }

    fn serialized_size(&self) -> usize {
        4
    }
}

impl Decodable for AddressIndex {
    type Args<'a> = &'a Network;

    fn read<R: corez::io::Read>(mut reader: R, params: &Network) -> corez::io::Result<Self> {
        let mut bytes = [0u8; 4];
        reader.read_exact(&mut bytes)?;
        Ok(AddressIndex {
            coin_type: params.coin_type,
            index: u32::from_le_bytes(bytes),
        })
    }
}

#[test]
fn args_can_be_a_borrow() {
    let network = Network { coin_type: 133 };
    let value = AddressIndex {
        coin_type: 133,
        index: 7,
    };
    check_codec_roundtrip_with(&value, &network);
}

/// And the container impls thread a borrowed context through to every element, with no
/// per-container code. This is what makes `Args` compose rather than being a special case.
#[test]
fn borrowed_args_thread_through_combinators() {
    let network = Network { coin_type: 133 };

    let items = vec![
        AddressIndex {
            coin_type: 133,
            index: 0,
        },
        AddressIndex {
            coin_type: 133,
            index: 1,
        },
    ];
    check_codec_roundtrip_with(&items, &network);

    let nested = Some(vec![AddressIndex {
        coin_type: 133,
        index: 42,
    }]);
    check_codec_roundtrip_with(&nested, &network);
}

proptest! {
    #[test]
    fn prop_txid_vec_roundtrip(items in prop::collection::vec(arb_txid(), 0..16)) {
        check_codec_roundtrip(&items);
    }

    #[test]
    fn prop_nested_roundtrip(
        items in prop::collection::vec(prop::option::of(arb_zatoshis()), 0..8)
    ) {
        check_codec_roundtrip(&items);
    }

    #[test]
    fn prop_decodable_rejects_nothing_it_wrote(v in arb_zatoshis()) {
        let mut bytes = Vec::new();
        Encodable::write(&v, &mut bytes).unwrap();
        let back = <Zatoshis as Decodable>::read(&bytes[..], ()).unwrap();
        prop_assert_eq!(v, back);
    }
}

// ---------------------------------------------------------------------------
// Canonicity: the property the round-trip test cannot reach, because it quantifies over
// arbitrary byte strings rather than over values.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_txid_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
        check_canonical::<TxId>(&bytes, ());
    }

    #[test]
    fn prop_zatoshis_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..24)) {
        check_canonical::<Zatoshis>(&bytes, ());
    }

    #[test]
    fn prop_option_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..24)) {
        check_canonical::<Option<Zatoshis>>(&bytes, ());
    }

    #[test]
    fn prop_vec_is_canonical(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        check_canonical::<Vec<Zatoshis>>(&bytes, ());
    }

    /// Biased toward the CompactSize boundary encodings, where non-canonical forms live:
    /// a length below 253 may only use the 1-byte form, and so on.
    #[test]
    fn prop_vec_is_canonical_near_compactsize_boundaries(
        tag in prop::sample::select(vec![0u8, 1, 252, 253, 254, 255]),
        rest in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        let mut bytes = vec![tag];
        bytes.extend_from_slice(&rest);
        check_canonical::<Vec<Zatoshis>>(&bytes, ());
    }
}
