//! Traits for types with a canonical binary encoding.
//!
//! Anything that goes on the wire or on disk must encode identically on every implementation,
//! so the encoding is part of the consensus surface rather than an implementation detail. These
//! traits give that surface one name.
//!
//! The split into [`Encodable`] and [`Decodable`] follows the shape of the two operations:
//! writing needs `&self`, reading is an associated function that needs `Self: Sized`, and plenty
//! of types need only one direction. [`Codec`] is the marker alias over the pair.
//!
//! [`Decodable`]'s type parameter carries the context a decoder needs but cannot recover from the
//! byte stream, such as the consensus branch ID required to parse a v4 transaction. It is `()`
//! for self-describing encodings.
//!
//! It is a type PARAMETER rather than an associated type. An associated type fixes a single
//! context per decoded type, and some decoders are generic over theirs: `Block` decodes under
//! any [`consensus::Parameters`], which it states
//! directly as `impl<P: Parameters> Decodable<&P> for Block`. With an associated type that is
//! inexpressible, because the associated type would have to be `&dyn Parameters` and
//! `Parameters` requires `Clone`, so it is not dyn-compatible. The cost is that a decoded type
//! must be named together with its context (`<T as Decodable<()>>`, `check_canonical::<T, _>`).
//!
//! [`consensus::Parameters`]: https://docs.rs/zcash_protocol/latest/zcash_protocol/consensus/trait.Parameters.html
//!
//! # The structure these traits implement
//!
//! Writing `B` for the set of byte strings, a codec for `T` is a pair
//!
//! ```text
//!     write : T -> B          (total)
//!     read  : B -> T          (partial)
//! ```
//!
//! Composition is written `.` below, so `g . f` means "`f` then `g`".
//!
//! ## `T` is a retract of `B`
//!
//! The law that makes the pair a codec is `read . write = id_T`: nothing is lost by encoding.
//! In categorical terms `write` is a [*section*][section] and `read` a [*retraction*][section],
//! and together they exhibit `T` as a **[retract][section]** of `B`. Setting
//! `e = write . read : B -> B` (partial), the retraction law forces `e` to be
//! [idempotent][idempotence]:
//!
//! ```text
//!     e . e = write . (read . write) . read = write . id_T . read = e
//! ```
//!
//! so `T` is the **[splitting of the idempotent][split-idempotent] `e`** (the object that the
//! [Karoubi envelope][karoubi], or idempotent completion, freely adjoins; in `Set` every
//! idempotent already splits, so here the content is that `e` is idempotent, not that a
//! splitting exists). Concretely, `e` is "normalise these bytes": decode them and re-encode.
//!
//! This is worth stating precisely because it pins down what the round-trip test can and cannot
//! establish. `read(write(v)) == v` is the retraction law. Re-encoding the *decoded* value and
//! comparing bytes adds nothing: it follows from the retraction law plus `write` being a
//! function. The independent property is
//!
//! ```text
//!     for all b in dom(read):  write(read(b)) = b        i.e.  e = id on dom(read)
//! ```
//!
//! which says the encoding is **canonical**: no value has two valid encodings. It quantifies over
//! arbitrary byte strings, not over values, so it must be tested by feeding `read` bytes it did
//! not produce. A codec that fails it is malleable, which in a consensus setting is a hazard
//! rather than a cosmetic defect: transaction-ID malleability is exactly this failure. See
//! [`crate::testing::check_canonical`].
//!
//! ## `Codec` is invariant, not covariant
//!
//! `T` appears in [*negative* position][variance] in `write` (as an argument) and in
//! [*positive* position][variance] in `read` (as a result). A structure with that shape is an
//! **[invariant functor][invariant]**: it admits no `map`. Given `f : T -> U` you cannot
//! transport a codec for `T` to one for `U`, because `write` needs to go the other way.
//! Transport requires both directions at once, that is a (partial) isomorphism `T <-> U`.
//!
//! Something with one contravariant and one covariant slot is a [profunctor][profunctor];
//! `Codec` is the diagonal case where both slots are the same type, and taking that diagonal is
//! exactly what turns `dimap : (a -> b) -> (c -> d) -> p b c -> p a d` into the invariant
//! `(a -> b) -> (b -> a) -> f a -> f b`.
//!
//! This is not a Rust artefact, it is the reason parser/printer libraries are built on partial
//! isomorphisms rather than functions. See Rendel and Ostermann, *Invertible Syntax Descriptions:
//! Unifying Parsing and Pretty Printing*, Haskell Symposium 2010
//! (<https://dl.acm.org/doi/10.1145/1863523.1863525>), whose `Syntax` interface is built from
//! `IsoFunctor` (transport along an iso), `ProductFunctor` (pairing) and [`Alternative`][alt]
//! (choice) precisely because plain [`Functor`][hs-functor] is unavailable.
//!
//! Those three are [higher-kinded][kind] abstractions: they quantify over a type *constructor*
//! `f : * -> *`, not over a type. Haskell and Idris can state them as classes over `f`, so a
//! parser combinator there is generic in the whole algebra. Rust has no such quantification, so
//! each of the three appears here as a blanket impl or a free-standing combinator rather than as
//! something a codec can be generic in. That, not any shortage of appetite, is why this module
//! is a set of impls instead of the algebra the paper describes.
//!
//! ## Where the container impls come from
//!
//! `Vec<T>`, `Option<T>` and `NonEmpty<T>` are not codecs that were written; they are the action
//! of the `List` and `Maybe` [endofunctors][functor] on codecs, which is why a single blanket
//! impl each suffices and why they compose to arbitrary depth with no per-combination code.
//! Pairing (the `ProductFunctor` above) is what would let a struct codec be assembled from its
//! field codecs and then transported along the iso "tuple of fields <-> struct"; in Rust that
//! assembly is written out by hand in each `impl` instead, or generated by a derive macro.
//!
//! ## What the context parameter is, and why it is not an associated type
//!
//! Model failure as a sum, which is all `io::Result<T>` is, and a decoder is a total map
//!
//! ```text
//!     read : A x B -> T + E
//! ```
//!
//! [Currying][currying] it, that is the [cartesian-closed][ccc] adjunction `(- x B) -| (-)^B`,
//! presents it as `A -> (B -> T + E)`: one decoder per context. `write` does not depend on `A`,
//! so a context does not give a family of codecs but a family of *retractions sharing a single
//! section*, hence a family of idempotents `e_a = write . read_a` on `B` that all split through
//! the same `T`. The assignment `a |-> e_a` is an [indexed family][indexed].
//!
//! The retraction law is indexed too, and only partially so: `read_a . write = id_T` holds for
//! the contexts consistent with the value, not for every `a`. A v4 `Transaction` carries its own
//! branch ID and round-trips only under that one.
//!
//! An associated type would be a different object. `type Args;` assigns one type to each
//! implementor, so it is a [type family][type-family] `Args : Impls -> Type`, a map on objects,
//! equivalently a [display map][display-map] whose total space is the [dependent sum][sigma]
//! `Sigma (T : Impls). Args(T)`. The defining property is that it is *functional*: every `T`
//! gets exactly one context.
//!
//! A type parameter drops that. `Decodable<A> for T` is a *relation* between types and contexts,
//! so one type may sit over many. This is the whole of the difference, and it is why `Block` is
//! inexpressible with an associated type: `Block` decodes under *every* [`consensus::Parameters`],
//! so its contexts are a family, and a function must collapse that family to a single type. The
//! collapse you want is the [existential][existential] `exists P. P`, left adjoint to weakening
//! in Lawvere's reading of the quantifiers; Rust spells it `dyn Parameters`, and it does not
//! exist here because `Parameters: Clone` is not [dyn-compatible][dyn-compat] (`clone` returns
//! `Self` by value). The family has no colimit to collapse to, so the functional form has
//! nothing to name. The relational form never asks the question.
//!
//! Coherence still forbids two impls at the same pair `(T, A)`, so the relation is single-valued
//! in the pair. It is only single-valued in `T` that it is not.
//!
//! ## Two honest deviations from the ideal object
//!
//! 1. **No [`Alternative`][alt].** Rendel and Ostermann's third operation is choice, which
//!    presumes a backtrackable input. [`Read`] is a one-shot stream with no `Seek`, so a failed
//!    branch cannot be retried. Only *prefix-determined* unions are expressible: read a
//!    discriminant, then dispatch. Every union in the Zcash wire format is of that shape, so
//!    this costs nothing here, but it means the traits model a strictly smaller class of formats
//!    than the paper's `Syntax` does.
//!
//! 2. **One codec per type and context.** Rust coherence permits at most one
//!    `impl Decodable<A> for T` per `A`, and overlapping context types are rejected, so in
//!    practice a type still has one encoding. A type with two *framings* therefore needs two
//!    types: see [`Unprefixed`], which exists because `Vec<T>` already spends its impl on the
//!    length-prefixed framing. Distinguishing two encodings by context type alone would compile
//!    in some cases but is deliberately not done here, because then the bytes a value produces
//!    would depend on a parameter that is not part of the value.
//!
//!    Making the codec a first-class *value* rather than a trait on the payload lifts this
//!    restriction properly, at the cost of losing the ergonomics of `value.write(w)`. That trade
//!    is the reason `zcash_history::Version` is shaped the way it is.
//!
//! [section]: https://en.wikipedia.org/wiki/Section_(category_theory)
//! [idempotence]: https://en.wikipedia.org/wiki/Idempotence
//! [split-idempotent]: https://ncatlab.org/nlab/show/split+idempotent
//! [karoubi]: https://en.wikipedia.org/wiki/Karoubi_envelope
//! [variance]: https://en.wikipedia.org/wiki/Covariance_and_contravariance_(computer_science)
//! [functor]: https://en.wikipedia.org/wiki/Functor
//! [invariant]: https://hackage.haskell.org/package/invariant
//! [profunctor]: https://ncatlab.org/nlab/show/profunctor
//! [alt]: https://hackage.haskell.org/package/base/docs/Control-Applicative.html
//! [hs-functor]: https://hackage.haskell.org/package/base/docs/Data-Functor.html
//! [kind]: https://en.wikipedia.org/wiki/Kind_(type_theory)
//! [currying]: https://en.wikipedia.org/wiki/Currying
//! [ccc]: https://en.wikipedia.org/wiki/Cartesian_closed_category
//! [indexed]: https://ncatlab.org/nlab/show/indexed+category
//! [type-family]: https://en.wikipedia.org/wiki/Type_family
//! [display-map]: https://ncatlab.org/nlab/show/display+map
//! [sigma]: https://ncatlab.org/nlab/show/dependent+sum
//! [existential]: https://ncatlab.org/nlab/show/existential+quantifier
//! [dyn-compat]: https://doc.rust-lang.org/reference/items/traits.html#dyn-compatibility

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use nonempty::NonEmpty;

use crate::{Array, CompactSize, Optional, Vector};

/// A type with a canonical binary encoding.
pub trait Encodable {
    /// Writes the canonical encoding of `self`.
    fn write<W>(&self, writer: W) -> io::Result<()>
    where
        W: Write;

    /// Returns the number of bytes [`Encodable::write`] will produce.
    ///
    /// The default implementation counts the bytes without buffering them. Override it when the
    /// size is known in closed form.
    fn serialized_size(&self) -> usize {
        let mut counter = ByteCounter(0);
        self.write(&mut counter)
            .expect("counting bytes cannot fail");
        counter.0
    }
}

/// A type that can be parsed from its canonical binary encoding, given context `A`.
///
/// `A` is context the byte stream does not itself carry, and is `()` when the encoding is
/// self-describing. It is a type parameter rather than an associated type so that a decoder
/// generic over its context can implement this for every context it accepts: `Block` decodes
/// under any `consensus::Parameters`, and expresses that as
/// `impl<P: Parameters> Decodable<&P> for Block`.
pub trait Decodable<A>: Sized {
    /// Parses a value from `reader`.
    fn read<R>(reader: R, args: A) -> io::Result<Self>
    where
        R: Read;
}

/// Marker alias for a type with a complete, context-free codec.
pub trait Codec: Encodable + Decodable<()> {}

impl<T> Codec for T where T: Encodable + Decodable<()> {}

/// A [`Write`] that discards its input and counts the bytes.
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Combinators, expressed as impls on the container types.
// ---------------------------------------------------------------------------

impl<T> Encodable for Vec<T>
where
    T: Encodable,
{
    fn write<W>(&self, writer: W) -> io::Result<()>
    where
        W: Write,
    {
        Vector::write(writer, self, |w, e| e.write(w))
    }

    fn serialized_size(&self) -> usize {
        CompactSize::serialized_size(self.len())
            + self.iter().map(Encodable::serialized_size).sum::<usize>()
    }
}

impl<A, T> Decodable<A> for Vec<T>
where
    A: Copy,
    T: Decodable<A>,
{
    fn read<R>(reader: R, args: A) -> io::Result<Self>
    where
        R: Read,
    {
        Vector::read_collected_mut(reader, |r| T::read(r, args))
    }
}

impl<T> Encodable for Option<T>
where
    T: Encodable,
{
    fn write<W>(&self, writer: W) -> io::Result<()>
    where
        W: Write,
    {
        Optional::write(writer, self.as_ref(), |w, e| e.write(w))
    }

    fn serialized_size(&self) -> usize {
        1 + self.as_ref().map_or(0, Encodable::serialized_size)
    }
}

impl<A, T> Decodable<A> for Option<T>
where
    A: Copy,
    T: Decodable<A>,
{
    fn read<R>(reader: R, args: A) -> io::Result<Self>
    where
        R: Read,
    {
        Optional::read(reader, |r| T::read(r, args))
    }
}

impl<T> Encodable for NonEmpty<T>
where
    T: Encodable,
{
    fn write<W>(&self, writer: W) -> io::Result<()>
    where
        W: Write,
    {
        Vector::write_nonempty(writer, self, |w, e| e.write(w))
    }

    fn serialized_size(&self) -> usize {
        CompactSize::serialized_size(self.len())
            + self.iter().map(Encodable::serialized_size).sum::<usize>()
    }
}

impl<A, T> Decodable<A> for NonEmpty<T>
where
    A: Copy,
    T: Decodable<A>,
{
    fn read<R>(reader: R, args: A) -> io::Result<Self>
    where
        R: Read,
    {
        let items: Vec<T> = Vector::read_collected_mut(reader, |r| T::read(r, args))?;
        NonEmpty::from_vec(items)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "expected a non-empty list"))
    }
}

/// A sequence with no length prefix, whose length comes from elsewhere in the stream.
///
/// This is the [`crate::Array`] combinator. It cannot be a second `Decodable` impl on `Vec<T>`,
/// because coherence permits exactly one impl per type: the trait form fixes *the* canonical
/// codec for a type, so a type with two encodings needs two types. The wrapper is that second
/// type, and it also documents at the call site which of the two framings is in use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unprefixed<T>(pub Vec<T>);

/// Decoding context for [`Unprefixed`]: the element count, plus the element's own context.
#[derive(Clone, Copy, Debug)]
pub struct UnprefixedArgs<A> {
    /// The number of elements to read.
    pub count: usize,
    /// The context each element needs.
    pub element: A,
}

impl<T> Encodable for Unprefixed<T>
where
    T: Encodable,
{
    fn write<W>(&self, writer: W) -> io::Result<()>
    where
        W: Write,
    {
        Array::write(writer, &self.0, |w, e| e.write(w))
    }

    fn serialized_size(&self) -> usize {
        self.0.iter().map(Encodable::serialized_size).sum()
    }
}

impl<A, T> Decodable<UnprefixedArgs<A>> for Unprefixed<T>
where
    A: Copy,
    T: Decodable<A>,
{
    fn read<R>(reader: R, args: UnprefixedArgs<A>) -> io::Result<Self>
    where
        R: Read,
    {
        Array::read_collected_mut(reader, args.count, |r| T::read(r, args.element)).map(Unprefixed)
    }
}
