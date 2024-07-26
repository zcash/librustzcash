//! Types representing the components within Zcash transactions.

use std::io;
use std::marker::PhantomData;

use zcash_protocol::value::BalanceError;

pub mod amount {
    pub use zcash_protocol::value::{
        BalanceError, ZatBalance as Amount, Zatoshis as NonNegativeAmount, COIN,
    };

    #[cfg(feature = "test-dependencies")]
    pub mod testing {
        pub use zcash_protocol::value::testing::{
            arb_positive_zat_balance as arb_positive_amount, arb_zat_balance as arb_amount,
            arb_zatoshis as arb_nonnegative_amount,
        };
    }
}
pub mod orchard;
pub mod sapling;
pub mod sprout;
pub mod transparent;
#[cfg(zcash_unstable = "zfuture")]
pub mod tze;

pub use self::{
    amount::Amount,
    sprout::JsDescription,
    transparent::{OutPoint, TxIn, TxOut},
};
pub use crate::sapling::bundle::{OutputDescription, SpendDescription};

#[cfg(zcash_unstable = "zfuture")]
pub use self::tze::{TzeIn, TzeOut};

use super::Authorization;

// π_A + π_B + π_C
pub const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;

/// The protocol-specific bundles of data within a transaction.
pub trait Bundles {
    type Transparent: TransparentPart;
    type Sprout: SproutPart;
    type Sapling: SaplingPart;
    type Orchard: OrchardPart;

    #[cfg(zcash_unstable = "zfuture")]
    type Tze: TzePart;
}

/// Marker type for a transaction that may contain payments within any Zcash protocol.
#[derive(Debug)]
pub struct AllBundles<A: Authorization> {
    _auth: PhantomData<A>,
}

impl<A: Authorization> Bundles for AllBundles<A> {
    type Transparent = Transparent<A::TransparentAuth>;
    type Sprout = Sprout;
    type Sapling = Sapling<A::SaplingAuth>;
    type Orchard = Orchard<A::OrchardAuth>;

    #[cfg(zcash_unstable = "zfuture")]
    type Tze = Tze<A::TzeAuth>;
}

/// The protocol-agnostic parts of a shielded bundle.
///
/// The trait methods can be implemented without any knowledge of protocol-specific
/// details, only requiring the ability to parse the general bundle structure within a
/// transaction.
pub trait ShieldedBundle {
    fn value_balance(&self) -> Amount;
}

impl ShieldedBundle for sprout::Bundle {
    fn value_balance(&self) -> Amount {
        // We don't support building Sprout bundles in Rust.
        self.value_balance()
            .expect("Sprout bundles are all checked by consensus")
    }
}

impl<A: ::sapling::bundle::Authorization> ShieldedBundle for ::sapling::Bundle<A, Amount> {
    fn value_balance(&self) -> Amount {
        *self.value_balance()
    }
}

impl<A: ::orchard::bundle::Authorization> ShieldedBundle for ::orchard::Bundle<A, Amount> {
    fn value_balance(&self) -> Amount {
        *self.value_balance()
    }
}

/// The transparent part of a transaction.
pub trait TransparentPart {
    type Bundle;

    fn value_balance<E, F>(bundle: &Self::Bundle, get_prevout_value: F) -> Result<Amount, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Amount, E>;
}

#[derive(Debug)]
pub struct Transparent<A: transparent::Authorization> {
    _auth: PhantomData<A>,
}

impl<A: transparent::Authorization> TransparentPart for Transparent<A> {
    type Bundle = transparent::Bundle<A>;

    fn value_balance<E, F>(bundle: &Self::Bundle, get_prevout_value: F) -> Result<Amount, E>
    where
        E: From<BalanceError>,
        F: FnMut(&OutPoint) -> Result<Amount, E>,
    {
        bundle.value_balance(get_prevout_value)
    }
}

/// The Sprout part of a transaction.
pub trait SproutPart {
    type Bundle: ShieldedBundle;
}

/// Marker type for a transaction that may contain a Sprout part.
#[derive(Debug)]
pub struct Sprout;

impl SproutPart for Sprout {
    type Bundle = sprout::Bundle;
}

/// The Sapling part of a transaction.
pub trait SaplingPart {
    type Bundle: ShieldedBundle;
}

/// Marker type for a transaction that may contain a Sapling part.
#[derive(Debug)]
pub struct Sapling<A> {
    _auth: PhantomData<A>,
}

impl<A: ::sapling::bundle::Authorization> SaplingPart for Sapling<A> {
    type Bundle = ::sapling::Bundle<A, Amount>;
}

/// The Orchard part of a transaction.
pub trait OrchardPart {
    type Bundle: ShieldedBundle;
}

/// Marker type for a transaction that may contain an Orchard part.
#[derive(Debug)]
pub struct Orchard<A> {
    _auth: PhantomData<A>,
}

impl<A: ::orchard::bundle::Authorization> OrchardPart for Orchard<A> {
    type Bundle = ::orchard::bundle::Bundle<A, Amount>;
}

/// The TZE part of a transaction.
#[cfg(zcash_unstable = "zfuture")]
pub trait TzePart {
    type Bundle;
}

/// Marker type for a transaction that may contain a TZE part.
#[cfg(zcash_unstable = "zfuture")]
#[derive(Debug)]
pub struct Tze<A: tze::Authorization> {
    _auth: PhantomData<A>,
}

#[cfg(zcash_unstable = "zfuture")]
impl<A: tze::Authorization> TzePart for Tze<A> {
    type Bundle = tze::Bundle<A>;
}

/// The Transparent part of an authorized transaction.
pub trait AuthorizedTransparentPart: TransparentPart {
    fn read_bundle<R: io::Read>(reader: R) -> io::Result<Option<Self::Bundle>>;

    fn write_bundle<W: io::Write>(bundle: Option<&Self::Bundle>, writer: W) -> io::Result<()>;
}

/// The Sprout part of an authorized transaction.
pub trait AuthorizedSproutPart: SproutPart {
    fn read_v4_bundle<R: io::Read>(
        reader: R,
        tx_has_sprout: bool,
        use_groth: bool,
    ) -> io::Result<Option<Self::Bundle>>;

    fn write_v4_bundle<W: io::Write>(
        bundle: Option<&Self::Bundle>,
        writer: W,
        tx_has_sprout: bool,
    ) -> io::Result<()>;
}

/// The Sapling part of an authorized transaction.
pub trait AuthorizedSaplingPart: SaplingPart {
    type V4Components;

    fn read_v4_components<R: io::Read>(
        reader: R,
        tx_has_sapling: bool,
    ) -> io::Result<Self::V4Components>;

    fn read_v4_binding_sig<R: io::Read>(
        reader: R,
        tx_has_sapling: bool,
        components: Self::V4Components,
    ) -> io::Result<Option<Self::Bundle>>;

    fn write_v4_components<W: io::Write>(
        bundle: Option<&Self::Bundle>,
        writer: W,
        tx_has_sapling: bool,
    ) -> io::Result<()>;

    fn write_v4_binding_sig<W: io::Write>(
        bundle: Option<&Self::Bundle>,
        writer: W,
        tx_has_sapling: bool,
    ) -> io::Result<()>;

    fn read_v5_bundle<R: io::Read>(reader: R) -> io::Result<Option<Self::Bundle>>;

    fn write_v5_bundle<W: io::Write>(bundle: Option<&Self::Bundle>, writer: W) -> io::Result<()>;
}

/// The Orchard part of an authorized transaction.
pub trait AuthorizedOrchardPart: OrchardPart {
    fn read_v5_bundle<R: io::Read>(reader: R) -> io::Result<Option<Self::Bundle>>;

    fn write_v5_bundle<W: io::Write>(bundle: Option<&Self::Bundle>, writer: W) -> io::Result<()>;
}

/// The TZE part of an authorized transaction.
#[cfg(zcash_unstable = "zfuture")]
pub trait AuthorizedTzePart: TzePart {
    fn read_bundle<R: io::Read>(reader: R, tx_has_tze: bool) -> io::Result<Option<Self::Bundle>>;

    fn write_bundle<W: io::Write>(
        bundle: Option<&Self::Bundle>,
        writer: W,
        tx_has_tze: bool,
    ) -> io::Result<()>;
}
