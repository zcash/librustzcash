//! String-encoding prefixes for Zcash addresses and Unified containers.
//!
//! Each network's prefixes are in the [`mainnet`], [`testnet`], and [`regtest`]
//! modules. The functions in this module select the prefix for a given
//! [`NetworkType`].
//!
//! Prefixes for encodings of keys that this crate does not handle, such as Sapling
//! extended keys, are defined in the `zcash_keys` crate.

use zcash_protocol::consensus::NetworkType;

/// String-encoding prefixes for the Zcash main network.
pub mod mainnet {
    /// The HRP for a Bech32-encoded mainnet Sapling payment address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.3.1][saplingpaymentaddrencoding].
    ///
    /// [saplingpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#saplingpaymentaddrencoding
    pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zs";

    /// The prefix for a Base58Check-encoded mainnet Sprout address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.2.1][sproutpaymentaddrencoding].
    ///
    /// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
    pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0x9a];

    /// The prefix for a Base58Check-encoded mainnet transparent P2PKH address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.1.1][transparentaddrencoding].
    ///
    /// [transparentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#transparentaddrencoding
    pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xb8];

    /// The prefix for a Base58Check-encoded mainnet transparent P2SH address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.1.1][transparentaddrencoding].
    ///
    /// [transparentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#transparentaddrencoding
    pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xbd];

    /// The HRP for a Bech32m-encoded mainnet [ZIP 320] TEX address.
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    pub const HRP_TEX_ADDRESS: &str = "tex";

    /// The HRP for a Bech32m-encoded mainnet Revision 0 Unified Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS: &str = "u";

    /// The HRP for a Bech32m-encoded mainnet Revision 0 Unified FVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_FVK: &str = "uview";

    /// The HRP for a Bech32m-encoded mainnet Revision 0 Unified IVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_IVK: &str = "uivk";

    /// The HRP for a Bech32m-encoded mainnet shielded-only Revision 2 Unified Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS_R2: &str = "zu";

    /// The HRP for a Bech32m-encoded mainnet transparent-including Revision 2 Unified
    /// Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS_R2_TI: &str = "tu";

    /// The HRP for a Bech32m-encoded mainnet Revision 2 Unified FVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_FVK_R2: &str = "uvf";

    /// The HRP for a Bech32m-encoded mainnet Revision 2 Unified IVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_IVK_R2: &str = "uvi";
}

/// String-encoding prefixes for the Zcash test network.
pub mod testnet {
    /// The HRP for a Bech32-encoded testnet Sapling payment address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.3.1][saplingpaymentaddrencoding].
    ///
    /// [saplingpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#saplingpaymentaddrencoding
    pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "ztestsapling";

    /// The prefix for a Base58Check-encoded testnet Sprout address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.2.1][sproutpaymentaddrencoding].
    ///
    /// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
    pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0xb6];

    /// The prefix for a Base58Check-encoded testnet transparent P2PKH address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.1.1][transparentaddrencoding].
    ///
    /// [transparentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#transparentaddrencoding
    pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1d, 0x25];

    /// The prefix for a Base58Check-encoded testnet transparent P2SH address.
    ///
    /// Defined in the [Zcash Protocol Specification section 5.6.1.1][transparentaddrencoding].
    ///
    /// [transparentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#transparentaddrencoding
    pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xba];

    /// The HRP for a Bech32m-encoded testnet [ZIP 320] TEX address.
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    pub const HRP_TEX_ADDRESS: &str = "textest";

    /// The HRP for a Bech32m-encoded testnet Revision 0 Unified Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS: &str = "utest";

    /// The HRP for a Bech32m-encoded testnet Revision 0 Unified FVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_FVK: &str = "uviewtest";

    /// The HRP for a Bech32m-encoded testnet Revision 0 Unified IVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_IVK: &str = "uivktest";

    /// The HRP for a Bech32m-encoded testnet shielded-only Revision 2 Unified Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS_R2: &str = "zutest";

    /// The HRP for a Bech32m-encoded testnet transparent-including Revision 2 Unified
    /// Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS_R2_TI: &str = "tutest";

    /// The HRP for a Bech32m-encoded testnet Revision 2 Unified FVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_FVK_R2: &str = "uvftest";

    /// The HRP for a Bech32m-encoded testnet Revision 2 Unified IVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_IVK_R2: &str = "uvitest";
}

/// String-encoding prefixes for a local regression-testing network.
///
/// The Base58Check prefixes are the same as on testnet, so a decoder cannot tell a
/// regtest Base58Check address from a testnet one.
pub mod regtest {
    /// The HRP for a Bech32-encoded regtest Sapling payment address.
    ///
    /// It is defined in zcashd, and is not part of the Zcash Protocol Specification.
    pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zregtestsapling";

    /// The prefix for a Base58Check-encoded regtest Sprout address.
    ///
    /// It is the same as [`super::testnet::B58_SPROUT_ADDRESS_PREFIX`].
    pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0xb6];

    /// The prefix for a Base58Check-encoded regtest transparent P2PKH address.
    ///
    /// It is the same as [`super::testnet::B58_PUBKEY_ADDRESS_PREFIX`].
    pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1d, 0x25];

    /// The prefix for a Base58Check-encoded regtest transparent P2SH address.
    ///
    /// It is the same as [`super::testnet::B58_SCRIPT_ADDRESS_PREFIX`].
    pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xba];

    /// The HRP for a Bech32m-encoded regtest [ZIP 320] TEX address.
    ///
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    pub const HRP_TEX_ADDRESS: &str = "texregtest";

    /// The HRP for a Bech32m-encoded regtest Revision 0 Unified Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS: &str = "uregtest";

    /// The HRP for a Bech32m-encoded regtest Revision 0 Unified FVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_FVK: &str = "uviewregtest";

    /// The HRP for a Bech32m-encoded regtest Revision 0 Unified IVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_IVK: &str = "uivkregtest";

    /// The HRP for a Bech32m-encoded regtest shielded-only Revision 2 Unified Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS_R2: &str = "zuregtest";

    /// The HRP for a Bech32m-encoded regtest transparent-including Revision 2 Unified
    /// Address.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_ADDRESS_R2_TI: &str = "turegtest";

    /// The HRP for a Bech32m-encoded regtest Revision 2 Unified FVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_FVK_R2: &str = "uvfregtest";

    /// The HRP for a Bech32m-encoded regtest Revision 2 Unified IVK.
    ///
    /// Defined in [ZIP 316].
    ///
    /// [ZIP 316]: https://zips.z.cash/zip-0316
    pub const HRP_UNIFIED_IVK_R2: &str = "uviregtest";
}

/// Returns the HRP for a Bech32-encoded Sapling payment address on the given network.
pub const fn hrp_sapling_payment_address(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
        NetworkType::Test => testnet::HRP_SAPLING_PAYMENT_ADDRESS,
        NetworkType::Regtest => regtest::HRP_SAPLING_PAYMENT_ADDRESS,
    }
}

/// Returns the prefix for a Base58Check-encoded Sprout address on the given network.
pub const fn b58_sprout_address_prefix(net: NetworkType) -> [u8; 2] {
    match net {
        NetworkType::Main => mainnet::B58_SPROUT_ADDRESS_PREFIX,
        NetworkType::Test => testnet::B58_SPROUT_ADDRESS_PREFIX,
        NetworkType::Regtest => regtest::B58_SPROUT_ADDRESS_PREFIX,
    }
}

/// Returns the prefix for a Base58Check-encoded transparent P2PKH address on the given
/// network.
pub const fn b58_pubkey_address_prefix(net: NetworkType) -> [u8; 2] {
    match net {
        NetworkType::Main => mainnet::B58_PUBKEY_ADDRESS_PREFIX,
        NetworkType::Test => testnet::B58_PUBKEY_ADDRESS_PREFIX,
        NetworkType::Regtest => regtest::B58_PUBKEY_ADDRESS_PREFIX,
    }
}

/// Returns the prefix for a Base58Check-encoded transparent P2SH address on the given
/// network.
pub const fn b58_script_address_prefix(net: NetworkType) -> [u8; 2] {
    match net {
        NetworkType::Main => mainnet::B58_SCRIPT_ADDRESS_PREFIX,
        NetworkType::Test => testnet::B58_SCRIPT_ADDRESS_PREFIX,
        NetworkType::Regtest => regtest::B58_SCRIPT_ADDRESS_PREFIX,
    }
}

/// Returns the HRP for a Bech32m-encoded [ZIP 320] TEX address on the given network.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
pub const fn hrp_tex_address(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_TEX_ADDRESS,
        NetworkType::Test => testnet::HRP_TEX_ADDRESS,
        NetworkType::Regtest => regtest::HRP_TEX_ADDRESS,
    }
}

/// Returns the HRP for a Bech32m-encoded Revision 0 Unified Address on the given network.
pub const fn hrp_unified_address(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_ADDRESS,
        NetworkType::Test => testnet::HRP_UNIFIED_ADDRESS,
        NetworkType::Regtest => regtest::HRP_UNIFIED_ADDRESS,
    }
}

/// Returns the HRP for a Bech32m-encoded Revision 0 Unified FVK on the given network.
pub const fn hrp_unified_fvk(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_FVK,
        NetworkType::Test => testnet::HRP_UNIFIED_FVK,
        NetworkType::Regtest => regtest::HRP_UNIFIED_FVK,
    }
}

/// Returns the HRP for a Bech32m-encoded Revision 0 Unified IVK on the given network.
pub const fn hrp_unified_ivk(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_IVK,
        NetworkType::Test => testnet::HRP_UNIFIED_IVK,
        NetworkType::Regtest => regtest::HRP_UNIFIED_IVK,
    }
}

/// Returns the HRP for a Bech32m-encoded shielded-only Revision 2 Unified Address on the
/// given network.
pub const fn hrp_unified_address_r2(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_ADDRESS_R2,
        NetworkType::Test => testnet::HRP_UNIFIED_ADDRESS_R2,
        NetworkType::Regtest => regtest::HRP_UNIFIED_ADDRESS_R2,
    }
}

/// Returns the HRP for a Bech32m-encoded transparent-including Revision 2 Unified Address
/// on the given network.
pub const fn hrp_unified_address_r2_ti(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_ADDRESS_R2_TI,
        NetworkType::Test => testnet::HRP_UNIFIED_ADDRESS_R2_TI,
        NetworkType::Regtest => regtest::HRP_UNIFIED_ADDRESS_R2_TI,
    }
}

/// Returns the HRP for a Bech32m-encoded Revision 2 Unified FVK on the given network.
pub const fn hrp_unified_fvk_r2(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_FVK_R2,
        NetworkType::Test => testnet::HRP_UNIFIED_FVK_R2,
        NetworkType::Regtest => regtest::HRP_UNIFIED_FVK_R2,
    }
}

/// Returns the HRP for a Bech32m-encoded Revision 2 Unified IVK on the given network.
pub const fn hrp_unified_ivk_r2(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_UNIFIED_IVK_R2,
        NetworkType::Test => testnet::HRP_UNIFIED_IVK_R2,
        NetworkType::Regtest => regtest::HRP_UNIFIED_IVK_R2,
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::{NetworkConstants, NetworkType};

    const NETWORKS: [NetworkType; 3] = [NetworkType::Main, NetworkType::Test, NetworkType::Regtest];

    /// The `zcash_protocol` copies of these prefixes must not drift from the definitions
    /// here while both exist.
    #[test]
    fn zcash_protocol_copies_match() {
        for net in NETWORKS {
            assert_eq!(
                super::hrp_sapling_payment_address(net),
                net.hrp_sapling_payment_address()
            );
            assert_eq!(
                super::b58_sprout_address_prefix(net),
                net.b58_sprout_address_prefix()
            );
            assert_eq!(
                super::b58_pubkey_address_prefix(net),
                net.b58_pubkey_address_prefix()
            );
            assert_eq!(
                super::b58_script_address_prefix(net),
                net.b58_script_address_prefix()
            );
            assert_eq!(super::hrp_tex_address(net), net.hrp_tex_address());
            assert_eq!(super::hrp_unified_address(net), net.hrp_unified_address());
            assert_eq!(super::hrp_unified_fvk(net), net.hrp_unified_fvk());
            assert_eq!(super::hrp_unified_ivk(net), net.hrp_unified_ivk());
        }
    }
}
