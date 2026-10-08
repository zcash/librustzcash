//! String-encoding prefixes for Zcash keys.
//!
//! Each network's prefixes are in the [`mainnet`], [`testnet`], and [`regtest`]
//! modules. The functions in this module select the prefix for a given
//! [`NetworkType`].
//!
//! Prefixes for address and Unified container encodings are defined in
//! [`zcash_address::constants`].

use zcash_protocol::consensus::NetworkType;

/// String-encoding prefixes of keys for the Zcash main network.
pub mod mainnet {
    /// The HRP for a Bech32-encoded mainnet Sapling [`ExtendedSpendingKey`].
    ///
    /// Defined in [ZIP 32].
    ///
    /// [`ExtendedSpendingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedSpendingKey.html
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-main";

    /// The HRP for a Bech32-encoded mainnet Sapling [`ExtendedFullViewingKey`].
    ///
    /// Defined in [ZIP 32].
    ///
    /// [`ExtendedFullViewingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedFullViewingKey.html
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviews";

    /// The prefix for a Base58Check-encoded mainnet transparent secret key, in the
    /// format of zcashd's [`EncodeSecret`] function.
    ///
    /// [`EncodeSecret`]: https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L298
    pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0x80];
}

/// String-encoding prefixes of keys for the Zcash test network.
pub mod testnet {
    /// The HRP for a Bech32-encoded testnet Sapling [`ExtendedSpendingKey`].
    ///
    /// Defined in [ZIP 32].
    ///
    /// [`ExtendedSpendingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedSpendingKey.html
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-test";

    /// The HRP for a Bech32-encoded testnet Sapling [`ExtendedFullViewingKey`].
    ///
    /// Defined in [ZIP 32].
    ///
    /// [`ExtendedFullViewingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedFullViewingKey.html
    /// [ZIP 32]: https://zips.z.cash/zip-0032
    pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewtestsapling";

    /// The prefix for a Base58Check-encoded testnet transparent secret key, in the
    /// format of zcashd's [`EncodeSecret`] function.
    ///
    /// [`EncodeSecret`]: https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L298
    pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0xef];
}

/// String-encoding prefixes of keys for a local regression-testing network.
pub mod regtest {
    /// The HRP for a Bech32-encoded regtest Sapling [`ExtendedSpendingKey`].
    ///
    /// It is defined in zcashd, and is not part of ZIP 32.
    ///
    /// [`ExtendedSpendingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedSpendingKey.html
    pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-regtest";

    /// The HRP for a Bech32-encoded regtest Sapling [`ExtendedFullViewingKey`].
    ///
    /// It is defined in zcashd, and is not part of ZIP 32.
    ///
    /// [`ExtendedFullViewingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedFullViewingKey.html
    pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewregtestsapling";

    /// The prefix for a Base58Check-encoded regtest transparent secret key.
    ///
    /// It is the same as [`super::testnet::B58_SECRET_KEY_PREFIX`].
    pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0xef];
}

/// Returns the HRP for a Bech32-encoded Sapling extended spending key on the given
/// network.
pub const fn hrp_sapling_extended_spending_key(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        NetworkType::Test => testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        NetworkType::Regtest => regtest::HRP_SAPLING_EXTENDED_SPENDING_KEY,
    }
}

/// Returns the HRP for a Bech32-encoded Sapling extended full viewing key on the given
/// network.
pub const fn hrp_sapling_extended_full_viewing_key(net: NetworkType) -> &'static str {
    match net {
        NetworkType::Main => mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        NetworkType::Test => testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        NetworkType::Regtest => regtest::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
    }
}

/// Returns the prefix for a Base58Check-encoded transparent secret key on the given
/// network.
pub const fn b58_secret_key_prefix(net: NetworkType) -> [u8; 1] {
    match net {
        NetworkType::Main => mainnet::B58_SECRET_KEY_PREFIX,
        NetworkType::Test => testnet::B58_SECRET_KEY_PREFIX,
        NetworkType::Regtest => regtest::B58_SECRET_KEY_PREFIX,
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::{NetworkConstants, NetworkType};

    const NETWORKS: [NetworkType; 3] = [NetworkType::Main, NetworkType::Test, NetworkType::Regtest];

    /// The `zcash_protocol` copies of these prefixes must not drift from the definitions
    /// here while both exist.
    #[test]
    #[allow(deprecated)]
    fn zcash_protocol_copies_match() {
        for net in NETWORKS {
            assert_eq!(
                super::hrp_sapling_extended_spending_key(net),
                net.hrp_sapling_extended_spending_key()
            );
            assert_eq!(
                super::hrp_sapling_extended_full_viewing_key(net),
                net.hrp_sapling_extended_full_viewing_key()
            );
            assert_eq!(
                super::b58_secret_key_prefix(net),
                net.b58_secret_key_prefix()
            );
        }
    }
}
