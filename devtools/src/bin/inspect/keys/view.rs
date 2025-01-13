use bech32::{Bech32, Hrp};
use zcash_address::unified::{self, Container, Encoding};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{
    consensus::{Network, NetworkConstants, NetworkType},
    local_consensus::LocalNetwork,
};

pub(crate) fn inspect_ufvk(ufvk: unified::Ufvk, network: NetworkType) {
    eprintln!("Unified full viewing key");
    eprintln!(
        " - Network: {}",
        match network {
            NetworkType::Main => "main",
            NetworkType::Test => "testnet",
            NetworkType::Regtest => "regtest",
        }
    );
    eprintln!(" - Items:");
    for item in ufvk.items() {
        match item {
            unified::Fvk::Orchard(data) => {
                eprintln!(
                    "   - Orchard ({})",
                    unified::Ufvk::try_from_items(vec![unified::Fvk::Orchard(data)])
                        .unwrap()
                        .encode(&network)
                );
            }
            unified::Fvk::Sapling(data) => {
                eprintln!(
                    "   - Sapling ({})",
                    bech32::encode::<Bech32>(
                        Hrp::parse_unchecked(network.hrp_sapling_extended_full_viewing_key()),
                        &data
                    )
                    .unwrap(),
                );
            }
            unified::Fvk::P2pkh(data) => {
                eprintln!("   - Transparent P2PKH");
                eprintln!("     - Payload: {}", hex::encode(data));
            }
            unified::Fvk::Unknown { typecode, data } => {
                eprintln!("   - Unknown");
                eprintln!("     - Typecode: {}", typecode);
                eprintln!("     - Payload: {}", hex::encode(data));
            }
        }
    }
}

pub(crate) fn inspect_uivk(uivk: unified::Uivk, network: NetworkType) {
    eprintln!("Unified incoming viewing key");
    eprintln!(
        " - Network: {}",
        match network {
            NetworkType::Main => "main",
            NetworkType::Test => "testnet",
            NetworkType::Regtest => "regtest",
        }
    );
    eprintln!(" - Items:");
    for item in uivk.items() {
        match item {
            unified::Ivk::Orchard(data) => {
                eprintln!(
                    "   - Orchard ({})",
                    unified::Uivk::try_from_items(vec![unified::Ivk::Orchard(data)])
                        .unwrap()
                        .encode(&network)
                );
            }
            unified::Ivk::Sapling(data) => {
                eprintln!("   - Sapling");
                eprintln!("     - Payload: {}", hex::encode(data));
            }
            unified::Ivk::P2pkh(data) => {
                eprintln!("   - Transparent P2PKH");
                eprintln!("     - Payload: {}", hex::encode(data));
            }
            unified::Ivk::Unknown { typecode, data } => {
                eprintln!("   - Unknown");
                eprintln!("     - Typecode: {}", typecode);
                eprintln!("     - Payload: {}", hex::encode(data));
            }
        }
    }
}

pub(crate) fn inspect_sapling_extfvk(data: Vec<u8>, network: NetworkType) {
    match sapling::zip32::ExtendedFullViewingKey::read(&data[..]).map_err(|_| ()) {
        Err(_) => {
            eprintln!("Invalid encoding that claims to be a Sapling extended full viewing key");
        }
        Ok(extfvk) => {
            eprintln!("Sapling extended full viewing key");

            let default_addr_bytes = extfvk.default_address().1.to_bytes();
            eprintln!(
                "- Default address: {}",
                bech32::encode::<Bech32>(
                    Hrp::parse_unchecked(network.hrp_sapling_payment_address()),
                    &default_addr_bytes,
                )
                .unwrap(),
            );

            if let Ok(ufvk) = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
            {
                let encoded_ufvk = match network {
                    NetworkType::Main => ufvk.encode(&Network::MainNetwork),
                    NetworkType::Test => ufvk.encode(&Network::TestNetwork),
                    NetworkType::Regtest => ufvk.encode(&LocalNetwork {
                        overwinter: None,
                        sapling: None,
                        blossom: None,
                        heartwood: None,
                        canopy: None,
                        nu5: None,
                        nu6: None,
                        #[cfg(zcash_unstable = "zfuture")]
                        z_future: None,
                    }),
                };
                eprintln!("- Equivalent UFVK: {encoded_ufvk}");

                let (default_ua, _) = ufvk.default_address(None).expect("should exist");
                let encoded_ua = match network {
                    NetworkType::Main => default_ua.encode(&Network::MainNetwork),
                    NetworkType::Test => default_ua.encode(&Network::TestNetwork),
                    NetworkType::Regtest => default_ua.encode(&LocalNetwork {
                        overwinter: None,
                        sapling: None,
                        blossom: None,
                        heartwood: None,
                        canopy: None,
                        nu5: None,
                        nu6: None,
                        #[cfg(zcash_unstable = "zfuture")]
                        z_future: None,
                    }),
                };
                eprintln!("  - Default address: {encoded_ua}");
            }
        }
    }
}
