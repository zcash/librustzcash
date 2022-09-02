use gumdrop::Options;
use zcash_client_backend::encoding::{decode_extended_full_viewing_key, encode_payment_address};
use zcash_primitives::{
    constants::{mainnet, testnet},
    zip32::{DiversifierIndex, ExtendedFullViewingKey},
};

fn parse_viewing_key(s: &str) -> Result<(ExtendedFullViewingKey, bool), &'static str> {
    decode_extended_full_viewing_key(mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, s)
        .map(|vk| (vk, true))
        .or_else(|_| {
            decode_extended_full_viewing_key(testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY, s)
                .map(|vk| (vk, false))
        })
        .map_err(|_| "Invalid Sapling viewing key")
}

fn parse_diversifier_index(s: &str) -> Result<DiversifierIndex, &'static str> {
    let i: u128 = s.parse().map_err(|_| "Diversifier index is not a number")?;
    if i >= (1 << 88) {
        return Err("Diversifier index too large");
    }
    Ok(DiversifierIndex(i.to_le_bytes()[..11].try_into().unwrap()))
}

fn encode_diversifier_index(di: &DiversifierIndex) -> u128 {
    let mut bytes = [0; 16];
    bytes[..11].copy_from_slice(&di.0);
    u128::from_le_bytes(bytes)
}

#[derive(Debug, Options)]
struct MyOptions {
    #[options(help = "Print this help message and exit.")]
    help: bool,

    #[options(
        free,
        help = "The Sapling viewing key to generate diversified addresses from",
        parse(try_from_str = "parse_viewing_key")
    )]
    viewing_key: Option<(ExtendedFullViewingKey, bool)>,

    #[options(
        free,
        help = "The index of the diversified address to generate (default 0). Some indices don't have a corresponding address.",
        parse(try_from_str = "parse_diversifier_index")
    )]
    diversifier_index: DiversifierIndex,
}

fn main() {
    let opts = MyOptions::parse_args_default_or_exit();

    let (extfvk, is_mainnet) = if let Some(res) = opts.viewing_key {
        res
    } else {
        eprintln!("Missing Sapling viewing key");
        return;
    };

    let (diversifier_index, address) = extfvk.find_address(opts.diversifier_index).unwrap();
    println!(
        "# Diversifier index: {}",
        encode_diversifier_index(&diversifier_index)
    );
    println!(
        "{}",
        encode_payment_address(
            if is_mainnet {
                mainnet::HRP_SAPLING_PAYMENT_ADDRESS
            } else {
                testnet::HRP_SAPLING_PAYMENT_ADDRESS
            },
            &address
        )
    );
}
