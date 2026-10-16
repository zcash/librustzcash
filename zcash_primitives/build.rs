fn main() {
    cfg_aliases::cfg_aliases! {
        // V7 transaction format and ZIP 248 support. V7 is introduced by the
        // NuTachyon network upgrade; see `TxVersion::V7`.
        zcash_v7: { zcash_unstable = "nutachyon" },
    }
}
