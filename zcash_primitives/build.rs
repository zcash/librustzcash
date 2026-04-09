fn main() {
    cfg_aliases::cfg_aliases! {
        // V6 transaction format and ZIP 248 support. Enabled under either
        // `--cfg zcash_unstable="nu7"` (NU7 activation) or
        // `--cfg zcash_unstable="zfuture"` (speculative future upgrades, which
        // implicitly include V6 since any future upgrade will activate after
        // NU7).
        zcash_v6: { any(zcash_unstable = "nu7", zcash_unstable = "zfuture") },
        // Transparent Zcash Extensions (TZEs). Enabled under
        // `--cfg zcash_unstable="zfuture"` only.
        zcash_tze: { zcash_unstable = "zfuture" },
    }
}
