fn main() -> Result<(), minreq::Error> {
    const DOWNLOAD_TIMEOUT_SECONDS: u64 = 3600;

    // Always do a download to /tmp, if compiled with `RUSTFLAGS="--cfg always_download"`
    #[cfg(always_download)]
    {
        std::env::set_var("HOME", "/tmp");
        let _ = std::fs::remove_dir(
            zcash_proofs::default_params_folder().expect("unexpected missing HOME env var"),
        );
    }

    zcash_proofs::download_sapling_parameters(Some(DOWNLOAD_TIMEOUT_SECONDS))?;
    zcash_proofs::download_sprout_parameters(Some(DOWNLOAD_TIMEOUT_SECONDS))?;

    Ok(())
}
