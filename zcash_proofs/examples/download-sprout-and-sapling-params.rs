fn main() -> Result<(), minreq::Error> {
    const DOWNLOAD_TIMEOUT_SECONDS: u64 = 3600;

    #[allow(unused_mut, unused_assignments)]
    let mut params_folder =
        zcash_proofs::default_params_folder().expect("unexpected missing HOME env var");

    // Always do a download to /tmp, if compiled with `RUSTFLAGS="--cfg always_download"`
    #[cfg(always_download)]
    {
        std::env::set_var("HOME", "/tmp");
        params_folder =
            zcash_proofs::default_params_folder().expect("unexpected missing HOME env var");

        println!("removing temporary parameters folder: {:?}", params_folder);
        let _ = std::fs::remove_dir_all(&params_folder);
    }

    println!("downloading sapling parameters to: {:?}", params_folder);
    zcash_proofs::download_sapling_parameters(Some(DOWNLOAD_TIMEOUT_SECONDS))?;

    println!("downloading sprout parameters to: {:?}", params_folder);
    zcash_proofs::download_sprout_parameters(Some(DOWNLOAD_TIMEOUT_SECONDS))?;

    Ok(())
}
