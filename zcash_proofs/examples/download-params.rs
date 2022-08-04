fn main() -> Result<(), minreq::Error> {
    #[allow(deprecated)]
    zcash_proofs::download_parameters()
}
