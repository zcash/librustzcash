fn main() {
    if let Some(path) = zcash_proofs::default_params_folder() {
        if let Some(path) = path.to_str() {
            println!("{}", path);
        }
    }
}
