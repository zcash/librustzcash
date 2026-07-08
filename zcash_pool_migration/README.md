# zcash_pool_migration

An engine for migrating Zcash wallet funds from the Orchard value pool to the
Ironwood value pool. The engine plans a note split into self-funding
power-of-ten denominations, builds and signs migration transactions as PCZTs,
schedules them by block height, and persists its state in the wallet
database; the consuming application broadcasts the transactions and reports
results back.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
