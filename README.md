# zcash-mmr

Special implementation of merkle mountain ranges (MMR) for ZCash!

[![Build Status](https://travis-ci.org/NikVolf/zcash-mmr.svg?branch=master)](https://travis-ci.org/NikVolf/zcash-mmr)

The main design goals of this mmr implementation are

- Allow zero-cache and avoid db callbacks. As it is implemented, calling side must just smartly pre-load MMR nodes from the database (about log2(tree length) for append, twice as much for deletion).

- Reuse as much logic between rust and c++ clients and place it here and librustzcash.

- Close to zero memory consumption.

# License

`zcash-mmr` is primarily distributed under the terms of both the MIT
license and the Apache License (Version 2.0), at your choice.

See LICENSE-APACHE, and LICENSE-MIT for details.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `zcash-mmr` by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
