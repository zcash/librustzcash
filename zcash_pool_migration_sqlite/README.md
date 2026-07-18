# zcash_pool_migration_sqlite

SQLite persistence for the Zcash Orchard -> Ironwood value-pool migration engine
(ZIP 318).

This crate implements the `PoolMigrationRead` / `PoolMigrationWrite` store traits
from `zcash_pool_migration_backend` over two SQLite tables, mirroring how
`zcash_client_sqlite` implements `zcash_client_backend`'s `WalletRead` /
`WalletWrite`.

The generic, pool-agnostic store machinery (the DDL builders, the blob
encode/decode helpers, and the store logic) lives in a private module,
parameterized over the per-pool table names. Each pool migration is a public
submodule that instantiates the store with its own table names and exposes the
concrete API; the generic store type never appears in the public surface, so
future pool migrations reuse the same machinery under their own tables.
Currently the only such submodule is `orchard_ironwood` (the Orchard -> Ironwood
migration, tables `orchard_ironwood_migrations` /
`orchard_ironwood_migration_transactions`):

```rust
use zcash_pool_migration_sqlite::orchard_ironwood::{PoolMigrations, init_migration_tables};
```

`zcash_client_sqlite` depends on this crate (never the reverse): it registers a
thin `schemerz` migration that runs a pool submodule's table DDL, depends on
`ironwood_received_notes`, and exposes the store through its `WalletDb`, so the
pool-migration tables live in the same `wallet.db`.

## License

Licensed under either of

- Apache License, Version 2.0
- MIT license

at your option.
