use schemer_rusqlite::RusqliteMigration;

pub fn all_migrations() -> Vec<Box<dyn RusqliteMigration<Error = rusqlite::Error>>> {
    vec![Box::new(init::Migration {})]
}

pub mod init {
    use rusqlite::{self};
    use schemer::{self, migration};
    use schemer_rusqlite::RusqliteMigration;
    use uuid::Uuid;

    pub struct Migration;

    /// The migration that added the `compactblocks_meta` table.
    ///
    /// 68525b40-36e5-46aa-a765-720f8389b99d
    pub const MIGRATION_ID: Uuid = Uuid::from_fields(
        0x68525b40,
        0x36e5,
        0x46aa,
        b"\xa7\x65\x72\x0f\x83\x89\xb9\x9d",
    );

    migration!(
        Migration,
        &format!("{}", MIGRATION_ID),
        [],
        "Initialize the cachemeta database."
    );

    impl RusqliteMigration for Migration {
        type Error = rusqlite::Error;

        fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
            transaction.execute_batch(
                "CREATE TABLE compactblocks_meta (
                    height INTEGER PRIMARY KEY,
                    blockhash BLOB NOT NULL,
                    time INTEGER NOT NULL,
                    sapling_outputs_count INTEGER NOT NULL,
                    orchard_actions_count INTEGER NOT NULL
                )",
            )?;
            Ok(())
        }

        fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
            transaction.execute_batch("DROP TABLE compactblocks_meta;")?;
            Ok(())
        }
    }
}
