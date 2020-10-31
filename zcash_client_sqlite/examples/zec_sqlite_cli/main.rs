//! An example light client wallet based on the `zcash_client_sqlite` crate.
//!
//! This is **NOT IMPLEMENTED SECURELY**, and it is not written to be efficient or usable!
//! It is only intended to show the overall light client workflow using this crate.

use gumdrop::Options;
use zcash_primitives::consensus::TEST_NETWORK;

mod commands;
mod data;
mod error;
mod remote;

const MIN_CONFIRMATIONS: u32 = 3;

#[derive(Debug, Options)]
struct MyOptions {
    #[options(help = "print help message")]
    help: bool,

    #[options(help = "path to the wallet directory")]
    wallet_dir: Option<String>,

    #[options(command)]
    command: Option<Command>,
}

#[derive(Debug, Options)]
enum Command {
    #[options(help = "initialise a new light wallet")]
    Init(commands::init::Command),

    #[options(help = "upgrade an existing light wallet")]
    Upgrade(commands::upgrade::Command),

    #[options(help = "scan the chain and sync the wallet")]
    Sync(commands::sync::Command),

    #[options(help = "get the balance in the wallet")]
    Balance(commands::balance::Command),

    #[options(help = "send funds to the given address")]
    Send(commands::send::Command),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opts = MyOptions::parse_args_default_or_exit();
    let params = TEST_NETWORK;

    match opts.command {
        Some(Command::Init(command)) => command.run(params, opts.wallet_dir).await,
        Some(Command::Upgrade(command)) => command.run(params, opts.wallet_dir),
        Some(Command::Sync(command)) => command.run(params, opts.wallet_dir).await,
        Some(Command::Balance(command)) => command.run(params, opts.wallet_dir),
        Some(Command::Send(command)) => command.run(params, opts.wallet_dir).await,
        _ => Ok(()),
    }
}
