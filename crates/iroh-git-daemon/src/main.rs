//! `iroh-git-daemon` - thin CLI wrapper over the daemon library.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::{Parser, Subcommand};
use iroh_git_daemon::Status;

#[derive(Parser)]
#[command(name = "iroh-git-daemon", about = "Serve git repositories over iroh", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon, serving the repositories listed in the grants file.
    Run,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run => iroh_git_daemon::run(Arc::new(Mutex::new(Status::default()))).await,
    }
}
