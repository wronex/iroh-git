//! `git-iroh` - the human-facing porcelain, run as `git iroh <cmd>`.

use std::path::Path;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use iroh_git::config::{GrantOutcome, Grants};
use iroh_git::identity::{self, Role};
use iroh_git::share::{self, Revoked};
use iroh_git::RepoId;

#[derive(Parser)]
#[command(name = "git-iroh", about = "Share git repositories over iroh", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print this machine's NODE_ID.
    ///
    /// Hand it to a repo owner so they can grant you access to repositories.
    ShowId,
    /// Generate identity keys.
    /// 
    /// Creates any missing key; only regenerates an existing key when you
    /// select it with --client/--server AND pass --force.
    Keygen {
        /// The client key (what `show-id` prints and friends grant).
        #[arg(short, long)]
        client: bool,
        /// The server key (the daemon identity embedded in your tickets).
        #[arg(short, long)]
        server: bool,
        /// Overwrite the selected existing key(s). Requires --client/--server.
        #[arg(short, long)]
        force: bool,
    },
    /// Authorize access to the repository in the current directory.
    Grant {
        /// The friend's NODE_ID (from their `git iroh show-id`).
        node_id: String,
        /// Allow this node to push (default is read-only). Additive: re-granting
        /// with --write upgrades an existing member in place.
        #[arg(long)]
        write: bool,
        /// Optional nickname so you can tell friends apart in `list`.
        #[arg(long)]
        name: Option<String>,
    },
    /// Revoke a member's access to a repository.
    ///
    /// By default this removes the member (NODE_ID) from the repository in the
    /// current directory. Pass --all to remove them from every repository you
    /// share, or --write to only revoke push access while keeping read access.
    Revoke {
        /// The member's NODE_ID (from their `git iroh show-id`).
        node_id: String,
        /// Only revoke write (push) access, leaving read access intact.
        #[arg(long)]
        write: bool,
        /// Apply to every repository you share, not just the current directory.
        #[arg(long)]
        all: bool,
    },
    /// Stop sharing a repository entirely.
    ///
    /// Removes the repository and all its members from anywhere. Identify the
    /// repository by its SHARE_ID (from `list`), or pass --all to stop sharing
    /// everything.
    Stop {
        /// The repository's SHARE_ID (from `list`). Omit when using --all.
        share_id: Option<String>,
        /// Stop sharing every repository.
        #[arg(long)]
        all: bool,
    },
    /// List shared repositories and their authorized members.
    List,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::ShowId => {
            let secret = identity::load_or_create(Role::Client)?;
            println!("{}", secret.public());
        }
        Cmd::Keygen { client, server, force } => keygen(client, server, force)?,
        Cmd::Grant { node_id, write, name } => grant(&node_id, write, name.as_deref().unwrap_or(""))?,
        Cmd::Revoke { node_id, write, all } => revoke(&node_id, write, all)?,
        Cmd::Stop { share_id, all } => stop(share_id.as_deref(), all)?,
        Cmd::List => list()?,
    }
    Ok(())
}

fn keygen(client: bool, server: bool, force: bool) -> Result<()> {
    let explicit = client || server;
    if force && !explicit {
        bail!("--force requires --client and/or --server (refusing to overwrite both keys implicitly)");
    }
    // With no selection, operate on both (create-if-missing only).
    let (do_client, do_server) = if explicit { (client, server) } else { (true, true) };

    for (role, label, on) in [
        (Role::Client, "client", do_client),
        (Role::Server, "server", do_server),
    ] {
        if !on {
            continue;
        }
        let exists = identity::exists(role)?;
        if exists && !force {
            let id = identity::load_or_create(role)?.public();
            println!("{label}: exists ({id}) - use --force to regenerate");
        } else {
            let secret = identity::generate(role)?;
            let verb = if exists { "regenerated" } else { "created" };
            println!("{label}: {verb} ({})", secret.public());
        }
    }
    Ok(())
}

fn grant(node_id: &str, write: bool, name: &str) -> Result<()> {
    let g = share::grant(Path::new("."), node_id, write, name)?;
    match g.outcome {
        GrantOutcome::Added => eprintln!("granted read-only access to {}", g.repo_path),
        GrantOutcome::AddedWrite => eprintln!("granted read-write access to {}", g.repo_path),
        GrantOutcome::UpgradedToWrite => {
            eprintln!("upgraded {} to read-write - their existing remote is unchanged", g.node_id)
        }
        GrantOutcome::Unchanged => {
            eprintln!("{} already has access - their existing remote is unchanged", g.node_id)
        }
    }
    println!("{}", g.ticket.encode());
    Ok(())
}

fn revoke(node_id: &str, write_only: bool, all: bool) -> Result<()> {
    let node = share::canonical_node_id(node_id)?;

    if all {
        let n = share::revoke_everywhere(node_id, write_only)?;
        match (n, write_only) {
            (0, true) => eprintln!("{node} had no write access to revoke in any repository"),
            (0, false) => eprintln!("{node} was not a member of any repository"),
            (n, true) => eprintln!("revoked write access for {node} in {}", repos(n)),
            (n, false) => eprintln!("revoked all access for {node} in {}", repos(n)),
        }
        return Ok(());
    }

    let repo_path = share::resolve_repo(Path::new("."))?;
    match share::revoke_at(&repo_path, node_id, write_only)? {
        Revoked::RemovedMember => eprintln!("revoked all access for {node}"),
        Revoked::DowngradedToReadOnly => {
            eprintln!("revoked write access for {node} (still read-only)")
        }
        Revoked::AlreadyReadOnly => eprintln!("{node} already had read-only access"),
        Revoked::NotAMember => bail!("{node} was not granted access to this repository"),
        Revoked::RepoNotShared => bail!("this repository isn't shared"),
    }
    Ok(())
}

fn stop(share_id: Option<&str>, all: bool) -> Result<()> {
    match (share_id, all) {
        (Some(_), true) => bail!("pass either a SHARE_ID or --all, not both"),
        (None, false) => {
            bail!("give a SHARE_ID (from `list`), or pass --all to stop sharing every repository")
        }
        (None, true) => {
            let n = share::unshare_all()?;
            if n == 0 {
                eprintln!("no shared repositories");
            } else {
                eprintln!("stopped sharing {}", repos(n));
            }
        }
        (Some(id), false) => {
            let repo_id = RepoId::parse(id).with_context(|| format!("invalid SHARE_ID {id:?}"))?;
            if share::unshare_by_id(repo_id)? {
                eprintln!("stopped sharing the repository with id {id}");
            } else {
                bail!("no shared repository with id {id}");
            }
        }
    }
    Ok(())
}

/// Pluralize a repository count for human-readable output.
fn repos(n: usize) -> String {
    if n == 1 {
        "1 repository".to_string()
    } else {
        format!("{n} repositories")
    }
}

fn list() -> Result<()> {
    let grants = Grants::load()?;
    if grants.repos.is_empty() {
        println!("no shared repositories");
        return Ok(());
    }
    for repo in &grants.repos {
        println!("{}  [{}]", repo.path, repo.id);
        if repo.members.is_empty() {
            println!("    (no members)");
        }
        for m in &repo.members {
            let mode = if m.allow_push { "rw" } else { "ro" };
            if m.nickname.is_empty() {
                println!("    {mode}  {}", m.node_id);
            } else {
                println!("    {mode}  {}  ({})", m.nickname, m.node_id);
            }
        }
    }
    Ok(())
}
