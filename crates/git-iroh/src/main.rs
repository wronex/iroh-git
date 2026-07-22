//! `git-iroh` - the human-facing porcelain, run as `git iroh <cmd>`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use iroh_git::config::{GrantOutcome, Grants};
use iroh_git::identity::{self, Role};
use iroh_git::lfs::{self, Session, UploadOutcome};
use iroh_git::share::{self, LfsToggle, RevokeWhat, Revoked};
use iroh_git::{RepoId, Ticket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

mod lfs_hook;

/// Concurrent object transfers for `lfs-pull`/`lfs-push`. This is in-process
/// fan-out over one connection (one identity); see the LFS notes in `iroh_git::lfs`.
const PARALLEL: usize = 8;

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
        /// Allow this node to transfer Git LFS objects (download; combine with
        /// --write for upload). Requires the repo to have LFS enabled
        /// (`git iroh lfs-enable`). Additive.
        #[arg(long)]
        lfs: bool,
        /// Optional nickname so you can tell friends apart in `list`.
        #[arg(long)]
        name: Option<String>,
    },
    /// Revoke a member's access to a repository.
    ///
    /// By default this removes the member (NODE_ID) from the repository in the
    /// current directory. Pass --all to remove them from every repository you
    /// share, --write to only revoke push access, or --lfs to only revoke LFS
    /// access (both keep read access intact).
    Revoke {
        /// The member's NODE_ID (from their `git iroh show-id`).
        node_id: String,
        /// Only revoke write (push) access, leaving read access intact.
        #[arg(long)]
        write: bool,
        /// Only revoke LFS access, leaving clone/push access intact.
        #[arg(long)]
        lfs: bool,
        /// Apply to every repository you share, not just the current directory.
        #[arg(long)]
        all: bool,
    },
    /// Stop sharing a repository entirely.
    ///
    /// Removes the repository and all its members. Identify the repository by its
    /// SHARE_ID (from `list`), pass --this for the repository in the current
    /// directory, or pass --all to stop sharing everything.
    Stop {
        /// The repository's SHARE_ID (from `list`). Omit when using --this/--all.
        share_id: Option<String>,
        /// Stop sharing the repository in the current directory.
        #[arg(long)]
        this: bool,
        /// Stop sharing every repository.
        #[arg(long)]
        all: bool,
    },
    /// List shared repositories and their authorized members.
    List,
    /// Enable Git LFS transfer for the repository in the current directory.
    ///
    /// LFS is off by default for every shared repo. With it enabled, members you
    /// grant `--lfs` can transfer objects over iroh.
    LfsEnable,
    /// Disable Git LFS transfer for the repository in the current directory.
    LfsDisable,
    /// Configure this repository to transfer Git LFS objects over iroh.
    ///
    /// Writes the local git config pointing Git LFS at the `git-lfs-iroh`
    /// transfer agent. Run once per clone - the config can't be committed (Git
    /// LFS refuses to run a transfer agent named by a cloned repo, for security).
    /// Afterwards `git lfs pull`/`push` ride your iroh remote automatically.
    LfsSetup,
    /// Stop the git-lfs pre-push hook from stalling pushes to iroh remotes.
    ///
    /// `git lfs install` leaves a hook that runs for every remote, and git-lfs
    /// cannot parse `iroh://` URLs - it reads the scheme as an SSH hostname and
    /// retries a doomed `ssh iroh` several times, adding ~20 s to every push
    /// (even in a repository that tracks no LFS files at all). This inserts one
    /// line at the top of that hook so it skips iroh remotes it has no way to
    /// transfer over; a repository set up with `lfs-setup` still runs git-lfs,
    /// as does every non-iroh remote. Idempotent, and it never touches a hook
    /// that isn't git-lfs's.
    GuardLfsHook,
    /// Fetch missing Git LFS objects over iroh, then update the working tree.
    ///
    /// The iroh equivalent of `git lfs pull`: downloads the objects referenced by
    /// the given refs (default: current HEAD) that are missing locally, with
    /// concurrent transfers over a single connection, then checks them out.
    LfsPull {
        /// Remote to fetch from.
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Refs to consider (default: current HEAD).
        refs: Vec<String>,
    },
    /// Upload Git LFS objects over iroh.
    ///
    /// The iroh equivalent of `git lfs push`: uploads the objects referenced by
    /// the given refs (default: current HEAD); the daemon skips any it already
    /// has. Run before `git push` so the receiver can resolve the pointers.
    LfsPush {
        /// Remote to push to.
        #[arg(long, default_value = "origin")]
        remote: String,
        /// Refs to consider (default: current HEAD).
        refs: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::ShowId => {
            let secret = identity::load_or_create(Role::Client)?;
            println!("{}", secret.public());
        }
        Cmd::Keygen { client, server, force } => keygen(client, server, force)?,
        Cmd::Grant { node_id, write, lfs, name } => {
            grant(&node_id, write, lfs, name.as_deref().unwrap_or(""))?
        }
        Cmd::Revoke { node_id, write, lfs, all } => revoke(&node_id, write, lfs, all)?,
        Cmd::Stop { share_id, this, all } => stop(share_id.as_deref(), this, all)?,
        Cmd::List => list()?,
        Cmd::LfsEnable => lfs_enable()?,
        Cmd::LfsDisable => lfs_disable()?,
        Cmd::LfsSetup => lfs_setup()?,
        Cmd::GuardLfsHook => guard_lfs_hook()?,
        Cmd::LfsPull { remote, refs } => lfs_pull(&remote, &refs)?,
        Cmd::LfsPush { remote, refs } => lfs_push(&remote, &refs)?,
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

fn grant(node_id: &str, write: bool, lfs: bool, name: &str) -> Result<()> {
    let g = share::grant(Path::new("."), node_id, write, lfs, name)?;
    match g.outcome {
        GrantOutcome::Added => eprintln!("granted read-only access to {}", g.repo_path),
        GrantOutcome::AddedWrite => eprintln!("granted read-write access to {}", g.repo_path),
        GrantOutcome::UpgradedToWrite => {
            eprintln!("upgraded {} to read-write - their existing remote is unchanged", g.node_id)
        }
        GrantOutcome::Unchanged => {
            // Only claim nothing changed when LFS didn't change either.
            if !g.lfs_added {
                eprintln!("{} already has access - their existing remote is unchanged", g.node_id);
            }
        }
    }
    if lfs {
        if g.lfs_added {
            eprintln!("granted LFS access to {}", g.node_id);
        } else {
            eprintln!("{} already had LFS access", g.node_id);
        }
        if !g.lfs_enabled {
            eprintln!(
                "note: LFS isn't enabled on this repository yet - run `git iroh lfs-enable` so members can use it"
            );
        }
    }
    println!("{}", g.ticket.encode());
    Ok(())
}

fn revoke(node_id: &str, write_only: bool, lfs_only: bool, all: bool) -> Result<()> {
    if write_only && lfs_only {
        bail!("pass only one of --write or --lfs");
    }
    let what = if write_only {
        RevokeWhat::Write
    } else if lfs_only {
        RevokeWhat::Lfs
    } else {
        RevokeWhat::Member
    };
    let node = share::canonical_node_id(node_id)?;

    if all {
        let n = share::revoke_everywhere(node_id, what)?;
        match (n, what) {
            (0, RevokeWhat::Write) => eprintln!("{node} had no write access to revoke in any repository"),
            (0, RevokeWhat::Lfs) => eprintln!("{node} had no LFS access to revoke in any repository"),
            (0, RevokeWhat::Member) => eprintln!("{node} was not a member of any repository"),
            (n, RevokeWhat::Write) => eprintln!("revoked write access for {node} in {}", repos(n)),
            (n, RevokeWhat::Lfs) => eprintln!("revoked LFS access for {node} in {}", repos(n)),
            (n, RevokeWhat::Member) => eprintln!("revoked all access for {node} in {}", repos(n)),
        }
        return Ok(());
    }

    let repo_path = share::resolve_repo(Path::new("."))?;
    match share::revoke_at(&repo_path, node_id, what)? {
        Revoked::RemovedMember => eprintln!("revoked all access for {node}"),
        Revoked::DowngradedToReadOnly => {
            eprintln!("revoked write access for {node} (still read-only)")
        }
        Revoked::AlreadyReadOnly => eprintln!("{node} already had read-only access"),
        Revoked::LfsRevoked => eprintln!("revoked LFS access for {node}"),
        Revoked::AlreadyNoLfs => eprintln!("{node} already had no LFS access"),
        Revoked::NotAMember => bail!("{node} was not granted access to this repository"),
        Revoked::RepoNotShared => bail!("this repository isn't shared"),
    }
    Ok(())
}

fn stop(share_id: Option<&str>, this: bool, all: bool) -> Result<()> {
    let selectors = share_id.is_some() as u8 + this as u8 + all as u8;
    if selectors > 1 {
        bail!("pass only one of a SHARE_ID, --this, or --all");
    }
    if selectors == 0 {
        bail!("give a SHARE_ID (from `list`), or pass --this for the current repository or --all for every repository");
    }

    if all {
        let n = share::unshare_all()?;
        if n == 0 {
            eprintln!("no shared repositories");
        } else {
            eprintln!("stopped sharing {}", repos(n));
        }
    } else if this {
        let repo_path = share::resolve_repo(Path::new("."))?;
        if share::unshare(&repo_path)? {
            eprintln!("stopped sharing {repo_path}");
        } else {
            bail!("this repository isn't shared");
        }
    } else {
        let id = share_id.expect("exactly one selector is set");
        let repo_id = RepoId::parse(id).with_context(|| format!("invalid SHARE_ID {id:?}"))?;
        if share::unshare_by_id(repo_id)? {
            eprintln!("stopped sharing the repository with id {id}");
        } else {
            bail!("no shared repository with id {id}");
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
        let lfs = if repo.lfs_enabled { "  (LFS on)" } else { "" };
        println!("{}  [{}]{lfs}", repo.path, repo.id);
        if repo.members.is_empty() {
            println!("    (no members)");
        }
        for m in &repo.members {
            let mode = if m.allow_push { "rw" } else { "ro" };
            let lfs = if m.allow_lfs { " +lfs" } else { "" };
            if m.nickname.is_empty() {
                println!("    {mode}{lfs}  {}", m.node_id);
            } else {
                println!("    {mode}{lfs}  {}  ({})", m.nickname, m.node_id);
            }
        }
    }
    Ok(())
}

fn lfs_enable() -> Result<()> {
    let (repo, outcome) = share::set_repo_lfs(Path::new("."), true)?;
    match outcome {
        LfsToggle::Enabled => {
            println!("LFS enabled for {repo}");
            eprintln!("grant members LFS access with `git iroh grant <node_id> --lfs [--write]`");
        }
        LfsToggle::AlreadyInThatState => println!("LFS already enabled for {repo}"),
        LfsToggle::NotShared => {
            bail!("{repo} isn't shared yet; grant someone access first (e.g. `git iroh grant <node_id> --lfs`)")
        }
        LfsToggle::Disabled => unreachable!("enable path"),
    }
    Ok(())
}

fn lfs_disable() -> Result<()> {
    let (repo, outcome) = share::set_repo_lfs(Path::new("."), false)?;
    match outcome {
        LfsToggle::Disabled => println!("LFS disabled for {repo}"),
        LfsToggle::AlreadyInThatState => println!("LFS already disabled for {repo}"),
        LfsToggle::NotShared => println!("{repo} isn't shared; nothing to disable"),
        LfsToggle::Enabled => unreachable!("disable path"),
    }
    Ok(())
}

fn lfs_setup() -> Result<()> {
    let repo = std::env::current_dir().context("getting current directory")?;
    let agent = agent_path();

    run_git(&repo, &["config", "--local", "lfs.standalonetransferagent", "iroh"])?;
    run_git(&repo, &["config", "--local", "lfs.customtransfer.iroh.path", &agent])?;
    // One agent process, one connection: with `concurrent = true` Git LFS would
    // spawn several agent processes, each binding the client identity and
    // colliding on the relay. `git iroh lfs-pull/push` does its own in-process
    // fan-out for speed instead.
    run_git(&repo, &["config", "--local", "lfs.customtransfer.iroh.concurrent", "false"])?;

    println!("configured Git LFS to transfer objects over iroh");
    println!("  agent: {agent}");
    println!("`git lfs pull`/`push` will now ride your iroh remote.");
    Ok(())
}

/// Insert the iroh guard into this repository's git-lfs pre-push hook.
fn guard_lfs_hook() -> Result<()> {
    let repo = std::env::current_dir().context("getting current directory")?;
    match lfs_hook::guard(&repo)? {
        (lfs_hook::Outcome::Added, Some(hook)) => {
            println!("guarded {}", hook.display());
            println!("iroh:// pushes now skip git-lfs unless `git iroh lfs-setup` has run here;");
            println!("every other remote is unchanged.");
        }
        (lfs_hook::Outcome::AlreadyGuarded, _) => println!("already guarded; nothing to do."),
        (lfs_hook::Outcome::NothingToDo, Some(hook)) => {
            println!("left {} alone: it doesn't run git-lfs.", hook.display())
        }
        (lfs_hook::Outcome::NothingToDo, None) => {
            println!("no pre-push hook here; nothing to guard.")
        }
        // `Added` always carries the hook it acted on.
        (lfs_hook::Outcome::Added, None) => unreachable!("a guarded hook has a path"),
    }
    Ok(())
}

fn lfs_pull(remote: &str, refs: &[String]) -> Result<()> {
    let repo = std::env::current_dir().context("getting current directory")?;
    let ticket = resolve_ticket(&repo, remote)?;
    let store = lfs::object_store(&repo)?;

    let missing: Vec<String> = lfs::referenced_oids(&repo, refs)?
        .into_iter()
        .filter(|oid| !lfs::object_path(&store, oid).exists())
        .collect();

    if missing.is_empty() {
        println!("LFS: all referenced objects already present");
    } else {
        println!("LFS: fetching {} object(s) over iroh...", missing.len());
        let (done, failures) = runtime()?.block_on(async {
            let session = Session::connect(&ticket).await?;
            let store = store.clone();
            let result = fan_out(&session, missing, move |s, oid| {
                let store = store.clone();
                async move { s.download(&oid, &lfs::object_path(&store, &oid)).await }
            })
            .await;
            session.close().await;
            anyhow::Ok(result)
        })?;

        for (oid, err) in &failures {
            eprintln!("  failed {oid}: {err:#}");
        }
        println!("LFS: fetched {} object(s)", done.len());
        if !failures.is_empty() {
            bail!("{} LFS object(s) failed to download", failures.len());
        }
    }

    // Smudge the working tree from the now-complete local store.
    run_git(&repo, &["lfs", "checkout"])?;
    lfs_hook::warn_if_unguarded(&repo);
    Ok(())
}

fn lfs_push(remote: &str, refs: &[String]) -> Result<()> {
    let repo = std::env::current_dir().context("getting current directory")?;
    let ticket = resolve_ticket(&repo, remote)?;
    let store = lfs::object_store(&repo)?;

    // Only push objects we actually have. A normal clone references LFS objects it
    // hasn't fetched yet (pointers only); those aren't ours to push, so skip them
    // rather than reporting them as failures.
    let (present, missing): (Vec<String>, Vec<String>) = lfs::referenced_oids(&repo, refs)?
        .into_iter()
        .partition(|oid| lfs::object_path(&store, oid).exists());
    if !missing.is_empty() {
        println!("LFS: skipping {} referenced object(s) not present in the local store", missing.len());
    }
    if present.is_empty() {
        println!("LFS: no local objects to push");
        lfs_hook::warn_if_unguarded(&repo);
        return Ok(());
    }

    println!("LFS: pushing {} object(s) over iroh...", present.len());
    let (done, failures) = runtime()?.block_on(async {
        let session = Session::connect(&ticket).await?;
        let store = store.clone();
        let result = fan_out(&session, present, move |s, oid| {
            let store = store.clone();
            async move {
                let path = lfs::object_path(&store, &oid);
                let size = std::fs::metadata(&path)?.len();
                s.upload(&oid, size, &path).await
            }
        })
        .await;
        session.close().await;
        anyhow::Ok(result)
    })?;

    for (oid, err) in &failures {
        eprintln!("  failed {oid}: {err:#}");
    }
    let uploaded = done.iter().filter(|(_, o)| *o == UploadOutcome::Uploaded).count();
    let skipped = done.len() - uploaded;
    println!("LFS: uploaded {uploaded}, already present {skipped}");
    if !failures.is_empty() {
        bail!("{} LFS object(s) failed to upload", failures.len());
    }
    // The next step is `git push`, which is exactly where the hook bites.
    lfs_hook::warn_if_unguarded(&repo);
    Ok(())
}

/// Run `op` for each oid concurrently over the shared `session`, with at most
/// PARALLEL transfers in flight. Returns the successes (oid + result) and the
/// per-oid failures. This is the in-process fan-out over one connection (one
/// identity) shared by `lfs-pull` and `lfs-push`.
async fn fan_out<T, F, Fut>(
    session: &Session,
    oids: Vec<String>,
    op: F,
) -> (Vec<(String, T)>, Vec<(String, anyhow::Error)>)
where
    T: Send + 'static,
    F: Fn(Session, String) -> Fut,
    Fut: std::future::Future<Output = Result<T>> + Send + 'static,
{
    let sem = Arc::new(Semaphore::new(PARALLEL));
    let mut set = JoinSet::new();
    for oid in oids {
        let sem = sem.clone();
        let task = op(session.clone(), oid.clone());
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.expect("semaphore not closed");
            (oid, task.await)
        });
    }

    let (mut done, mut failures) = (Vec::new(), Vec::new());
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((oid, Ok(v))) => done.push((oid, v)),
            Ok((oid, Err(e))) => failures.push((oid, e)),
            Err(e) => failures.push(("<task>".to_string(), anyhow!("join error: {e}"))),
        }
    }
    (done, failures)
}

/// Resolve a remote name (or `iroh://` URL) to its parsed ticket.
fn resolve_ticket(repo: &Path, remote: &str) -> Result<Ticket> {
    let url = lfs::resolve_remote_url(repo, remote)?;
    Ticket::parse(&url)
        .with_context(|| format!("remote {remote:?} is not an iroh:// remote (url: {url})"))
}

/// Absolute path to the `git-lfs-iroh` binary shipped next to this one, so the
/// configured transfer agent resolves regardless of the working directory.
fn agent_path() -> String {
    let exe = format!("git-lfs-iroh{}", std::env::consts::EXE_SUFFIX);
    match std::env::current_exe() {
        Ok(p) => p.with_file_name(&exe).to_string_lossy().into_owned(),
        Err(_) => exe, // fall back to the bare name (relies on PATH)
    }
}

/// Run `git -C <repo> <args>`, failing on non-zero exit.
fn run_git(repo: &Path, args: &[&str]) -> Result<()> {
    let mut cmd = iroh_git::paths::git_command(repo);
    cmd.args(args);
    let status = cmd.status().with_context(|| format!("running git {}", args.join(" ")))?;
    if !status.success() {
        bail!("git {} failed", args.join(" "));
    }
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")
}
