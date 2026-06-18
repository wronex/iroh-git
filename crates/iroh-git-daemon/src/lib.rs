//! The iroh-git daemon as a library, so both the standalone `iroh-git-daemon`
//! binary and the Windows tray app can run the same service.
//!
//! It loads the grants file, hot-reloads it on change, and authorizes every
//! connection by matching the caller's cryptographic NODE_ID against the
//! addressed repository's member list.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use iroh::endpoint::{presets, Connection, Incoming, RecvStream, SendStream, VarInt};
use iroh::{Endpoint, PublicKey};
use iroh_git::config::{self, Grants};
use iroh_git::identity::{self, Role};
use iroh_git::protocol::{self, Request, Response, Service, VERSION};
use iroh_git::{RepoId, ALPN};
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use tokio::process::Command;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// Cap on concurrent in-flight connections. Anyone who learns our NODE_ID (it is
/// public - it travels in every ticket and is discoverable) can open a
/// connection, so without a cap a flood would spawn unbounded tasks. Excess
/// connections are dropped rather than queued.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// How long a freshly accepted connection has to open its stream and send its
/// handshake. Until the handshake completes the caller is effectively
/// unauthenticated (authorization is an app-layer check), so without this bound
/// a peer could hold a connection - and the task serving it - open indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC application close code used when we tear down a session whose access was
/// revoked. The value is informational; the client just sees the connection close.
const CLOSE_REVOKED: u32 = 1;

/// Lock a mutex, tolerating poison. The daemon's locked sections are short and
/// panic-free, so a poisoned lock (from a panic in some other holder) should
/// never be allowed to wedge connection handling - take the inner value anyway.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// In-flight git-serving sessions, keyed by a unique id, so a grants change can
/// close any whose caller the new grants no longer authorize.
type Sessions = Arc<Mutex<HashMap<u64, ActiveSession>>>;

/// Everything needed to re-authorize a live session and close it if revoked.
struct ActiveSession {
    caller: PublicKey,
    req: Request,
    conn: Connection,
}

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(0);

/// Registers a live session and removes it again when dropped (i.e. when the
/// serve finishes, errors, or the connection is closed out from under it).
struct SessionGuard {
    sessions: Sessions,
    id: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        lock(&self.sessions).remove(&self.id);
    }
}

fn register_session(
    sessions: &Sessions,
    caller: PublicKey,
    req: Request,
    conn: Connection,
) -> SessionGuard {
    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    lock(sessions).insert(id, ActiveSession { caller, req, conn });
    SessionGuard { sessions: sessions.clone(), id }
}

/// Close every in-flight session the just-reloaded `grants` no longer authorize
/// (member removed, repo unshared, or write revoked mid-push). Closing tears
/// down the streams, so the serve task's stdio relay ends and git is reaped.
fn close_revoked_sessions(sessions: &Sessions, grants: &Grants) {
    for sess in lock(sessions).values() {
        if authorize(grants, &sess.req, &sess.caller).is_err() {
            sess.conn.close(VarInt::from_u32(CLOSE_REVOKED), b"access revoked");
            eprintln!("closed revoked session for {}", sess.caller.fmt_short());
        }
    }
}

/// A snapshot of the daemon's state, for UIs that want to show status.
#[derive(Clone, Debug, Default)]
pub struct Status {
    /// True once the endpoint has reached a relay and is reachable.
    pub online: bool,
    /// The daemon's NODE_ID (hex), set once online.
    pub node_id: Option<String>,
    /// The relay the daemon is homed on, if any.
    pub relay: Option<String>,
    /// Number of repositories currently shared.
    pub repos: usize,
}

/// Run the daemon until the endpoint closes. `status` is updated in place as the
/// daemon comes online and as grants change, so a caller (e.g. the tray) can read
/// it at any time; the daemon also prints progress to stdout for CLI use.
pub async fn run(status: Arc<Mutex<Status>>) -> Result<()> {
    let grants = Arc::new(Mutex::new(Grants::load()?));
    lock(&status).repos = lock(&grants).repos.len();
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));

    // Keep the watcher alive for the lifetime of the daemon.
    let _watcher = spawn_grants_watcher(grants.clone(), status.clone(), sessions.clone())?;

    let secret = identity::load_or_create(Role::Server)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("binding endpoint: {e}"))?;

    // Wait for a relay home, then record it so `git iroh grant` can hint tickets.
    endpoint.online().await;
    let relay = endpoint.addr().relay_urls().next().map(|u| u.to_string());
    config::write_relay_hint(relay.as_deref())?;

    let node_id = endpoint.id().to_string();
    {
        let mut s = lock(&status);
        s.online = true;
        s.node_id = Some(node_id.clone());
        s.relay = relay.clone();
    }

    println!("iroh-git-daemon online");
    println!("NODE_ID: {node_id}");
    if let Some(r) = &relay {
        println!("relay:   {r}");
    }
    println!("serving {} repositories", lock(&status).repos);

    let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    while let Some(incoming) = endpoint.accept().await {
        // Bound concurrency: drop the connection if we're already at the cap
        // rather than spawning an unbounded number of tasks.
        let permit = match limiter.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("at connection limit ({MAX_CONCURRENT_CONNECTIONS}), refusing connection");
                incoming.refuse();
                continue;
            }
        };
        let grants = grants.clone();
        let sessions = sessions.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(incoming, grants, sessions, permit).await {
                eprintln!("connection error: {e:#}");
            }
        });
    }
    Ok(())
}

/// Watch the config directory and reload grants into `grants` on any change.
fn spawn_grants_watcher(
    grants: Arc<Mutex<Grants>>,
    status: Arc<Mutex<Status>>,
    sessions: Sessions,
) -> Result<RecommendedWatcher> {
    let dir = identity::config_dir()?;
    std::fs::create_dir_all(&dir)?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            if res.is_ok() {
                let _ = tx.send(());
            }
        },
        notify::Config::default(),
    )
    .context("creating grants file watcher")?;
    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .context("watching config directory")?;

    tokio::spawn(async move {
        while rx.recv().await.is_some() {
            match Grants::load() {
                Ok(reloaded) => {
                    let n = reloaded.repos.len();
                    // Cut off any in-flight session the new grants revoke, then
                    // publish the new grants for subsequent connections.
                    close_revoked_sessions(&sessions, &reloaded);
                    *lock(&grants) = reloaded;
                    lock(&status).repos = n;
                    println!("grants reloaded ({n} repositories)");
                }
                Err(e) => eprintln!("ignoring grants reload error: {e:#}"),
            }
        }
    });

    Ok(watcher)
}

/// Handle one connection. `permit` bounds concurrency; it is held while git is
/// actually being served, but released early on the rejection path (see below)
/// so a flood of rejected callers can't occupy the limited serving slots.
async fn handle(
    incoming: Incoming,
    grants: Arc<Mutex<Grants>>,
    sessions: Sessions,
    permit: OwnedSemaphorePermit,
) -> Result<()> {
    let conn = incoming
        .await
        .map_err(|e| anyhow::anyhow!("accepting connection: {e}"))?;
    let caller = conn.remote_id();

    // Bound the handshake so a peer that connects but never opens a stream, or
    // opens one and never sends, can't pin this task (and the connection) open.
    let handshake = async {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| anyhow::anyhow!("accepting stream: {e}"))?;
        let req: Request = protocol::read_msg(&mut recv).await?;
        Ok::<_, anyhow::Error>((send, recv, req))
    };
    let (mut send, mut recv, req) = timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| anyhow::anyhow!("handshake timed out"))??;

    // Resolve the authorization decision while holding the lock, then release it
    // before doing any async work.
    let decision = {
        let grants = lock(&grants);
        authorize(&grants, &req, &caller)
    };

    match decision {
        Ok((path, service)) => {
            protocol::write_msg(&mut send, &Response::Ok).await?;
            eprintln!(
                "{} -> {} {}",
                caller.fmt_short(),
                service.git_subcommand(),
                path.display()
            );
            // Register so a concurrent revoke can close this connection; the
            // guard deregisters when the serve finishes or errors.
            let _guard = register_session(&sessions, caller, req, conn.clone());
            serve_git(service, &path, &mut recv, &mut send).await?;
        }
        Err(denied) => {
            protocol::write_msg(&mut send, &Response::Error(denied.public)).await?;
            let _ = send.finish();
            // Log the precise reason locally; the caller only gets the vague form.
            eprintln!("rejected {}: {}", caller.fmt_short(), denied.log);
            // Release the concurrency slot before the courtesy linger: the linger
            // only holds a lightweight future, so rejected callers must not keep
            // occupying the (small) pool that real git serving needs.
            drop(permit);
            // Linger until the client has read the rejection (it closes the
            // connection once it has), so the friend sees the real reason rather
            // than a generic "connection lost".
            let _ = timeout(Duration::from_secs(5), conn.closed()).await;
        }
    }
    // On the Ok path `permit` is held until here, bounding concurrent git serves.
    Ok(())
}

/// A rejected request. `public` is sent to the caller; `log` is recorded
/// server-side. They differ deliberately for the unknown-repo / not-a-member
/// cases: both return the same vague `public` text so a stranger holding a
/// (possibly leaked) ticket cannot tell "this repo doesn't exist here" apart
/// from "you aren't a member of it".
struct Denied {
    public: String,
    log: String,
}

impl Denied {
    /// A denial whose caller-visible and logged text are identical (used when
    /// the reason reveals nothing a legitimate caller doesn't already know).
    fn plain(msg: impl Into<String>) -> Self {
        let msg = msg.into();
        Denied { public: msg.clone(), log: msg }
    }
}

/// The vague rejection shown to the caller for both unknown-repo and
/// not-a-member, so the two are indistinguishable from the outside.
const NOT_AUTHORIZED: &str = "not authorized for this repository";

/// Authorize a request against the grants: the repo must exist, the caller must
/// be a member, and push requires `allow_push`.
fn authorize(
    grants: &Grants,
    req: &Request,
    caller: &PublicKey,
) -> std::result::Result<(PathBuf, Service), Denied> {
    if req.version != VERSION {
        return Err(Denied::plain(format!(
            "unsupported protocol version {}",
            req.version
        )));
    }

    let repo = grants
        .repos
        .iter()
        .find(|r| RepoId::parse(&r.id).map(|id| id.as_bytes() == &req.repo_id).unwrap_or(false))
        .ok_or_else(|| Denied {
            public: NOT_AUTHORIZED.to_string(),
            log: "unknown repository".to_string(),
        })?;

    let member = repo
        .members
        .iter()
        .find(|m| m.node_id.parse::<PublicKey>().map(|n| &n == caller).unwrap_or(false))
        .ok_or_else(|| Denied {
            public: NOT_AUTHORIZED.to_string(),
            log: "caller is not a member".to_string(),
        })?;

    if matches!(req.service, Service::ReceivePack) && !member.allow_push {
        return Err(Denied::plain("this repository is read-only for you"));
    }

    Ok((PathBuf::from(&repo.path), req.service))
}

/// Spawn the git service and splice its stdio onto the iroh stream.
async fn serve_git(
    service: Service,
    repo: &Path,
    recv: &mut RecvStream,
    send: &mut SendStream,
) -> Result<()> {
    let mut cmd = Command::new(iroh_git::paths::git_program());
    // Validate incoming objects on push, so a write-authorized peer can't seed
    // the repo with malformed or fsck-evading objects that would later be served
    // to (and trip up, or attack) everyone else who fetches. `-c` must precede
    // the subcommand. Read-only fetches send objects we already vouch for.
    if matches!(service, Service::ReceivePack) {
        cmd.arg("-c").arg("receive.fsckObjects=true");
    }
    cmd.arg(service.git_subcommand())
        .arg(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    // Don't pop a console window when the daemon runs inside the GUI tray.
    #[cfg(windows)]
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning git {}", service.git_subcommand()))?;

    let mut child_in = child.stdin.take().expect("piped stdin");
    let mut child_out = child.stdout.take().expect("piped stdout");

    // caller -> git stdin
    let to_child = async move {
        tokio::io::copy(recv, &mut child_in).await?;
        // dropping child_in here closes git's stdin (EOF)
        Ok::<_, anyhow::Error>(())
    };
    // git stdout -> caller
    let from_child = async move {
        tokio::io::copy(&mut child_out, send).await?;
        let _ = send.finish();
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(to_child, from_child)?;
    let status = child.wait().await.context("waiting for git")?;
    if !status.success() {
        bail!("git {} exited with {status}", service.git_subcommand());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use iroh_git::config::{Member, RepoGrant};

    fn key(n: u8) -> PublicKey {
        SecretKey::from_bytes(&[n; 32]).public()
    }

    fn grants_with(repo: &RepoId, member: &PublicKey, allow_push: bool) -> Grants {
        Grants {
            repos: vec![RepoGrant {
                id: repo.to_string(),
                path: "/tmp/repo".to_string(),
                members: vec![Member {
                    node_id: member.to_string(),
                    nickname: String::new(),
                    allow_push,
                }],
            }],
        }
    }

    fn req(repo: &RepoId, service: Service) -> Request {
        Request { version: VERSION, repo_id: *repo.as_bytes(), service }
    }

    #[test]
    fn member_may_fetch() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let g = grants_with(&repo, &m, false);
        assert!(authorize(&g, &req(&repo, Service::UploadPack), &m).is_ok());
    }

    #[test]
    fn non_member_denied() {
        let repo = RepoId::random().unwrap();
        let g = grants_with(&repo, &key(1), false);
        assert!(authorize(&g, &req(&repo, Service::UploadPack), &key(2)).is_err());
    }

    #[test]
    fn unknown_repo_denied() {
        let known = RepoId::random().unwrap();
        let other = RepoId::random().unwrap();
        let m = key(1);
        let g = grants_with(&known, &m, false);
        assert!(authorize(&g, &req(&other, Service::UploadPack), &m).is_err());
    }

    #[test]
    fn push_requires_allow_push() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let ro = grants_with(&repo, &m, false);
        assert!(authorize(&ro, &req(&repo, Service::ReceivePack), &m).is_err());
        assert!(authorize(&ro, &req(&repo, Service::UploadPack), &m).is_ok());

        let rw = grants_with(&repo, &m, true);
        assert!(authorize(&rw, &req(&repo, Service::ReceivePack), &m).is_ok());
    }

    #[test]
    fn wrong_version_denied() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let g = grants_with(&repo, &m, false);
        let mut r = req(&repo, Service::UploadPack);
        r.version = VERSION.wrapping_add(1);
        assert!(authorize(&g, &r, &m).is_err());
    }

    // The predicate `close_revoked_sessions` relies on: once the grants change so
    // that a live session would no longer be authorized, re-running `authorize`
    // against the new grants must flip to an error.
    #[test]
    fn revoking_member_flips_to_denied() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let r = req(&repo, Service::ReceivePack);

        let mut g = grants_with(&repo, &m, true);
        assert!(authorize(&g, &r, &m).is_ok());

        // Full revoke: member removed entirely.
        g.repos[0].members.clear();
        assert!(authorize(&g, &r, &m).is_err());
    }

    #[test]
    fn downgrading_write_stops_in_flight_push_but_not_fetch() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let mut g = grants_with(&repo, &m, true);

        // Downgrade to read-only.
        g.repos[0].members[0].allow_push = false;
        assert!(authorize(&g, &req(&repo, Service::ReceivePack), &m).is_err());
        assert!(authorize(&g, &req(&repo, Service::UploadPack), &m).is_ok());
    }
}
