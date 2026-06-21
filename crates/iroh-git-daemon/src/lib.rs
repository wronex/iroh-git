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
use iroh_git::protocol::{
    self, LfsOp, LfsRequest, LfsResponse, Request, Response, Service, LFS_VERSION, VERSION,
};
use iroh_git::{lfs, RepoId, ALPN, LFS_ALPN};
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

/// Max concurrent object transfers served per LFS connection. A connection holds
/// one connection-permit; this bounds the per-object stream tasks behind it, so a
/// single peer can't fan out unbounded file/hash work from one slot.
const MAX_LFS_STREAMS_PER_CONN: usize = 16;

/// Max time a single LFS object transfer may run before it is aborted, so a
/// stalled or slow-trickle peer can't pin a stream task (and its temp file) open.
const LFS_TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

/// How long an LFS connection may sit idle - no new object stream and nothing in
/// flight - before the daemon closes it and reclaims its connection slot. iroh
/// keep-alives connections, so without this an idle (or parked) LFS connection
/// would hold one of the limited connection permits indefinitely.
const LFS_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Lock a mutex, tolerating poison. The daemon's locked sections are short and
/// panic-free, so a poisoned lock (from a panic in some other holder) should
/// never be allowed to wedge connection handling - take the inner value anyway.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// In-flight git-serving sessions, keyed by a unique id, so a grants change can
/// close any whose caller the new grants no longer authorize.
type Sessions = Arc<Mutex<HashMap<u64, ActiveSession>>>;

/// How to re-check a live session against reloaded grants.
enum Reauth {
    /// A git pack session: re-run the full pack authorization.
    Pack(Request),
    /// An LFS connection (one per friend, many object streams): keep it only while
    /// the caller still has LFS access to this repository. Holds the repo id.
    Lfs([u8; 16]),
}

/// Everything needed to re-authorize a live session and close it if revoked.
struct ActiveSession {
    caller: PublicKey,
    auth: Reauth,
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

fn register(sessions: &Sessions, caller: PublicKey, auth: Reauth, conn: Connection) -> SessionGuard {
    let id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    lock(sessions).insert(id, ActiveSession { caller, auth, conn });
    SessionGuard { sessions: sessions.clone(), id }
}

fn register_session(
    sessions: &Sessions,
    caller: PublicKey,
    req: Request,
    conn: Connection,
) -> SessionGuard {
    register(sessions, caller, Reauth::Pack(req), conn)
}

fn register_lfs_session(
    sessions: &Sessions,
    caller: PublicKey,
    repo_id: [u8; 16],
    conn: Connection,
) -> SessionGuard {
    register(sessions, caller, Reauth::Lfs(repo_id), conn)
}

impl ActiveSession {
    /// Whether the reloaded `grants` still authorize this live session.
    fn still_authorized(&self, grants: &Grants) -> bool {
        match &self.auth {
            Reauth::Pack(req) => authorize(grants, req, &self.caller).is_ok(),
            Reauth::Lfs(repo_id) => lfs_session_authorized(grants, repo_id, &self.caller),
        }
    }
}

/// Close every in-flight session the just-reloaded `grants` no longer authorize
/// (member removed, repo unshared, write revoked mid-push, or LFS access dropped).
/// Closing tears down the connection, ending the serve task.
fn close_revoked_sessions(sessions: &Sessions, grants: &Grants) {
    // Snapshot the connections to close while briefly holding the sessions lock,
    // then close them after releasing it, so a finishing serve (SessionGuard::drop)
    // or a new registration doesn't block behind the whole sweep.
    let revoked: Vec<(PublicKey, Connection)> = {
        let map = lock(sessions);
        map.values()
            .filter(|s| !s.still_authorized(grants))
            .map(|s| (s.caller, s.conn.clone()))
            .collect()
    };
    for (caller, conn) in revoked {
        conn.close(VarInt::from_u32(CLOSE_REVOKED), b"access revoked");
        eprintln!("closed revoked session for {}", caller.fmt_short());
    }
}

/// Whether `caller` may still use LFS on the repo identified by `repo_id` (a
/// member of a repo whose LFS is enabled, holding the LFS right). Drives the
/// connection-level teardown for LFS; per-object direction (download vs upload) is
/// re-checked per stream by [`authorize_lfs`].
fn lfs_session_authorized(grants: &Grants, repo_id: &[u8; 16], caller: &PublicKey) -> bool {
    match resolve_member(grants, repo_id, caller) {
        Ok((repo, member)) => repo.lfs_enabled && member.allow_lfs,
        Err(_) => false,
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
        .alpns(vec![ALPN.to_vec(), LFS_ALPN.to_vec()])
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
                    // Publish the new grants FIRST so any connection authorizing
                    // concurrently sees them, THEN sweep live sessions. (Sweeping
                    // before the swap left a window where a just-authorized session
                    // escaped both; `handle` also re-checks after registering.)
                    *lock(&grants) = reloaded;
                    lock(&status).repos = n;
                    close_revoked_sessions(&sessions, &lock(&grants));
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

    // Route by negotiated ALPN. LFS keeps one connection open for many per-object
    // streams, so it has its own handler; everything else is the git pack protocol.
    if conn.alpn() == LFS_ALPN {
        return handle_lfs(conn, grants, sessions, permit).await;
    }

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
            // Close the reload-between-authorize-and-register race: if a grants
            // change landed in that window the sweep may not have seen us yet, so
            // re-check against the now-current grants before serving.
            if authorize(&lock(&grants), &req, &caller).is_err() {
                return Ok(());
            }
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

/// Resolve the repo addressed by `repo_id` and the member matching `caller`. The
/// unknown-repo and not-a-member denials use the same vague `public` text so an
/// outsider holding a (possibly leaked) ticket can't tell them apart, while the
/// `log` records the precise reason locally.
fn resolve_member<'a>(
    grants: &'a Grants,
    repo_id: &[u8; 16],
    caller: &PublicKey,
) -> std::result::Result<(&'a config::RepoGrant, &'a config::Member), Denied> {
    let repo = grants
        .repos
        .iter()
        .find(|r| RepoId::parse(&r.id).map(|id| id.as_bytes() == repo_id).unwrap_or(false))
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

    Ok((repo, member))
}

/// Authorize a pack request: the repo must exist, the caller must be a member,
/// and push requires `allow_push`.
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

    let (repo, member) = resolve_member(grants, &req.repo_id, caller)?;

    if matches!(req.service, Service::ReceivePack) && !member.allow_push {
        return Err(Denied::plain("this repository is read-only for you"));
    }

    Ok((PathBuf::from(&repo.path), req.service))
}

/// Authorize an LFS object transfer. On top of [`authorize`]'s repo/member check,
/// the repo's LFS switch must be on and the member must hold the LFS right; uploads
/// also require push access. The LFS-specific denials are clearer (not the vague
/// `NOT_AUTHORIZED`) because they only run for an established member, who already
/// knows the repo exists and that they belong to it.
fn authorize_lfs(
    grants: &Grants,
    req: &LfsRequest,
    caller: &PublicKey,
) -> std::result::Result<PathBuf, Denied> {
    if req.version != LFS_VERSION {
        return Err(Denied::plain(format!(
            "unsupported LFS protocol version {}",
            req.version
        )));
    }

    let (repo, member) = resolve_member(grants, &req.repo_id, caller)?;

    if !repo.lfs_enabled {
        return Err(Denied::plain("LFS is not enabled for this repository"));
    }
    if !member.allow_lfs {
        return Err(Denied::plain("you do not have LFS access to this repository"));
    }
    if matches!(req.op, LfsOp::Upload) && !member.allow_push {
        return Err(Denied::plain("this repository is read-only for you"));
    }

    Ok(PathBuf::from(&repo.path))
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
    // (tokio's Command has its own creation_flags, distinct from std's.)
    #[cfg(windows)]
    cmd.creation_flags(iroh_git::paths::CREATE_NO_WINDOW);
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

/// Serve LFS object transfers on a connection. The client opens one bidirectional
/// stream per object; each is authorized and served independently, so a grants
/// change also takes effect on the next object. The connection is registered in
/// `sessions` on its first object so a revoke (or LFS-disable) closes it outright,
/// and pinned to a single repository so that revoke check stays exact. `_permit`
/// (the connection slot) plus a per-connection stream semaphore bound the work
/// behind it, and an idle timeout reclaims the slot from a parked connection.
async fn handle_lfs(
    conn: Connection,
    grants: Arc<Mutex<Grants>>,
    sessions: Sessions,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let caller = conn.remote_id();
    let stream_sem = Arc::new(Semaphore::new(MAX_LFS_STREAMS_PER_CONN));
    // Registered (and the repo pinned) on the first object; dropped when the loop
    // ends. `repo_id` doubles as "have we registered yet?".
    let mut guard: Option<SessionGuard> = None;
    let mut repo_id: Option<[u8; 16]> = None;

    loop {
        // Wait for the next object stream, but don't let an idle connection pin its
        // slot: time out only when nothing is in flight. A running transfer holds a
        // stream permit, so available < max means "busy - keep waiting".
        let (mut send, mut recv) = tokio::select! {
            accepted = conn.accept_bi() => match accepted {
                Ok(streams) => streams,
                Err(_) => return Ok(()), // client closed - normal end of session
            },
            _ = tokio::time::sleep(LFS_IDLE_TIMEOUT) => {
                if stream_sem.available_permits() == MAX_LFS_STREAMS_PER_CONN {
                    return Ok(()); // idle with nothing in flight - reclaim the slot
                }
                continue; // transfers still running; keep the connection open
            }
        };

        // Bound the per-stream request read so an opened-but-silent stream can't stall us.
        let req: LfsRequest = match timeout(HANDSHAKE_TIMEOUT, protocol::read_msg(&mut recv)).await {
            Ok(Ok(r)) => r,
            _ => continue, // slow or broken stream; drop it and keep serving
        };

        // Register on the first object (so a revoke can close us) and pin the repo:
        // the wire carries a per-stream repo id, but the connection-level revoke
        // check tracks one, so reject any later stream that addresses a different one.
        match repo_id {
            None => {
                repo_id = Some(req.repo_id);
                guard = Some(register_lfs_session(&sessions, caller, req.repo_id, conn.clone()));
            }
            Some(id) if id != req.repo_id => {
                let msg = "an LFS connection may address only one repository".to_string();
                let _ = protocol::write_msg(&mut send, &LfsResponse::Error(msg)).await;
                let _ = send.finish();
                continue;
            }
            Some(_) => {}
        }

        // Cap concurrent object transfers per connection; the loop blocks here
        // (back-pressure) once MAX_LFS_STREAMS_PER_CONN are in flight.
        let permit = match stream_sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let grants = grants.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the transfer's lifetime
            if let Err(e) = serve_lfs_request(send, recv, req, caller, grants).await {
                eprintln!("lfs stream error: {e:#}");
            }
        });
    }
    drop(guard);
    Ok(())
}

/// Authorize and serve one already-read LFS object request, bounding the transfer
/// itself with a timeout so a stalled peer can't pin the stream forever.
async fn serve_lfs_request(
    mut send: SendStream,
    mut recv: RecvStream,
    req: LfsRequest,
    caller: PublicKey,
    grants: Arc<Mutex<Grants>>,
) -> Result<()> {
    let decision = {
        let grants = lock(&grants);
        authorize_lfs(&grants, &req, &caller)
    };

    match decision {
        Ok(path) => {
            let op = match req.op {
                LfsOp::Download => "download",
                LfsOp::Upload => "upload",
            };
            eprintln!("{} -> lfs {op} {}", caller.fmt_short(), req.oid);
            let transfer = lfs::serve(req.op, &path, &req.oid, req.size, &mut recv, &mut send);
            match timeout(LFS_TRANSFER_TIMEOUT, transfer).await {
                Ok(r) => r?,
                Err(_) => bail!("lfs {op} of {} timed out", req.oid),
            }
        }
        Err(denied) => {
            protocol::write_msg(&mut send, &LfsResponse::Error(denied.public)).await?;
            let _ = send.finish();
            eprintln!("rejected lfs {}: {}", caller.fmt_short(), denied.log);
        }
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
                // LFS on by default in tests so the LFS-authz cases exercise the
                // member-level checks; the repo/member gates are toggled per test.
                lfs_enabled: true,
                members: vec![Member {
                    node_id: member.to_string(),
                    nickname: String::new(),
                    allow_push,
                    allow_lfs: true,
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

    fn lfs_req(repo: &RepoId, op: LfsOp) -> LfsRequest {
        LfsRequest { version: LFS_VERSION, repo_id: *repo.as_bytes(), op, oid: "a".repeat(64), size: 0 }
    }

    #[test]
    fn lfs_download_needs_membership_upload_needs_push() {
        let repo = RepoId::random().unwrap();
        let m = key(1);

        let ro = grants_with(&repo, &m, false);
        assert!(authorize_lfs(&ro, &lfs_req(&repo, LfsOp::Download), &m).is_ok());
        assert!(authorize_lfs(&ro, &lfs_req(&repo, LfsOp::Upload), &m).is_err());

        let rw = grants_with(&repo, &m, true);
        assert!(authorize_lfs(&rw, &lfs_req(&repo, LfsOp::Upload), &m).is_ok());
    }

    #[test]
    fn lfs_non_member_denied() {
        let repo = RepoId::random().unwrap();
        let g = grants_with(&repo, &key(1), false);
        assert!(authorize_lfs(&g, &lfs_req(&repo, LfsOp::Download), &key(2)).is_err());
    }

    #[test]
    fn lfs_denied_when_repo_lfs_disabled() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let mut g = grants_with(&repo, &m, true);
        g.repos[0].lfs_enabled = false;
        // Even a write member with the LFS right can't transfer when the repo's
        // LFS switch is off.
        assert!(authorize_lfs(&g, &lfs_req(&repo, LfsOp::Download), &m).is_err());
        assert!(authorize_lfs(&g, &lfs_req(&repo, LfsOp::Upload), &m).is_err());
    }

    #[test]
    fn lfs_denied_without_member_lfs_right() {
        let repo = RepoId::random().unwrap();
        let m = key(1);
        let mut g = grants_with(&repo, &m, true);
        g.repos[0].members[0].allow_lfs = false;
        // Repo LFS is on, member can clone/push, but lacks the explicit LFS grant.
        assert!(authorize_lfs(&g, &lfs_req(&repo, LfsOp::Download), &m).is_err());
    }
}
