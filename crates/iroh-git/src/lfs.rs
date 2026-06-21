//! Git LFS objects over iroh.
//!
//! LFS keeps large blobs out of the git pack: a repository stores only small
//! pointer files (which ride the pack protocol for free), while the object bytes
//! move over a separate transfer. This module carries that transfer over iroh,
//! on its own [`crate::LFS_ALPN`], reusing the daemon's node-id allowlist for
//! authorization (download = read access, upload = push access).
//!
//! [`Session`] is the client side, used by the `git-lfs-iroh` transfer agent and
//! by `git iroh lfs-pull`/`lfs-push`: it dials the daemon once and opens one
//! bidirectional stream per object. [`serve`] is the server side, called by the
//! daemon after it has authorized the request. The remaining helpers locate and
//! enumerate objects in a repository's LFS store, and are shared by both sides.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::Endpoint;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::protocol::{self, LfsOp, LfsRequest, LfsResponse, LFS_VERSION};
use crate::ticket::SCHEME;
use crate::{paths, Ticket, LFS_ALPN};

/// How many bytes to move per chunk when streaming object bodies.
const CHUNK: usize = 64 * 1024;

/// What an [`upload`](Session::upload) did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadOutcome {
    /// The object was streamed to and stored by the daemon.
    Uploaded,
    /// The daemon already had the object; nothing was sent.
    AlreadyHad,
}

/// A client-side connection to a daemon for transferring LFS objects.
///
/// Holds the endpoint and a single connection. Clone it cheaply to fan out
/// concurrent transfers from one process: each [`download`](Self::download) /
/// [`upload`](Self::upload) opens its own bidirectional stream on the shared
/// connection. This is the only concurrency model compatible with the single
/// granted client identity (multiple processes would each bind the client key
/// and collide on the relay).
#[derive(Clone)]
pub struct Session {
    endpoint: Endpoint,
    conn: Connection,
    repo_id: [u8; 16],
}

impl Session {
    /// Dial the daemon named by `ticket` over [`LFS_ALPN`]. Fails fast if the
    /// daemon doesn't advertise the LFS protocol (ALPN negotiation rejects it).
    pub async fn connect(ticket: &Ticket) -> Result<Self> {
        let (endpoint, conn) = crate::dial(ticket, LFS_ALPN)
            .await
            .context("connecting for LFS (does the daemon advertise it?)")?;
        Ok(Self { endpoint, conn, repo_id: *ticket.repo_id.as_bytes() })
    }

    /// Fetch object `oid` into `dest` (parent directories are created). The body
    /// is verified against `oid` before `dest` appears, so a partial or forged
    /// transfer never lands there.
    pub async fn download(&self, oid: &str, dest: &Path) -> Result<()> {
        let oid = normalize_oid(oid)?;
        let (mut send, mut recv) =
            self.conn.open_bi().await.map_err(|e| anyhow!("opening stream: {e}"))?;
        protocol::write_msg(&mut send, &self.request(LfsOp::Download, &oid, 0)).await?;
        match protocol::read_msg::<_, LfsResponse>(&mut recv).await? {
            LfsResponse::Proceed => {}
            LfsResponse::Have => bail!("daemon returned Have for a download"),
            LfsResponse::Error(m) => bail!("daemon refused download of {oid}: {m}"),
        }

        // `staged` removes the partial/forged file if we bail or the rename fails.
        let (mut staged, got, _total) = stage_from_stream(&mut recv, dest).await?;
        if got != oid {
            bail!("object {oid} failed verification (got {got})");
        }
        tokio::fs::rename(staged.path(), dest)
            .await
            .with_context(|| format!("placing object at {}", dest.display()))?;
        staged.disarm();
        Ok(())
    }

    /// Upload the object at `src` (named `oid`, `size` bytes). Returns
    /// [`UploadOutcome::AlreadyHad`] if the daemon already has it.
    pub async fn upload(&self, oid: &str, size: u64, src: &Path) -> Result<UploadOutcome> {
        let oid = normalize_oid(oid)?;
        let (mut send, mut recv) =
            self.conn.open_bi().await.map_err(|e| anyhow!("opening stream: {e}"))?;
        protocol::write_msg(&mut send, &self.request(LfsOp::Upload, &oid, size)).await?;
        match protocol::read_msg::<_, LfsResponse>(&mut recv).await? {
            LfsResponse::Have => return Ok(UploadOutcome::AlreadyHad),
            LfsResponse::Proceed => {}
            LfsResponse::Error(m) => bail!("daemon refused upload of {oid}: {m}"),
        }

        let mut file = tokio::fs::File::open(src)
            .await
            .with_context(|| format!("opening {}", src.display()))?;
        tokio::io::copy(&mut file, &mut send)
            .await
            .with_context(|| format!("uploading {}", src.display()))?;
        let _ = send.finish();

        match protocol::read_msg::<_, LfsResponse>(&mut recv).await? {
            LfsResponse::Proceed | LfsResponse::Have => Ok(UploadOutcome::Uploaded),
            LfsResponse::Error(m) => bail!("daemon rejected upload of {oid}: {m}"),
        }
    }

    fn request(&self, op: LfsOp, oid: &str, size: u64) -> LfsRequest {
        LfsRequest { version: LFS_VERSION, repo_id: self.repo_id, op, oid: oid.to_string(), size }
    }

    /// Gracefully close the connection and endpoint. Best-effort.
    pub async fn close(self) {
        self.conn.close(VarInt::from_u32(0), b"bye");
        self.endpoint.close().await;
    }
}

/// Server side of an LFS transfer, called by the daemon once it has authorized
/// the request. `repo` is the on-disk repository path from the grants file. This
/// drives the whole response sequence (see [`crate::protocol`]).
pub async fn serve(
    op: LfsOp,
    repo: &Path,
    oid: &str,
    size: u64,
    recv: &mut RecvStream,
    send: &mut SendStream,
) -> Result<()> {
    let oid = match normalize_oid(oid) {
        Ok(o) => o,
        Err(e) => {
            protocol::write_msg(send, &LfsResponse::Error(e.to_string())).await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    let store = object_store(repo)?;
    let path = object_path(&store, &oid);

    match op {
        LfsOp::Download => match tokio::fs::File::open(&path).await {
            Ok(mut f) => {
                protocol::write_msg(send, &LfsResponse::Proceed).await?;
                tokio::io::copy(&mut f, send).await?;
                let _ = send.finish();
            }
            Err(_) => {
                let msg = format!("object {oid} not present");
                protocol::write_msg(send, &LfsResponse::Error(msg)).await?;
                let _ = send.finish();
            }
        },
        LfsOp::Upload => {
            if path.exists() {
                protocol::write_msg(send, &LfsResponse::Have).await?;
                let _ = send.finish();
                return Ok(());
            }
            protocol::write_msg(send, &LfsResponse::Proceed).await?;

            // On every branch below except the successful rename, `staged` removes
            // the staging file when it drops at function exit.
            let (mut staged, got, total) = stage_from_stream(recv, &path).await?;
            if got != oid || total != size {
                let msg = format!("verification failed (oid {got}, {total} bytes)");
                protocol::write_msg(send, &LfsResponse::Error(msg)).await?;
            } else if path.exists() {
                // A concurrent upload of the same (content-addressed) object landed
                // first; that's fine since the content is identical.
                protocol::write_msg(send, &LfsResponse::Proceed).await?;
            } else {
                tokio::fs::rename(staged.path(), &path)
                    .await
                    .with_context(|| format!("storing object at {}", path.display()))?;
                staged.disarm();
                protocol::write_msg(send, &LfsResponse::Proceed).await?;
            }
            let _ = send.finish();
        }
    }
    Ok(())
}

/// Normalize an LFS oid to a bare lowercase 64-hex sha256, rejecting anything
/// else. This also defends the server against path traversal and junk oids.
pub fn normalize_oid(oid: &str) -> Result<String> {
    let s = oid.strip_prefix("sha256:").unwrap_or(oid).trim().to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        bail!("not a sha256 lfs oid: {oid:?}")
    }
}

/// The LFS object store for a repository: `<git-dir>/lfs/objects`. Resolves the
/// git dir straight from the filesystem (no `git` subprocess, so this is cheap to
/// call once per object), handling bare repos, normal work trees, and the
/// `.git`-file pointer used by linked worktrees and submodules.
pub fn object_store(repo: &Path) -> Result<PathBuf> {
    Ok(git_dir(repo)?.join("lfs").join("objects"))
}

/// Resolve a repository path to its git directory without spawning git. Handles a
/// normal work tree (`<repo>/.git`) and a bare repository (`<repo>` itself).
///
/// A `.git` *file* (the `gitdir:` pointer used by linked worktrees and submodules)
/// is deliberately rejected rather than followed: chasing an attacker-influenceable
/// pointer could redirect the LFS store outside the shared repository, and such
/// setups never resolved to the right store anyway (they need `--git-common-dir`).
fn git_dir(repo: &Path) -> Result<PathBuf> {
    let dotgit = repo.join(".git");
    if dotgit.is_file() {
        bail!(
            "{} is a linked worktree or submodule (.git file); LFS over iroh \
             needs a normal or bare repository",
            repo.display()
        );
    }
    if dotgit.is_dir() {
        Ok(dotgit) // normal work tree
    } else {
        Ok(repo.to_path_buf()) // no `.git`: the path is itself a (bare) git dir
    }
}

/// Path of object `oid` within `store`: `<store>/ab/cd/<oid>` (the LFS layout).
/// `oid` must be a normalized 64-hex string (see [`normalize_oid`]).
pub fn object_path(store: &Path, oid: &str) -> PathBuf {
    store.join(&oid[0..2]).join(&oid[2..4]).join(oid)
}

/// The set of LFS object oids referenced by `refs` (or the current HEAD/index if
/// `refs` is empty), as reported by `git lfs ls-files --long`. Deduplicated.
pub fn referenced_oids(repo: &Path, refs: &[String]) -> Result<Vec<String>> {
    let mut cmd = paths::git_command(repo);
    cmd.args(["lfs", "ls-files", "--long"]);
    for r in refs {
        cmd.arg(r);
    }
    let out = cmd.output().context("running git lfs ls-files")?;
    if !out.status.success() {
        bail!("git lfs ls-files failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let text = String::from_utf8(out.stdout).context("git lfs ls-files output was not UTF-8")?;

    let mut seen = HashSet::new();
    let mut oids = Vec::new();
    for line in text.lines() {
        // Each line is "<oid> <* | -> <path>"; we want the oid.
        if let Some(tok) = line.split_whitespace().next() {
            if let Ok(oid) = normalize_oid(tok) {
                if seen.insert(oid.clone()) {
                    oids.push(oid);
                }
            }
        }
    }
    Ok(oids)
}

/// Resolve a git remote (a name like `origin`, or an `iroh://` URL) to its
/// `iroh://` URL by consulting `git config`, run inside `repo`.
pub fn resolve_remote_url(repo: &Path, remote: &str) -> Result<String> {
    if remote.starts_with(SCHEME) {
        return Ok(remote.to_string());
    }
    let out = paths::git_command(repo)
        .args(["config", "--get", &format!("remote.{remote}.url")])
        .output()
        .context("running git config")?;
    if !out.status.success() {
        bail!("no url configured for remote {remote:?}");
    }
    let url = String::from_utf8(out.stdout).context("git config output was not UTF-8")?;
    Ok(url.trim().to_string())
}

/// A unique temp path next to `dest`, for staging a download/upload before the
/// atomic rename. The random suffix keeps concurrent transfers of the same oid
/// from colliding on the staging file.
fn tmp_sibling(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().map(|s| s.to_os_string()).unwrap_or_default();
    name.push(format!(".{}.tmp", rand_suffix()));
    dest.with_file_name(name)
}

fn rand_suffix() -> String {
    let mut b = [0u8; 8];
    let _ = getrandom::getrandom(&mut b); // best-effort; collision only risks a retry
    hex::encode(b)
}

/// Removes a staging file when dropped, unless [`disarm`](Self::disarm)ed, so an
/// aborted or failed transfer never leaves a `.tmp` orphan on any error path
/// (stream reset mid-write, disk error, rename failure, ...).
struct TmpGuard(Option<PathBuf>);

impl TmpGuard {
    fn new(path: &Path) -> Self {
        TmpGuard(Some(path.to_path_buf()))
    }

    /// The staging path (valid until [`disarm`](Self::disarm)ed).
    fn path(&self) -> &Path {
        self.0.as_deref().expect("staging file already disarmed")
    }

    /// Keep the file — call once a successful rename has moved it into place.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TmpGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// Stream `recv` to a fresh temp file beside `dest` (creating `dest`'s parent),
/// hashing the bytes as they arrive. Returns a [`TmpGuard`] owning the staging
/// file (removed on drop unless the caller renames it into place and calls
/// [`TmpGuard::disarm`]), the hex sha256, and the byte count. Shared by the client
/// download and the server upload so the read-verify-rename path lives in one place.
async fn stage_from_stream(recv: &mut RecvStream, dest: &Path) -> Result<(TmpGuard, String, u64)> {
    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let guard = TmpGuard::new(&tmp_sibling(dest));
    let mut file = tokio::fs::File::create(guard.path())
        .await
        .with_context(|| format!("creating {}", guard.path().display()))?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = vec![0u8; CHUNK];
    // iroh's RecvStream::read is quinn-style: Ok(Some(n)) bytes, Ok(None) at EOF.
    while let Some(n) = recv.read(&mut buf).await.context("reading object body")? {
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).await?;
        total += n as u64;
    }
    file.flush().await?;
    drop(file);
    Ok((guard, hex::encode(hasher.finalize()), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_prefixed_and_bare() {
        let bare = "a".repeat(64);
        assert_eq!(normalize_oid(&bare).unwrap(), bare);
        assert_eq!(normalize_oid(&format!("sha256:{bare}")).unwrap(), bare);
        assert_eq!(normalize_oid(&format!("  {}\n", bare.to_uppercase())).unwrap(), bare);
    }

    #[test]
    fn normalize_rejects_junk() {
        assert!(normalize_oid("").is_err());
        assert!(normalize_oid("../etc/passwd").is_err());
        assert!(normalize_oid(&"g".repeat(64)).is_err());
        assert!(normalize_oid(&"a".repeat(63)).is_err());
    }

    #[test]
    fn object_path_uses_lfs_fanout() {
        let oid = "ab".to_string() + &"c".repeat(62);
        let p = object_path(Path::new("/store"), &oid);
        assert!(p.ends_with(Path::new("ab").join("cc").join(&oid)));
    }
}
