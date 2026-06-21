// No console window: git-lfs talks to this agent over stdio pipes (inherited
// handles), exactly as git talks to git-remote-iroh, so it never needs a console.
// This avoids a black box flashing when it is launched from a non-console context.
#![cfg_attr(windows, windows_subsystem = "windows")]

//! `git-lfs-iroh` - a Git LFS custom transfer agent that moves objects over iroh.
//!
//! Configured as a *standalone* transfer agent (`lfs.standalonetransferagent`),
//! so git-lfs skips its HTTP batch API entirely and hands us each object to move.
//! We speak git-lfs's line-delimited JSON protocol on stdin/stdout: an `init`,
//! then one `download`/`upload` per object, then `terminate`. All the iroh dialing
//! and object verification lives in [`iroh_git::lfs`]; this binary is just the
//! translation layer.
//!
//! Set up per-repository with `git iroh lfs-setup`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use iroh_git::lfs::{self, Session};
use iroh_git::Ticket;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("git-lfs-iroh: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut out = tokio::io::stdout();
    let mut agent: Option<Agent> = None;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        // Skip an unparseable line rather than aborting: killing the process here
        // would fail every remaining object in the batch, not just this one.
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("git-lfs-iroh: ignoring unparseable message: {e}");
                continue;
            }
        };
        match msg["event"].as_str() {
            Some("init") => {
                let remote = msg["remote"].as_str().unwrap_or_default();
                match Agent::init(remote).await {
                    Ok(a) => {
                        agent = Some(a);
                        // An empty object signals init success.
                        send(&mut out, &json!({})).await?;
                    }
                    Err(e) => {
                        send(&mut out, &json!({"error": {"code": 1, "message": format!("{e:#}")}}))
                            .await?;
                    }
                }
            }
            Some("download") => {
                let oid = msg["oid"].as_str().unwrap_or_default().to_string();
                let result = match agent.as_ref() {
                    Some(a) => a.download(&oid).await.map(Some),
                    None => Err(anyhow!("download before init")),
                };
                send(&mut out, &complete(&oid, result)).await?;
            }
            Some("upload") => {
                let oid = msg["oid"].as_str().unwrap_or_default().to_string();
                let path = msg["path"].as_str().unwrap_or_default().to_string();
                // git-lfs always sends `size`, but fall back to the file's actual
                // length rather than 0 (which the daemon would reject as a mismatch).
                let size = msg["size"]
                    .as_u64()
                    .unwrap_or_else(|| std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0));
                let result = match agent.as_ref() {
                    Some(a) => a.upload(&oid, size, &path).await.map(|_| None),
                    None => Err(anyhow!("upload before init")),
                };
                send(&mut out, &complete(&oid, result)).await?;
            }
            Some("terminate") => break,
            _ => {} // ignore unknown / future events
        }
    }

    if let Some(a) = agent {
        a.session.close().await;
    }
    Ok(())
}

/// The connected agent: one iroh session, plus where to stage downloaded objects.
struct Agent {
    session: Session,
    /// Directory to stage downloads in; git-lfs moves the finished file into the
    /// object store, so keeping this on the same filesystem makes that a rename.
    stage: PathBuf,
}

impl Agent {
    async fn init(remote: &str) -> Result<Agent> {
        let cwd = std::env::current_dir().context("getting current directory")?;
        let url = lfs::resolve_remote_url(&cwd, remote)?;
        let ticket = Ticket::parse(&url)?;
        let session = Session::connect(&ticket).await?;
        let stage = stage_dir(&cwd);
        tokio::fs::create_dir_all(&stage).await.ok();
        Ok(Agent { session, stage })
    }

    /// Download `oid` to a staging file and return its path for git-lfs to move.
    async fn download(&self, oid: &str) -> Result<String> {
        let oid = lfs::normalize_oid(oid)?;
        let dest = self.stage.join(&oid);
        self.session.download(&oid, &dest).await?;
        Ok(dest.to_string_lossy().into_owned())
    }

    async fn upload(&self, oid: &str, size: u64, path: &str) -> Result<()> {
        self.session.upload(oid, size, Path::new(path)).await?;
        Ok(())
    }
}

/// Where to stage downloads: `<git-dir>/lfs/tmp` when we can find it (same
/// filesystem as the object store), else the system temp directory.
fn stage_dir(repo: &Path) -> PathBuf {
    match lfs::object_store(repo) {
        Ok(store) => store.parent().map(|p| p.join("tmp")).unwrap_or_else(std::env::temp_dir),
        Err(_) => std::env::temp_dir(),
    }
}

/// Build the `complete` reply for a transfer: `Ok(Some(path))` for a finished
/// download, `Ok(None)` for a finished upload, `Err` to report a failure.
fn complete(oid: &str, result: Result<Option<String>>) -> Value {
    match result {
        Ok(Some(path)) => json!({"event": "complete", "oid": oid, "path": path}),
        Ok(None) => json!({"event": "complete", "oid": oid}),
        Err(e) => {
            json!({"event": "complete", "oid": oid, "error": {"code": 2, "message": format!("{e:#}")}})
        }
    }
}

/// Write one JSON message followed by a newline, and flush.
async fn send<W>(out: &mut W, msg: &Value) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let mut line = msg.to_string();
    line.push('\n');
    out.write_all(line.as_bytes()).await?;
    out.flush().await?;
    Ok(())
}
