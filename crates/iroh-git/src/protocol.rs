//! The tiny handshake spoken over an iroh stream before git's native protocol.
//!
//! The remote helper opens a bidirectional stream, sends a [`Request`], and
//! reads a [`Response`]. On [`Response::Ok`] both sides fall through to relaying
//! raw git pack-protocol bytes; the daemon has by then spawned the matching
//! `git upload-pack` / `git receive-pack`.

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Handshake protocol version.
pub const VERSION: u8 = 0;

/// Version of the LFS sub-protocol spoken over [`crate::LFS_ALPN`]. Independent
/// of [`VERSION`]: LFS rides a separate ALPN, so it can evolve without touching
/// the frozen pack handshake that released `git-remote-iroh` clients speak.
pub const LFS_VERSION: u8 = 0;

/// Upper bound on a framed handshake message, to bound allocation. Only the small
/// LFS request/response frames are length-prefixed; object bodies stream raw and
/// are not bound by this.
const MAX_FRAME: usize = 64 * 1024;

/// Which git service the caller wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Service {
    /// Fetch / clone - served by `git upload-pack`.
    UploadPack,
    /// Push - served by `git receive-pack`.
    ReceivePack,
}

impl Service {
    /// The git plumbing subcommand that serves this request.
    pub fn git_subcommand(self) -> &'static str {
        match self {
            Service::UploadPack => "upload-pack",
            Service::ReceivePack => "receive-pack",
        }
    }

    /// Map a remote-helper `connect <service>` argument to a [`Service`].
    pub fn from_connect_arg(arg: &str) -> Option<Service> {
        match arg {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }
}

/// Sent by the helper to open a session.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Request {
    pub version: u8,
    pub repo_id: [u8; 16],
    pub service: Service,
}

/// The daemon's verdict on a [`Request`].
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Error(String),
}

/// Write a length-prefixed postcard frame and flush it.
pub async fn write_msg<W, T>(w: &mut W, msg: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = postcard::to_stdvec(msg).context("encoding message")?;
    let len = u32::try_from(bytes.len()).context("message too large")?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed postcard frame.
pub async fn read_msg<R, T>(r: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("handshake frame of {len} bytes exceeds {MAX_FRAME} limit");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    postcard::from_bytes(&buf).context("decoding message")
}

// --- Git LFS sub-protocol -------------------------------------------------
//
// Spoken over [`crate::LFS_ALPN`], one object per bidirectional stream. Entirely
// separate from the pack handshake above so the released pack wire is frozen.
//
// Download: client sends [`LfsRequest`] (`op = Download`); the daemon replies
// [`LfsResponse::Proceed`] then streams the raw object bytes and finishes the
// stream, or [`LfsResponse::Error`] if the object is absent.
//
// Upload: client sends [`LfsRequest`] (`op = Upload`, with `size`); the daemon
// replies [`LfsResponse::Have`] (object already present, skip the body),
// [`LfsResponse::Error`] (not authorized), or [`LfsResponse::Proceed`] (send the
// body). After the client streams `size` bytes and finishes its half, the daemon
// verifies the sha256 and replies a final [`LfsResponse::Proceed`] (stored) or
// [`LfsResponse::Error`] (mismatch).

/// Which LFS transfer the client wants on this stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LfsOp {
    /// Fetch one object from the daemon's store.
    Download,
    /// Store one object into the daemon's store (requires push access).
    Upload,
}

/// Opens an LFS transfer for a single content-addressed object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LfsRequest {
    pub version: u8,
    pub repo_id: [u8; 16],
    pub op: LfsOp,
    /// Bare 64-hex sha256 oid (no `sha256:` prefix).
    pub oid: String,
    /// Object size in bytes. Authoritative for uploads; ignored for downloads
    /// (the sha256 is the integrity check and the body streams to EOF).
    pub size: u64,
}

/// The daemon's reply within an LFS transfer. The meaning of [`Self::Proceed`]
/// depends on the phase (see the module-level protocol notes).
#[derive(Debug, Serialize, Deserialize)]
pub enum LfsResponse {
    /// Download: bytes follow. Upload phase 1: send the body. Upload phase 2: stored.
    Proceed,
    /// Upload only: the object is already present; skip sending the body.
    Have,
    /// The transfer was refused or failed (unauthorized, missing, or mismatch).
    Error(String),
}
