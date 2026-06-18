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

/// Upper bound on a framed handshake message, to bound allocation.
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
