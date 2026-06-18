//! `git-remote-iroh` - the git remote helper for `iroh://` URLs.
//!
//! Git invokes this as `git-remote-iroh <remote> <url>` and speaks the
//! remote-helper protocol on stdin/stdout. We advertise only the `connect`
//! capability: git then asks us to `connect git-upload-pack` (fetch) or
//! `connect git-receive-pack` (push); we dial the daemon, complete a small
//! handshake, emit a blank line, and relay git's native protocol byte-for-byte.

use std::env;

use anyhow::{bail, Context, Result};
use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayUrl};
use iroh_git::identity::{self, Role};
use iroh_git::protocol::{self, Request, Response, Service, VERSION};
use iroh_git::{Ticket, ALPN};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Stdin, Stdout};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("git-remote-iroh: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    // argv: git-remote-iroh <remote-name> <url>
    if env::args().skip(1).any(|a| matches!(a.as_str(), "--version" | "-V" | "version")) {
        println!("git-remote-iroh {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let url = env::args()
        .nth(2)
        .context("usage: git-remote-iroh <remote> <url>")?;
    let ticket = Ticket::parse(&url)?;

    let mut git_in = BufReader::new(tokio::io::stdin());
    let mut git_out = tokio::io::stdout();
    let mut line = String::new();

    loop {
        line.clear();
        if git_in.read_line(&mut line).await? == 0 {
            return Ok(()); // git closed without asking us to connect
        }
        let cmd = line.trim_end();
        match cmd {
            "" => continue,
            "capabilities" => {
                git_out.write_all(b"connect\n\n").await?;
                git_out.flush().await?;
            }
            _ if cmd.starts_with("connect ") => {
                let arg = cmd["connect ".len()..].trim();
                let service = Service::from_connect_arg(arg)
                    .with_context(|| format!("unsupported service: {arg}"))?;
                return connect_and_relay(ticket, service, git_in, git_out).await;
            }
            other => bail!("unexpected command from git: {other:?}"),
        }
    }
}

async fn connect_and_relay(
    ticket: Ticket,
    service: Service,
    mut git_in: BufReader<Stdin>,
    mut git_out: Stdout,
) -> Result<()> {
    let secret = identity::load_or_create(Role::Client)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .bind()
        .await
        .map_err(|e| anyhow::anyhow!("binding endpoint: {e}"))?;

    let mut addr = EndpointAddr::new(ticket.node_id);
    if let Some(relay) = &ticket.relay_url {
        let relay: RelayUrl = relay.parse().context("ticket relay url")?;
        addr = addr.with_relay_url(relay);
    }

    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .map_err(|e| anyhow::anyhow!("connecting to daemon: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("opening stream: {e}"))?;

    let req = Request {
        version: VERSION,
        repo_id: *ticket.repo_id.as_bytes(),
        service,
    };
    protocol::write_msg(&mut send, &req).await?;
    match protocol::read_msg::<_, Response>(&mut recv).await? {
        Response::Ok => {}
        Response::Error(msg) => {
            // git's `connect` exits silently if we just close, and a GUI git
            // client won't show our stderr. So signal a successful connect, then
            // feed git a protocol-level ERR packet: git itself dies with
            // "fatal: remote error: <msg>", visible everywhere.
            git_out.write_all(b"\n").await?;
            git_out.write_all(&pkt_line_err(&format!("iroh: {msg}"))).await?;
            git_out.flush().await?;
            return Ok(());
        }
    }

    // Tell git the connection is live, then become a dumb pipe.
    git_out.write_all(b"\n").await?;
    git_out.flush().await?;

    // git stdin -> daemon
    let up = async move {
        tokio::io::copy(&mut git_in, &mut send).await?;
        let _ = send.finish();
        Ok::<_, anyhow::Error>(())
    };
    // daemon -> git stdout
    let down = async move {
        tokio::io::copy(&mut recv, &mut git_out).await?;
        git_out.flush().await?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(up, down)?;
    Ok(())
}

/// Build a git pkt-line `ERR <msg>` packet. When git reads this as the first
/// line of a ref advertisement, it dies with `fatal: remote error: <msg>`.
fn pkt_line_err(msg: &str) -> Vec<u8> {
    let payload = format!("ERR {msg}");
    // pkt-line length prefix is 4 hex digits covering the whole line.
    format!("{:04x}{}", payload.len() + 4, payload).into_bytes()
}
