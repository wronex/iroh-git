//! The `iroh://…` ticket: pure addressing, no secret.
//!
//! A ticket names the daemon (`node_id` + optional `relay_url` hint) and which
//! repository to ask for (`repo_id`). Authorization is entirely the daemon's
//! node-id allowlist, so a ticket is safe to reuse and even republish - a leaked
//! ticket only lets a stranger *attempt* a connection the daemon will reject.

use std::fmt;

use anyhow::{Context, Result};
use iroh::PublicKey;
use serde::{Deserialize, Serialize};

/// URL scheme git maps to the `git-remote-iroh` helper.
pub const SCHEME: &str = "iroh://";

/// Opaque per-repository identifier, minted when a repo is first shared.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RepoId([u8; 16]);

impl RepoId {
    /// Mint a fresh random repo id.
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes)
            .map_err(|e| anyhow::anyhow!("gathering randomness for a repo id: {e}"))?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse a repo id from its base32 string form (as stored in grants).
    pub fn parse(s: &str) -> Result<Self> {
        let bytes = data_encoding::BASE32_NOPAD
            .decode(s.to_uppercase().as_bytes())
            .context("repo id is not valid base32")?;
        let arr: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .context("repo id is not 16 bytes")?;
        Ok(Self(arr))
    }
}

impl fmt::Display for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", data_encoding::BASE32_NOPAD.encode(&self.0).to_lowercase())
    }
}

impl fmt::Debug for RepoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoId({self})")
    }
}

/// A decoded `iroh://` ticket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ticket {
    /// The daemon's node id.
    pub node_id: PublicKey,
    /// Relay URL hint; discovery can recover the daemon without it.
    pub relay_url: Option<String>,
    /// Which repository on that daemon this ticket addresses.
    pub repo_id: RepoId,
    /// Cosmetic repository name appended to the URL as `/<name>.git` so a bare
    /// `git clone` lands in a sensibly-named directory. Not part of the
    /// addressing and ignored by the daemon.
    pub name: String,
}

/// Compact wire form fed to postcard. Kept separate so we never depend on serde
/// impls of iroh's own types.
#[derive(Serialize, Deserialize)]
struct Wire {
    node_id: [u8; 32],
    relay_url: Option<String>,
    repo_id: [u8; 16],
}

impl Ticket {
    /// Encode as `iroh://<base32>[/<name>.git]` for use as a git remote. The
    /// trailing name makes a bare `git clone` choose `<name>` as its directory.
    pub fn encode(&self) -> String {
        let wire = Wire {
            node_id: *self.node_id.as_bytes(),
            relay_url: self.relay_url.clone(),
            repo_id: self.repo_id.0,
        };
        let bytes = postcard::to_stdvec(&wire).expect("postcard encoding a ticket cannot fail");
        let token = data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase();
        let mut url = format!("{SCHEME}{token}");
        if !self.name.is_empty() {
            url.push('/');
            url.push_str(&self.name);
            url.push_str(".git");
        }
        url
    }

    /// Parse an `iroh://<base32>[/<name>.git]` remote URL back into a ticket. The
    /// trailing name is cosmetic and recovered for completeness only.
    pub fn parse(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix(SCHEME)
            .with_context(|| format!("not an {SCHEME} url: {s}"))?;
        let (token, name) = match rest.split_once('/') {
            Some((token, path)) => {
                let leaf = path.rsplit('/').next().unwrap_or(path);
                (token, leaf.strip_suffix(".git").unwrap_or(leaf).to_string())
            }
            None => (rest, String::new()),
        };
        let bytes = data_encoding::BASE32_NOPAD
            .decode(token.to_uppercase().as_bytes())
            .context("ticket is not valid base32")?;
        let wire: Wire = postcard::from_bytes(&bytes).context("ticket has an unexpected layout")?;
        let node_id = PublicKey::from_bytes(&wire.node_id).context("ticket has an invalid node id")?;
        Ok(Self {
            node_id,
            relay_url: wire.relay_url,
            repo_id: RepoId(wire.repo_id),
            name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    #[test]
    fn ticket_roundtrips() {
        let node_id = SecretKey::from_bytes(&[7u8; 32]).public();
        let ticket = Ticket {
            node_id,
            relay_url: Some("https://relay.example./".to_string()),
            repo_id: RepoId([0xAB; 16]),
            name: "myrepo".to_string(),
        };

        let encoded = ticket.encode();
        assert!(encoded.starts_with(SCHEME));
        assert!(encoded.ends_with("/myrepo.git"), "url should end in the repo name");
        assert_eq!(encoded, encoded.to_lowercase(), "token must be lowercase");

        let decoded = Ticket::parse(&encoded).expect("round-trip parse");
        assert_eq!(decoded, ticket);
    }

    #[test]
    fn rejects_non_iroh_url() {
        assert!(Ticket::parse("https://example.com").is_err());
    }
}
