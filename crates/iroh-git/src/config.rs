//! The grants file: which node ids may access which repositories.
//!
//! Written only by `git iroh` (the porcelain), read and watched by the daemon.
//! Authorization is a per-repo allowlist of node ids - there is no secret here,
//! so the file is plain TOML:
//!
//! ```toml
//! [[repo]]
//! id   = "<repo id>"
//! path = "C:\\Dev\\whatever"
//!
//!   [[repo.member]]
//!   node_id    = "<friend node id>"
//!   allow_push = false
//! ```

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::identity::config_dir;
use crate::ticket::RepoId;

/// The whole grants file.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Grants {
    #[serde(default, rename = "repo")]
    pub repos: Vec<RepoGrant>,
}

/// One shared repository and the members allowed to reach it.
#[derive(Debug, Serialize, Deserialize)]
pub struct RepoGrant {
    /// Opaque repo id, minted on first share; appears in tickets.
    pub id: String,
    /// Absolute path to the repository on disk.
    pub path: String,
    /// Whether this repository serves/accepts Git LFS objects over iroh. Off by
    /// default; flipped by `git iroh lfs-enable`. Declared before `members` so it
    /// serializes as a scalar ahead of the `[[repo.member]]` tables (TOML requires
    /// a table's scalar keys to precede its sub-tables).
    #[serde(default, skip_serializing_if = "is_false")]
    pub lfs_enabled: bool,
    #[serde(default, rename = "member")]
    pub members: Vec<Member>,
}

/// A node id authorized to reach a repository.
#[derive(Debug, Serialize, Deserialize)]
pub struct Member {
    pub node_id: String,
    /// Optional human label so the owner can tell friends apart.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nickname: String,
    #[serde(default)]
    pub allow_push: bool,
    /// Whether this member may transfer Git LFS objects: download requires this,
    /// upload requires this and `allow_push`. Granted separately with
    /// `git iroh grant --lfs`, on top of the per-repo `lfs_enabled` switch.
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_lfs: bool,
}

/// serde `skip_serializing_if` helper: keep `false` bools out of the grants file.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Path to the grants file.
pub fn grants_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("grants.toml"))
}

impl Grants {
    /// Load the grants file, returning an empty set if it does not exist yet.
    pub fn load() -> Result<Self> {
        let path = grants_path()?;
        match fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Persist the grants file, creating the config directory if needed.
    ///
    /// Writes to a sibling temp file and atomically renames it over the target,
    /// so the daemon's file watcher never observes a half-written, unparseable
    /// grants file. (On a parse error the watcher keeps the previous, more
    /// permissive grants - which would silently delay a revoke.)
    pub fn save(&self) -> Result<()> {
        let path = grants_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let body = toml::to_string_pretty(self).context("serializing grants")?;

        // The pid keeps concurrent `git iroh` invocations from colliding on the
        // temp name; the rename is atomic and replaces any existing target.
        let file_name = format!(
            "{}.{}.tmp",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("grants.toml"),
            std::process::id()
        );
        let tmp = path.with_file_name(file_name);
        fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("replacing {}", path.display()));
        }
        Ok(())
    }

    /// Find the repo entry for `path`, creating one with a fresh id if absent.
    pub fn find_or_create_repo(&mut self, path: &str) -> Result<&mut RepoGrant> {
        if let Some(idx) = self.repos.iter().position(|r| r.path == path) {
            return Ok(&mut self.repos[idx]);
        }
        self.repos.push(RepoGrant {
            id: RepoId::random()?.to_string(),
            path: path.to_string(),
            lfs_enabled: false,
            members: Vec::new(),
        });
        Ok(self.repos.last_mut().expect("just pushed"))
    }
}

/// Result of [`RepoGrant::grant_member`]. Grant is additive - it never lowers an
/// existing member's access.
#[derive(Debug, PartialEq, Eq)]
pub enum GrantOutcome {
    /// New member, read-only.
    Added,
    /// New member, read-write.
    AddedWrite,
    /// Existing read-only member raised to read-write.
    UpgradedToWrite,
    /// Member already had the requested access; nothing changed.
    Unchanged,
}

/// Result of [`RepoGrant::revoke_member`].
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Removed,
    NotAMember,
}

/// Result of [`RepoGrant::revoke_write`].
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeWriteOutcome {
    Downgraded,
    AlreadyReadOnly,
    NotAMember,
}

/// Result of [`RepoGrant::revoke_lfs`].
#[derive(Debug, PartialEq, Eq)]
pub enum RevokeLfsOutcome {
    Revoked,
    AlreadyNoLfs,
    NotAMember,
}

impl RepoGrant {
    /// Grant access to `node_id`. Additive: a read-only grant on an existing
    /// member leaves write access intact; `write` and `lfs` only ever raise
    /// access, never lower it. A non-empty `nickname` updates the member's label.
    /// The returned [`GrantOutcome`] reflects the read/write transition; the `lfs`
    /// change (if any) is applied as a side effect — callers read the resulting
    /// `allow_lfs` to report it.
    pub fn grant_member(
        &mut self,
        node_id: &str,
        write: bool,
        lfs: bool,
        nickname: &str,
    ) -> GrantOutcome {
        match self.members.iter_mut().find(|m| m.node_id == node_id) {
            Some(m) => {
                if !nickname.is_empty() {
                    m.nickname = nickname.to_string();
                }
                if lfs {
                    m.allow_lfs = true;
                }
                if write && !m.allow_push {
                    m.allow_push = true;
                    GrantOutcome::UpgradedToWrite
                } else {
                    GrantOutcome::Unchanged
                }
            }
            None => {
                self.members.push(Member {
                    node_id: node_id.to_string(),
                    nickname: nickname.to_string(),
                    allow_push: write,
                    allow_lfs: lfs,
                });
                if write {
                    GrantOutcome::AddedWrite
                } else {
                    GrantOutcome::Added
                }
            }
        }
    }

    /// Remove `node_id` from the member list entirely.
    pub fn revoke_member(&mut self, node_id: &str) -> RevokeOutcome {
        let before = self.members.len();
        self.members.retain(|m| m.node_id != node_id);
        if self.members.len() == before {
            RevokeOutcome::NotAMember
        } else {
            RevokeOutcome::Removed
        }
    }

    /// Revoke only write access from `node_id`, keeping read access.
    pub fn revoke_write(&mut self, node_id: &str) -> RevokeWriteOutcome {
        match self.members.iter_mut().find(|m| m.node_id == node_id) {
            None => RevokeWriteOutcome::NotAMember,
            Some(m) if !m.allow_push => RevokeWriteOutcome::AlreadyReadOnly,
            Some(m) => {
                m.allow_push = false;
                RevokeWriteOutcome::Downgraded
            }
        }
    }

    /// Revoke only LFS access from `node_id`, keeping clone/push access.
    pub fn revoke_lfs(&mut self, node_id: &str) -> RevokeLfsOutcome {
        match self.members.iter_mut().find(|m| m.node_id == node_id) {
            None => RevokeLfsOutcome::NotAMember,
            Some(m) if !m.allow_lfs => RevokeLfsOutcome::AlreadyNoLfs,
            Some(m) => {
                m.allow_lfs = false;
                RevokeLfsOutcome::Revoked
            }
        }
    }
}

/// Where the running daemon records its current relay, so the offline `grant`
/// command can embed a relay hint in tickets.
pub fn relay_hint_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("daemon-relay.txt"))
}

/// Record the daemon's current relay (empty string clears it).
pub fn write_relay_hint(relay: Option<&str>) -> Result<()> {
    let path = relay_hint_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, relay.unwrap_or("")).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read the daemon's last-known relay, if any.
pub fn read_relay_hint() -> Option<String> {
    let text = fs::read_to_string(relay_hint_path().ok()?).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}
