//! Grant/revoke operations shared by the `git-iroh` CLI and the tray.
//!
//! These edit the grants file and (for grant) mint the `iroh://` ticket. The
//! daemon picks up changes via its file watcher.

use std::path::Path;

use anyhow::{bail, Context, Result};
use iroh::PublicKey;

use crate::config::{
    self, GrantOutcome, Grants, RevokeLfsOutcome, RevokeOutcome, RevokeWriteOutcome,
};
use crate::identity::{self, Role};
use crate::{paths, RepoId, Ticket};

/// Parse and canonicalize a NODE_ID to its hex form, so stored ids compare
/// cleanly regardless of which encoding was pasted.
pub fn canonical_node_id(node_id: &str) -> Result<String> {
    let key: PublicKey = node_id
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid NODE_ID {node_id:?}: {e}"))?;
    Ok(key.to_string())
}

/// Run `git -C <dir> rev-parse <args>` without a console window.
fn git_rev_parse(dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = paths::git_command(dir);
    cmd.arg("rev-parse").args(args);
    cmd.output().context("running git rev-parse")
}

/// Resolve a directory to the normalized path of its git repository. Works for
/// both work trees (uses the top level) and bare repositories (uses the git dir,
/// since a bare repo has no work tree and `--show-toplevel` would fail).
pub fn resolve_repo(dir: &Path) -> Result<String> {
    let is_bare = git_rev_parse(dir, &["--is-bare-repository"])?;
    if !is_bare.status.success() {
        bail!("not a git repository: {}", dir.display());
    }
    let bare = String::from_utf8_lossy(&is_bare.stdout).trim() == "true";

    let out = if bare {
        git_rev_parse(dir, &["--absolute-git-dir"])?
    } else {
        git_rev_parse(dir, &["--show-toplevel"])?
    };
    if !out.status.success() {
        bail!("could not resolve repository path for {}", dir.display());
    }
    let path = String::from_utf8(out.stdout).context("git output was not UTF-8")?;
    let norm = paths::normalize(Path::new(path.trim()))?;
    norm.to_str()
        .map(str::to_string)
        .context("repository path is not valid UTF-8")
}

/// The result of a [`grant`].
pub struct Granted {
    pub outcome: GrantOutcome,
    pub node_id: String,
    pub repo_path: String,
    pub ticket: Ticket,
    /// The member's resulting LFS right after this grant.
    pub allow_lfs: bool,
    /// Whether this grant newly turned on the member's LFS right (vs. it already
    /// being set), so the caller can word the message without contradicting the
    /// read/write outcome.
    pub lfs_added: bool,
    /// Whether the repository currently has LFS serving enabled (so the caller
    /// can warn when `--lfs` was granted but the repo's LFS switch is still off).
    pub lfs_enabled: bool,
}

/// Grant `node_id` access to the repository containing `dir`, minting the repo
/// on first use. Additive: a read-only grant never lowers existing write access.
/// `lfs` additionally grants LFS transfer (download; upload also needs `write`).
/// A non-empty `nickname` labels the member.
pub fn grant(dir: &Path, node_id: &str, write: bool, lfs: bool, nickname: &str) -> Result<Granted> {
    let node = canonical_node_id(node_id)?;
    let repo_path = resolve_repo(dir)?;

    let mut grants = Grants::load()?;
    let repo = grants.find_or_create_repo(&repo_path)?;
    let had_lfs = repo.members.iter().find(|m| m.node_id == node).map(|m| m.allow_lfs).unwrap_or(false);
    let outcome = repo.grant_member(&node, write, lfs, nickname.trim());
    let allow_lfs = repo
        .members
        .iter()
        .find(|m| m.node_id == node)
        .map(|m| m.allow_lfs)
        .unwrap_or(lfs);
    let lfs_enabled = repo.lfs_enabled;
    let repo_id = repo.id.clone();
    grants.save()?;

    let ticket = build_ticket(&repo_id, &repo_path)?;
    Ok(Granted {
        outcome,
        node_id: node,
        repo_path,
        ticket,
        allow_lfs,
        lfs_added: lfs && !had_lfs,
        lfs_enabled,
    })
}

/// What a [`revoke_at`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Revoked {
    RemovedMember,
    DowngradedToReadOnly,
    AlreadyReadOnly,
    LfsRevoked,
    AlreadyNoLfs,
    NotAMember,
    RepoNotShared,
}

/// Which access a revoke should remove.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeWhat {
    /// Remove the member entirely.
    Member,
    /// Downgrade to read-only: keep clone access, drop push.
    Write,
    /// Drop only LFS access: keep clone/push.
    Lfs,
}

/// Revoke access for `node_id` at an already-resolved repository path. `what`
/// selects whether to remove the member, downgrade write, or drop LFS only.
pub fn revoke_at(repo_path: &str, node_id: &str, what: RevokeWhat) -> Result<Revoked> {
    let node = canonical_node_id(node_id)?;
    let mut grants = Grants::load()?;
    let Some(repo) = grants.repos.iter_mut().find(|r| r.path == repo_path) else {
        return Ok(Revoked::RepoNotShared);
    };

    let result = match what {
        RevokeWhat::Write => match repo.revoke_write(&node) {
            RevokeWriteOutcome::Downgraded => Revoked::DowngradedToReadOnly,
            RevokeWriteOutcome::AlreadyReadOnly => Revoked::AlreadyReadOnly,
            RevokeWriteOutcome::NotAMember => Revoked::NotAMember,
        },
        RevokeWhat::Lfs => match repo.revoke_lfs(&node) {
            RevokeLfsOutcome::Revoked => Revoked::LfsRevoked,
            RevokeLfsOutcome::AlreadyNoLfs => Revoked::AlreadyNoLfs,
            RevokeLfsOutcome::NotAMember => Revoked::NotAMember,
        },
        RevokeWhat::Member => match repo.revoke_member(&node) {
            RevokeOutcome::Removed => Revoked::RemovedMember,
            RevokeOutcome::NotAMember => Revoked::NotAMember,
        },
    };

    if !matches!(result, Revoked::NotAMember) {
        grants.save()?;
    }
    Ok(result)
}

/// Revoke `node_id` from every shared repository per `what` (remove / downgrade
/// write / drop LFS). Returns the number of repositories actually changed.
pub fn revoke_everywhere(node_id: &str, what: RevokeWhat) -> Result<usize> {
    let node = canonical_node_id(node_id)?;
    let mut grants = Grants::load()?;
    let mut changed = 0usize;
    for repo in &mut grants.repos {
        let hit = match what {
            RevokeWhat::Write => matches!(repo.revoke_write(&node), RevokeWriteOutcome::Downgraded),
            RevokeWhat::Lfs => matches!(repo.revoke_lfs(&node), RevokeLfsOutcome::Revoked),
            RevokeWhat::Member => matches!(repo.revoke_member(&node), RevokeOutcome::Removed),
        };
        if hit {
            changed += 1;
        }
    }
    if changed > 0 {
        grants.save()?;
    }
    Ok(changed)
}

/// Result of [`set_repo_lfs`].
#[derive(Debug, PartialEq, Eq)]
pub enum LfsToggle {
    Enabled,
    Disabled,
    AlreadyInThatState,
    NotShared,
}

/// Enable or disable Git LFS serving for the repository containing `dir`.
/// Enabling registers the repository if it isn't shared yet (like [`grant`]);
/// disabling one that isn't shared is a no-op.
pub fn set_repo_lfs(dir: &Path, enabled: bool) -> Result<(String, LfsToggle)> {
    let repo_path = resolve_repo(dir)?;
    let mut grants = Grants::load()?;

    // The repository must already be shared (via `grant`); enabling LFS does not
    // mint a phantom member-less share. This keeps enable and disable symmetric.
    let Some(repo) = grants.repos.iter_mut().find(|r| r.path == repo_path) else {
        return Ok((repo_path, LfsToggle::NotShared));
    };
    if repo.lfs_enabled == enabled {
        return Ok((repo_path, LfsToggle::AlreadyInThatState));
    }
    repo.lfs_enabled = enabled;
    grants.save()?;
    Ok((repo_path, if enabled { LfsToggle::Enabled } else { LfsToggle::Disabled }))
}

/// Stop sharing a repository entirely (removes the repo and all its members).
/// Returns whether a repo was actually removed.
pub fn unshare(repo_path: &str) -> Result<bool> {
    let mut grants = Grants::load()?;
    let before = grants.repos.len();
    grants.repos.retain(|r| r.path != repo_path);
    let removed = grants.repos.len() != before;
    if removed {
        grants.save()?;
    }
    Ok(removed)
}

/// Stop sharing the repository with the given share (repo) id, from anywhere.
/// Returns whether a repo was actually removed.
pub fn unshare_by_id(repo_id: RepoId) -> Result<bool> {
    let mut grants = Grants::load()?;
    let before = grants.repos.len();
    grants.repos.retain(|r| RepoId::parse(&r.id).ok() != Some(repo_id));
    let removed = grants.repos.len() != before;
    if removed {
        grants.save()?;
    }
    Ok(removed)
}

/// Stop sharing every repository (clears the grants file). Returns how many
/// repositories were removed.
pub fn unshare_all() -> Result<usize> {
    let mut grants = Grants::load()?;
    let n = grants.repos.len();
    if n > 0 {
        grants.repos.clear();
        grants.save()?;
    }
    Ok(n)
}

/// Build the shareable ticket for an already-shared repository path.
pub fn ticket_for(repo_path: &str) -> Result<Option<Ticket>> {
    let grants = Grants::load()?;
    let Some(repo) = grants.repos.iter().find(|r| r.path == repo_path) else {
        return Ok(None);
    };
    Ok(Some(build_ticket(&repo.id, &repo.path)?))
}

fn build_ticket(repo_id: &str, repo_path: &str) -> Result<Ticket> {
    let server = identity::load_or_create(Role::Server)?;
    Ok(Ticket {
        node_id: server.public(),
        relay_url: config::read_relay_hint(),
        repo_id: RepoId::parse(repo_id)?,
        name: repo_name(repo_path),
    })
}

/// The repository's directory name, sanitized for use as a URL path segment.
/// A trailing `.git` (the bare-repo convention) is stripped so `foo.git` clones
/// into `foo`, not `foo.git`.
fn repo_name(repo_path: &str) -> String {
    let base = repo_path
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("repo");
    let base = base.strip_suffix(".git").unwrap_or(base);
    let sanitized: String = base
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') { c } else { '-' })
        .collect();
    if sanitized.is_empty() {
        "repo".to_string()
    } else {
        sanitized
    }
}
