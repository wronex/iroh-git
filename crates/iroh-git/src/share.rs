//! Grant/revoke operations shared by the `git-iroh` CLI and the tray.
//!
//! These edit the grants file and (for grant) mint the `iroh://` ticket. The
//! daemon picks up changes via its file watcher.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use iroh::PublicKey;

use crate::config::{self, GrantOutcome, Grants, RevokeOutcome, RevokeWriteOutcome};
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

/// Stop a spawned command from popping a console window on Windows (e.g. when a
/// GUI app like the tray spawns git). No-op on other platforms.
fn no_console(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Run `git -C <dir> rev-parse <args>` without a console window.
fn git_rev_parse(dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new(paths::git_program());
    cmd.arg("-C").arg(dir).arg("rev-parse").args(args);
    no_console(&mut cmd);
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
}

/// Grant `node_id` access to the repository containing `dir`, minting the repo
/// on first use. Additive: a read-only grant never lowers existing write access.
/// A non-empty `nickname` labels the member.
pub fn grant(dir: &Path, node_id: &str, write: bool, nickname: &str) -> Result<Granted> {
    let node = canonical_node_id(node_id)?;
    let repo_path = resolve_repo(dir)?;

    let mut grants = Grants::load()?;
    let repo = grants.find_or_create_repo(&repo_path)?;
    let outcome = repo.grant_member(&node, write, nickname.trim());
    let repo_id = repo.id.clone();
    grants.save()?;

    let ticket = build_ticket(&repo_id, &repo_path)?;
    Ok(Granted {
        outcome,
        node_id: node,
        repo_path,
        ticket,
    })
}

/// What a [`revoke_at`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Revoked {
    RemovedMember,
    DowngradedToReadOnly,
    AlreadyReadOnly,
    NotAMember,
    RepoNotShared,
}

/// Revoke access for `node_id` at an already-resolved repository path. With
/// `write_only`, downgrade to read-only instead of removing the member.
pub fn revoke_at(repo_path: &str, node_id: &str, write_only: bool) -> Result<Revoked> {
    let node = canonical_node_id(node_id)?;
    let mut grants = Grants::load()?;
    let Some(repo) = grants.repos.iter_mut().find(|r| r.path == repo_path) else {
        return Ok(Revoked::RepoNotShared);
    };

    let result = if write_only {
        match repo.revoke_write(&node) {
            RevokeWriteOutcome::Downgraded => Revoked::DowngradedToReadOnly,
            RevokeWriteOutcome::AlreadyReadOnly => Revoked::AlreadyReadOnly,
            RevokeWriteOutcome::NotAMember => Revoked::NotAMember,
        }
    } else {
        match repo.revoke_member(&node) {
            RevokeOutcome::Removed => Revoked::RemovedMember,
            RevokeOutcome::NotAMember => Revoked::NotAMember,
        }
    };

    if !matches!(result, Revoked::NotAMember) {
        grants.save()?;
    }
    Ok(result)
}

/// Revoke `node_id` from every shared repository. With `write_only`, downgrade
/// each membership to read-only instead of removing it. Returns the number of
/// repositories actually changed.
pub fn revoke_everywhere(node_id: &str, write_only: bool) -> Result<usize> {
    let node = canonical_node_id(node_id)?;
    let mut grants = Grants::load()?;
    let mut changed = 0usize;
    for repo in &mut grants.repos {
        let hit = if write_only {
            matches!(repo.revoke_write(&node), RevokeWriteOutcome::Downgraded)
        } else {
            matches!(repo.revoke_member(&node), RevokeOutcome::Removed)
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
