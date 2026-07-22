//! Detecting - and defusing - the `git-lfs` pre-push hook on iroh remotes.
//!
//! `git lfs install` leaves a `pre-push` hook that runs `git lfs pre-push` for
//! *every* remote, and git-lfs cannot parse an `iroh://` URL: it reads the
//! unknown scheme as an SSH-style one, takes `iroh` for a hostname, and runs
//! `ssh iroh git-lfs-transfer ...`, which fails - then retries. Measured here on
//! a repository tracking **zero** LFS files, the hook took 19.9 s.
//!
//! What saves us is that `git iroh lfs-setup` writes
//! `lfs.standalonetransferagent`, and a standalone agent makes git-lfs skip
//! endpoint resolution entirely - so the doomed `ssh iroh` never happens and the
//! same hook costs 3.1 s, matching a non-iroh remote. That splits the two cases
//! cleanly, and the guard keys on it: a repository that has run `lfs-setup` still
//! runs git-lfs on push (so LFS objects still upload), and one that has not skips
//! it, because there git-lfs has no way to transfer over the remote anyway.
//!
//! [`warn_if_unguarded`] points the problem out from the clone-side commands;
//! [`guard`] applies the fix.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Marks a hook this tool has already guarded, so guarding twice is a no-op and
/// a reader can see who added the line and why.
const GUARD_MARKER: &str = "git-iroh: skip git-lfs on iroh:// remotes it cannot transfer over";

/// The guard itself. `$2` is the remote URL git passes to `pre-push`; exiting 0
/// tells git the hook approved the push.
fn guard_block() -> String {
    format!(
        "# {GUARD_MARKER}\n\
         # git-lfs reads the iroh:// scheme as an SSH hostname and retries a doomed\n\
         # `ssh iroh` several times, adding ~20 s to every push - even in a repository\n\
         # that tracks no LFS files. Once `git iroh lfs-setup` has run, git-lfs uses the\n\
         # iroh transfer agent instead and works normally, so only an unconfigured\n\
         # repository skips it. Every other remote falls through untouched.\n\
         case \"$2\" in iroh://*)\n\
         \tgit config --get lfs.standalonetransferagent >/dev/null 2>&1 || exit 0 ;;\n\
         esac\n"
    )
}

/// What a `pre-push` hook is, as far as this concerns us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookKind {
    /// Runs `git lfs pre-push`, and nothing has guarded it yet.
    UnguardedGitLfs,
    /// Runs `git lfs pre-push` but already skips the iroh remotes it can't serve.
    GuardedGitLfs,
    /// Some other hook. Never touched.
    Other,
}

/// Classify a hook from its contents. Pure, so the interesting cases are
/// testable without a git repository.
pub fn classify(contents: &str) -> HookKind {
    // Match the invocation rather than the word "lfs": a hook merely mentioning
    // LFS in a comment is not one we should rewrite.
    let runs_git_lfs = contents.contains("lfs pre-push") || contents.contains("lfs-pre-push");
    if !runs_git_lfs {
        return HookKind::Other;
    }
    if contents.contains(GUARD_MARKER) {
        HookKind::GuardedGitLfs
    } else {
        HookKind::UnguardedGitLfs
    }
}

/// This repository's hooks directory (`git rev-parse --git-path hooks`, resolved
/// to an absolute path), which honors worktrees and `core.hooksPath`.
fn hooks_dir(repo: &Path) -> Result<PathBuf> {
    let out = iroh_git::paths::git_command(repo)
        .args(["rev-parse", "--git-path", "hooks"])
        .output()
        .context("running git rev-parse --git-path hooks")?;
    if !out.status.success() {
        anyhow::bail!("git rev-parse --git-path hooks failed");
    }
    let rel = String::from_utf8(out.stdout).context("git output was not UTF-8")?.trim().to_string();
    let path = PathBuf::from(&rel);
    Ok(if path.is_absolute() { path } else { repo.join(path) })
}

/// The repository's `pre-push` hook path, if the file exists.
fn pre_push_path(repo: &Path) -> Result<Option<PathBuf>> {
    let hook = hooks_dir(repo)?.join("pre-push");
    Ok(hook.is_file().then_some(hook))
}

/// The repository's unguarded git-lfs `pre-push` hook, if it has one.
///
/// Errors are swallowed into `None`: this drives an advisory warning on paths
/// that must not fail because a hook could not be read.
pub fn find_unguarded(repo: &Path) -> Option<PathBuf> {
    let hook = pre_push_path(repo).ok()??;
    let contents = std::fs::read_to_string(&hook).ok()?;
    (classify(&contents) == HookKind::UnguardedGitLfs).then_some(hook)
}

/// Warn - to stderr, so it never pollutes a ticket printed on stdout - that this
/// repository's git-lfs hook will stall pushes to an iroh remote. Best-effort,
/// and silent when there is nothing to say.
pub fn warn_if_unguarded(repo: &Path) {
    let Some(hook) = find_unguarded(repo) else {
        return;
    };
    eprintln!();
    eprintln!("warning: this repository has a git-lfs pre-push hook ({}).", hook.display());
    eprintln!("  git-lfs can't parse iroh:// URLs - it reads the scheme as an SSH host and retries");
    eprintln!("  a doomed `ssh iroh` several times, adding ~20 s to every push to an iroh remote.");
    eprintln!("  Run `git iroh guard-lfs-hook` to skip git-lfs where it can't transfer anyway.");
}

/// What [`guard`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The guard was inserted.
    Added,
    /// The hook already had it.
    AlreadyGuarded,
    /// No `pre-push` hook, or one that does not run git-lfs.
    NothingToDo,
}

/// Insert the guard into `repo`'s git-lfs `pre-push` hook.
pub fn guard(repo: &Path) -> Result<(Outcome, Option<PathBuf>)> {
    let Some(hook) = pre_push_path(repo)? else {
        return Ok((Outcome::NothingToDo, None));
    };
    let contents =
        std::fs::read_to_string(&hook).with_context(|| format!("reading {}", hook.display()))?;
    match classify(&contents) {
        HookKind::Other => Ok((Outcome::NothingToDo, Some(hook))),
        HookKind::GuardedGitLfs => Ok((Outcome::AlreadyGuarded, Some(hook))),
        HookKind::UnguardedGitLfs => {
            write_guarded(&hook, &contents)?;
            Ok((Outcome::Added, Some(hook)))
        }
    }
}

/// The hook's contents with the guard inserted directly after its shebang (so it
/// runs before git-lfs), preserving everything else verbatim.
fn insert_guard(contents: &str) -> String {
    let mut out = String::with_capacity(contents.len() + 512);
    let mut rest = contents;
    if contents.starts_with("#!") {
        let line_end = contents.find('\n').map_or(contents.len(), |i| i + 1);
        out.push_str(&contents[..line_end]);
        rest = &contents[line_end..];
    }
    out.push_str(&guard_block());
    out.push_str(rest);
    out
}

/// Rewrite `hook` with the guard inserted.
///
/// Staged beside the hook and renamed into place, so an interrupted write can
/// never leave a half-written - and therefore broken - pre-push hook, which would
/// block every push in the repository.
fn write_guarded(hook: &Path, contents: &str) -> Result<()> {
    let out = insert_guard(contents);
    let tmp = hook.with_extension("iroh-guard.tmp");
    std::fs::write(&tmp, out.as_bytes()).with_context(|| format!("writing {}", tmp.display()))?;
    copy_mode(hook, &tmp)?;
    std::fs::rename(&tmp, hook).with_context(|| {
        let _ = std::fs::remove_file(&tmp);
        format!("replacing {}", hook.display())
    })?;
    Ok(())
}

/// Give the staged file the original hook's permissions, so the rename doesn't
/// hand git a hook it can't execute. The executable bit doesn't exist off Unix.
#[cfg(unix)]
fn copy_mode(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(from)
        .with_context(|| format!("reading {}", from.display()))?
        .permissions()
        .mode();
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode on {}", to.display()))
}

#[cfg(not(unix))]
fn copy_mode(_from: &Path, _to: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `git lfs install` actually writes, as captured from git-lfs 3.7.1.
    const GIT_LFS_HOOK: &str = "#!/bin/sh\n\
        command -v git-lfs >/dev/null 2>&1 || { printf >&2 \"missing git-lfs\"; exit 2; }\n\
        git lfs pre-push \"$@\"\n";

    #[test]
    fn classifies_the_hooks_that_matter() {
        assert_eq!(classify(GIT_LFS_HOOK), HookKind::UnguardedGitLfs);
        assert_eq!(classify("#!/bin/sh\necho hello\n"), HookKind::Other);
        // Merely naming LFS is not running it.
        assert_eq!(classify("#!/bin/sh\n# nothing to do with git lfs here\n"), HookKind::Other);
    }

    #[test]
    fn guarding_is_idempotent_and_keeps_the_original_hook() {
        let guarded = insert_guard(GIT_LFS_HOOK);

        // The shebang still leads, and every original line survives.
        assert!(guarded.starts_with("#!/bin/sh\n"));
        assert!(guarded.contains("git lfs pre-push \"$@\""));
        assert!(guarded.contains("command -v git-lfs"));

        // The guard runs before git-lfs, or it buys nothing.
        let guard_at = guarded.find("case \"$2\"").unwrap();
        let lfs_at = guarded.find("git lfs pre-push").unwrap();
        assert!(guard_at < lfs_at, "the guard must run before git-lfs");

        // Now classified as guarded, so a second pass is a no-op.
        assert_eq!(classify(&guarded), HookKind::GuardedGitLfs);
    }

    #[test]
    fn the_guard_only_skips_a_repository_with_no_transfer_agent() {
        let guarded = insert_guard(GIT_LFS_HOOK);
        // Pinning the shape of the shell, since the whole design rests on it:
        // iroh remotes are matched, and skipped only when the `git config` probe
        // for a standalone agent fails.
        assert!(guarded.contains("case \"$2\" in iroh://*)"));
        assert!(guarded
            .contains("git config --get lfs.standalonetransferagent >/dev/null 2>&1 || exit 0 ;;"));
    }

    #[test]
    fn a_hook_without_a_shebang_still_gets_the_guard_first() {
        let original = "git lfs pre-push \"$@\"\n";
        let guarded = insert_guard(original);
        assert!(guarded.starts_with(&format!("# {GUARD_MARKER}")));
        assert!(guarded.trim_end().ends_with("git lfs pre-push \"$@\""));
    }
}
