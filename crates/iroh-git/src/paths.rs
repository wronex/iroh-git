//! Path helpers, mostly to keep Windows paths in a form git accepts.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Resolve the `git` executable to an absolute path.
///
/// On Windows, `Command::new("git")` lets `CreateProcess` search the *current
/// directory* before `PATH`, so a `git.exe` planted in a directory we happen to
/// be running from (e.g. an untrusted clone) would hijack every git invocation.
/// We instead walk `PATH` ourselves, considering only absolute entries, and hand
/// back the first `git.exe` we find. If none is found we fall back to the bare
/// name (preserving old behavior) rather than failing outright.
///
/// On Unix the loader does not search the current directory unless `.` is on
/// `PATH` (a deliberate, non-default choice), so the bare name is already safe.
pub fn git_program() -> OsString {
    #[cfg(windows)]
    {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                // Skip empty/relative entries: on Windows an empty `PATH` entry
                // resolves against the current directory, exactly what we avoid.
                if !dir.is_absolute() {
                    continue;
                }
                let candidate = dir.join("git.exe");
                if candidate.is_file() {
                    return candidate.into_os_string();
                }
            }
        }
    }
    OsString::from("git")
}

/// Canonicalize `path` and strip the Windows `\\?\` verbatim prefix that git
/// refuses to recognize.
pub fn normalize(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolving path {}", path.display()))?;
    Ok(strip_verbatim(canonical))
}

/// Strip the Windows `\\?\` verbatim prefix from a path. Leaves UNC
/// (`\\?\UNC\…`) and non-Windows paths untouched.
pub fn strip_verbatim(p: PathBuf) -> PathBuf {
    match p.to_str() {
        Some(s) => match s.strip_prefix(r"\\?\") {
            Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
            _ => p,
        },
        None => p,
    }
}
