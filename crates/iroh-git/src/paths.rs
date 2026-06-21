//! Path helpers, mostly to keep Windows paths in a form git accepts.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Creation flag that suppresses a new console window on Windows.
#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Suppress the console window a child process would otherwise pop on Windows
/// (e.g. when a GUI app like the tray spawns git). No-op on other platforms.
pub fn no_console(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Build `git -C <repo> …` with stdin closed and no console window — the form
/// every helper in the workspace uses to shell out to git. Closing stdin keeps a
/// spawned git from blocking on an inherited handle.
pub fn git_command(repo: &Path) -> Command {
    let mut cmd = Command::new(git_program());
    cmd.arg("-C").arg(repo).stdin(Stdio::null());
    no_console(&mut cmd);
    cmd
}

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
