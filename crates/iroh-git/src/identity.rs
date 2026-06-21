//! Persistent iroh identities.
//!
//! A machine keeps two stable keys so that its server role and client role can
//! be online at the same time without two endpoints claiming one NODE_ID:
//!
//! - [`Role::Server`] (`server.key`) - used by `iroh-git-daemon`; its NODE_ID is
//!   embedded in the tickets you hand out.
//! - [`Role::Client`] (`client.key`) - used by `git-remote-iroh` when dialing, and
//!   printed by `git iroh show-id`. This is the NODE_ID a repo owner grants.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use iroh::SecretKey;
use zeroize::Zeroize;

/// Which persistent identity to load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The daemon's serving identity; appears in tickets.
    Server,
    /// The dialing identity; what `show-id` prints and an owner grants.
    Client,
}

impl Role {
    fn filename(self) -> &'static str {
        match self {
            Role::Server => "server.key",
            Role::Client => "client.key",
        }
    }
}

/// Directory holding identity keys and configuration.
pub fn config_dir() -> Result<PathBuf> {
    let dirs = directories::ProjectDirs::from("", "", "iroh-git")
        .context("could not determine a configuration directory for this platform")?;
    Ok(dirs.config_dir().to_path_buf())
}

/// Load the persistent key for `role`, generating and storing one on first use.
pub fn load_or_create(role: Role) -> Result<SecretKey> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating config directory {}", dir.display()))?;
    restrict_dir(&dir);
    let path = dir.join(role.filename());

    if path.exists() {
        let mut bytes = fs::read(&path).with_context(|| format!("reading key {}", path.display()))?;
        // Defensively tighten perms in case an older build wrote the key world-readable.
        restrict_file(&path);
        let mut seed: [u8; 32] = match bytes.as_slice().try_into() {
            Ok(seed) => seed,
            Err(_) => {
                // Wipe the key material even on the error path before bailing.
                bytes.zeroize();
                bail!("key {} is not 32 bytes", path.display());
            }
        };
        let secret = SecretKey::from_bytes(&seed);
        // Wipe the transient copies; the live key lives on inside `secret`.
        seed.zeroize();
        bytes.zeroize();
        Ok(secret)
    } else {
        mint(&path)
    }
}

/// Whether the key file for `role` already exists.
pub fn exists(role: Role) -> Result<bool> {
    Ok(config_dir()?.join(role.filename()).exists())
}

/// Generate a fresh key for `role`, overwriting any existing one.
pub fn generate(role: Role) -> Result<SecretKey> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("creating config directory {}", dir.display()))?;
    restrict_dir(&dir);
    let path = dir.join(role.filename());
    mint(&path)
}

/// Generate a fresh secret key, write it to `path`, and wipe the transient
/// copies (the live key lives on inside the returned `SecretKey`). The caller is
/// responsible for having created and restricted the parent directory.
fn mint(path: &Path) -> Result<SecretKey> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("gathering randomness for a new key: {e}"))?;
    let secret = SecretKey::from_bytes(&seed);
    seed.zeroize();
    let mut out = secret.to_bytes();
    let result = write_secret(path, &out);
    out.zeroize();
    result?;
    Ok(secret)
}

/// Write a secret key file, restricting it to the current user: `0600` on Unix,
/// an owner-only DACL on Windows (see [`restrict_file`]).
fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating key {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("writing key {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes).with_context(|| format!("writing key {}", path.display()))?;
        // The file inherited the directory's ACL on creation; tighten it now.
        restrict_file(path);
    }
    Ok(())
}

/// Best-effort: restrict a secret key file to the current user. `0600` on Unix;
/// on Windows, replace the inherited DACL with one that grants only the current
/// user. `%APPDATA%` is user-private by default, but we don't want to rely on
/// that alone for the long-term private keys.
fn restrict_file(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(windows)]
    {
        if let Err(e) = restrict_file_acl(path) {
            // Don't fail key creation over an ACL hiccup; the file is already in
            // a user-private directory. Surface it so it isn't wholly silent.
            eprintln!(
                "warning: could not restrict permissions on {}: {e:#}",
                path.display()
            );
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = path;
}

/// Replace `path`'s DACL with a protected one granting only the current user
/// full control (dropping inherited ACEs). The Windows analogue of `chmod 0600`.
#[cfg(windows)]
fn restrict_file_acl(path: &Path) -> Result<()> {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE,
        SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // FILE_ALL_ACCESS, written out so we needn't pull in the FileSystem feature.
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

    unsafe {
        // 1. Look up the current user's SID via the process token.
        let mut token = HANDLE(std::ptr::null_mut());
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).context("OpenProcessToken")?;

        let mut len = 0u32;
        // The first call "fails" only to report the required length; expected.
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let info = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        info.context("GetTokenInformation(TokenUser)")?;
        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let sid: PSID = token_user.User.Sid;

        // 2. One explicit-access entry: that SID, full control, non-inheritable.
        let ea = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: PWSTR(sid.0 as *mut u16),
            },
        };

        // 3. Build a fresh ACL containing just that entry.
        let mut acl: *mut ACL = std::ptr::null_mut();
        let rc = SetEntriesInAclW(Some(std::slice::from_ref(&ea)), None, &mut acl);
        if rc != ERROR_SUCCESS {
            return Err(anyhow::anyhow!("SetEntriesInAclW failed: {rc:?}"));
        }

        // 4. Install it as a *protected* DACL so inherited ACEs are dropped.
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let rc = SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl as *const ACL),
            None,
        );
        if !acl.is_null() {
            let _ = LocalFree(Some(HLOCAL(acl as *mut c_void)));
        }
        if rc != ERROR_SUCCESS {
            return Err(anyhow::anyhow!("SetNamedSecurityInfoW failed: {rc:?}"));
        }
    }
    Ok(())
}

/// Best-effort: restrict the config directory to `0700` on Unix.
fn restrict_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = dir;
}
