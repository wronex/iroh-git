//! `iroh-git-tray` - a Windows system-tray front end that embeds the daemon.
//!
//! The daemon runs on a background thread (its own tokio runtime); the GUI thread
//! owns the Win32 message loop and the NotifyIcon. Quitting the tray stops the
//! process (and with it the embedded daemon). People who want a headless or
//! non-Windows daemon use `iroh-git-daemon run` directly.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;

#[cfg(windows)]
fn main() {
    if let Err(e) = app::run() {
        app::log_error(&format!("fatal: {e:#}"));
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("iroh-git-tray is Windows-only; use `iroh-git-daemon run` on other platforms.");
}
