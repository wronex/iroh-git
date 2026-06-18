//! Embed a Windows application manifest so the tray gets modern (Common Controls
//! v6) visual styles and per-monitor-v2 DPI awareness.

use embed_manifest::manifest::DpiAwareness;
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest(new_manifest("IrohGit.Tray").dpi_awareness(DpiAwareness::PerMonitorV2))
            .expect("unable to embed application manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
