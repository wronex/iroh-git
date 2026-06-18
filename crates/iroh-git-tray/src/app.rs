//! Win32 tray implementation (hand-rolled against the `windows` crate).

use core::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};

use anyhow::{Context, Result};
use iroh_git::config::Grants;
use iroh_git::share;
use iroh_git_daemon::Status;
use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    GetLastError, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, HGLOBAL, HINSTANCE, HWND, LPARAM,
    LRESULT, POINT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    CreateFontIndirectW, GetSysColorBrush, COLOR_3DFACE, DEFAULT_CHARSET, HFONT, LOGFONTW,
};
use windows::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Console::{
    AttachConsole, GetStdHandle, ATTACH_PARENT_PROCESS, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ,
};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, IShellItem, Shell_NotifyIconW, ShellExecuteW, FOS_PICKFOLDERS,
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_SETVERSION, NOTIFYICONDATAW,
    NOTIFYICON_VERSION_4, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::*;

const TRAY_UID: u32 = 1;
const WM_TRAYICON: u32 = WM_APP + 1;

// Fixed menu command ids.
const ID_COPY: usize = 101;
const ID_OPEN_CONFIG: usize = 102;
const ID_QUIT: usize = 103;
const ID_TOGGLE_STARTUP: usize = 104;
const ID_GRANT: usize = 105;
// Dynamic (per-repo/per-member) command ids start here.
const ID_DYN_BASE: usize = 2000;

// Grant-dialog control ids.
const ID_OK: i32 = 1;
const ID_CANCEL: i32 = 2;
const ID_EDIT_NODE: i32 = 1001;
const ID_EDIT_REPO: i32 = 1002;
const ID_BTN_BROWSE: i32 = 1003;
const ID_CHK_WRITE: i32 = 1004;
const ID_EDIT_NICK: i32 = 1005;

static STATUS: OnceLock<Arc<Mutex<Status>>> = OnceLock::new();
static MENU_ACTIONS: Mutex<Vec<MenuAction>> = Mutex::new(Vec::new());
static DIALOG_OPEN: AtomicBool = AtomicBool::new(false);

/// Create the dialog font (Segoe UI 9pt) scaled to the given DPI.
unsafe fn dialog_font(dpi: u32) -> HFONT {
    let mut lf: LOGFONTW = std::mem::zeroed();
    lf.lfHeight = -((9 * dpi as i32) / 72); // 9pt at this DPI
    lf.lfWeight = 400; // FW_NORMAL
    lf.lfCharSet = DEFAULT_CHARSET;
    for (i, c) in "Segoe UI".encode_utf16().enumerate() {
        lf.lfFaceName[i] = c;
    }
    CreateFontIndirectW(&lf)
}

#[derive(Clone)]
enum MenuAction {
    OpenInExplorer(String),
    CopyTicket(String),
    AddMember(String),
    RevokeMember { repo: String, node: String, name: String },
    StopSharing(String),
}

fn status() -> &'static Arc<Mutex<Status>> {
    STATUS.get().expect("status initialized before the message loop")
}

/// Append the daemon's error to a log file (there is no console in a tray app).
pub fn log_error(msg: &str) {
    if let Ok(dir) = iroh_git::identity::config_dir() {
        let _ = std::fs::write(dir.join("tray.log"), msg);
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Print the version to stdout. The tray is a no-console GUI app, so if it was
/// launched from a terminal without redirection it has no stdout - attach to the
/// parent console in that case. If stdout is already redirected (a pipe/file),
/// leave it alone so `iroh-git-tray --version > file` still works.
fn print_version() {
    use std::io::Write;
    unsafe {
        let has_stdout = GetStdHandle(STD_OUTPUT_HANDLE)
            .map(|h| !h.is_invalid() && !h.0.is_null())
            .unwrap_or(false);
        if !has_stdout {
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
    println!("iroh-git-tray {}", env!("CARGO_PKG_VERSION"));
    let _ = std::io::stdout().flush();
}

pub fn run() -> Result<()> {
    if std::env::args().skip(1).any(|a| matches!(a.as_str(), "--version" | "-V" | "version")) {
        print_version();
        return Ok(());
    }
    unsafe {
        let _mutex = CreateMutexW(None, true, w!("iroh-git-tray-singleton"))
            .context("creating single-instance mutex")?;
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return Ok(());
        }
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        start_daemon();

        let hmodule = GetModuleHandleW(PCWSTR::null()).context("GetModuleHandleW")?;
        let hinstance = HINSTANCE(hmodule.0);
        let class_name = w!("iroh-git-tray-window");

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: class_name,
            ..Default::default()
        };
        if RegisterClassW(&wc) == 0 {
            return Err(anyhow::anyhow!("RegisterClassW failed: {:?}", GetLastError()));
        }

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("iroh-git"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(hinstance),
            None,
        )
        .context("CreateWindowExW")?;

        add_tray_icon(hwnd)?;

        let mut msg = MSG::default();
        loop {
            let ret = GetMessageW(&mut msg, None, 0, 0).0;
            if ret <= 0 {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        remove_tray_icon(hwnd);
        Ok(())
    }
}

fn start_daemon() {
    let shared = Arc::new(Mutex::new(Status::default()));
    let _ = STATUS.set(shared.clone());
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                log_error(&format!("failed to start tokio runtime: {e}"));
                return;
            }
        };
        if let Err(e) = rt.block_on(iroh_git_daemon::run(shared)) {
            log_error(&format!("daemon stopped: {e:#}"));
        }
    });
}

// ---------------------------------------------------------------------------
// Tray icon
// ---------------------------------------------------------------------------

unsafe fn add_tray_icon(hwnd: HWND) -> Result<()> {
    let icon = LoadIconW(None, IDI_APPLICATION).context("LoadIconW")?;
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = icon;
    for (i, c) in "iroh-git".encode_utf16().enumerate() {
        nid.szTip[i] = c;
    }
    Shell_NotifyIconW(NIM_ADD, &nid)
        .ok()
        .context("Shell_NotifyIconW(NIM_ADD)")?;
    nid.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    let _ = Shell_NotifyIconW(NIM_SETVERSION, &nid);
    Ok(())
}

unsafe fn remove_tray_icon(hwnd: HWND) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_UID;
    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_TRAYICON => {
            let event = (lparam.0 as u32) & 0xFFFF;
            if (event == WM_RBUTTONUP || event == WM_LBUTTONUP || event == WM_CONTEXTMENU)
                && !DIALOG_OPEN.load(Ordering::SeqCst)
            {
                show_menu(hwnd);
            }
            LRESULT(0)
        }
        WM_COMMAND => {
            handle_command(hwnd, wparam.0 & 0xFFFF);
            LRESULT(0)
        }
        WM_DESTROY => {
            remove_tray_icon(hwnd);
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

// ---------------------------------------------------------------------------
// Menu
// ---------------------------------------------------------------------------

unsafe fn show_menu(hwnd: HWND) {
    MENU_ACTIONS.lock().unwrap().clear();
    let Ok(menu) = CreatePopupMenu() else { return };
    let snapshot = status().lock().unwrap().clone();

    let header = if snapshot.online {
        format!(
            "iroh-git - online · {} repo{}",
            snapshot.repos,
            if snapshot.repos == 1 { "" } else { "s" }
        )
    } else {
        "iroh-git - starting…".to_string()
    };
    item(menu, MF_STRING | MF_GRAYED, 0, &header);
    if let Some(id) = &snapshot.node_id {
        item(menu, MF_STRING | MF_GRAYED, 0, &format!("node {}…", &id[..id.len().min(16)]));
    }
    separator(menu);

    // Shared repos submenu (with per-member revoke).
    let grants = Grants::load().unwrap_or_default();
    if let Ok(repos_menu) = CreatePopupMenu() {
        if grants.repos.is_empty() {
            item(repos_menu, MF_STRING | MF_GRAYED, 0, "(nothing shared yet)");
        } else {
            for repo in &grants.repos {
                if let Ok(repo_menu) = CreatePopupMenu() {
                    action(repo_menu, "Open in Explorer", MenuAction::OpenInExplorer(repo.path.clone()));
                    action(repo_menu, "Copy remote URL", MenuAction::CopyTicket(repo.path.clone()));
                    action(repo_menu, "Add member…", MenuAction::AddMember(repo.path.clone()));
                    separator(repo_menu);
                    if repo.members.is_empty() {
                        item(repo_menu, MF_STRING | MF_GRAYED, 0, "(no members)");
                    } else {
                        for m in &repo.members {
                            let who = if m.nickname.is_empty() {
                                format!("{}…", &m.node_id[..m.node_id.len().min(12)])
                            } else {
                                m.nickname.clone()
                            };
                            let access = if m.allow_push { "read-write" } else { "read-only" };
                            action(
                                repo_menu,
                                &format!("Revoke {who}'s access ({access})"),
                                MenuAction::RevokeMember {
                                    repo: repo.path.clone(),
                                    node: m.node_id.clone(),
                                    name: who,
                                },
                            );
                        }
                    }
                    separator(repo_menu);
                    action(repo_menu, "Stop sharing", MenuAction::StopSharing(repo.path.clone()));
                    let name = repo
                        .path
                        .rsplit(['\\', '/'])
                        .find(|s| !s.is_empty())
                        .unwrap_or(repo.path.as_str());
                    submenu(repos_menu, repo_menu, name);
                }
            }
        }
        submenu(menu, repos_menu, "Shared repos");
    }

    item(menu, MF_STRING, ID_GRANT, "Grant access…");
    separator(menu);
    item(menu, MF_STRING, ID_COPY, "Copy my node id");
    let startup = MF_STRING | if startup_enabled() { MF_CHECKED } else { MF_UNCHECKED };
    item(menu, startup, ID_TOGGLE_STARTUP, "Start at login");
    item(menu, MF_STRING, ID_OPEN_CONFIG, "Open config folder");
    separator(menu);
    item(menu, MF_STRING, ID_QUIT, "Quit");

    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);
    let _ = SetForegroundWindow(hwnd);
    let _ = TrackPopupMenu(menu, TPM_RIGHTBUTTON, pt.x, pt.y, None, hwnd, None);
    let _ = DestroyMenu(menu);
}

unsafe fn item(menu: HMENU, flags: MENU_ITEM_FLAGS, id: usize, text: &str) {
    let _ = AppendMenuW(menu, flags, id, PCWSTR(wide(text).as_ptr()));
}

unsafe fn separator(menu: HMENU) {
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
}

unsafe fn submenu(parent: HMENU, child: HMENU, text: &str) {
    let _ = AppendMenuW(parent, MF_POPUP, child.0 as usize, PCWSTR(wide(text).as_ptr()));
}

unsafe fn action(menu: HMENU, text: &str, act: MenuAction) {
    let id = {
        let mut actions = MENU_ACTIONS.lock().unwrap();
        let id = ID_DYN_BASE + actions.len();
        actions.push(act);
        id
    };
    item(menu, MF_STRING, id, text);
}

unsafe fn handle_command(hwnd: HWND, id: usize) {
    match id {
        ID_COPY => copy_my_id(hwnd),
        ID_OPEN_CONFIG => open_config_folder(),
        ID_TOGGLE_STARTUP => set_startup(!startup_enabled()),
        ID_GRANT => {
            if let Some(input) = prompt_grant(hwnd, None) {
                do_grant(hwnd, input);
            }
        }
        ID_QUIT => {
            let _ = DestroyWindow(hwnd);
        }
        _ if id >= ID_DYN_BASE => {
            let act = MENU_ACTIONS.lock().unwrap().get(id - ID_DYN_BASE).cloned();
            if let Some(act) = act {
                run_action(hwnd, act);
            }
        }
        _ => {}
    }
}

unsafe fn run_action(hwnd: HWND, act: MenuAction) {
    match act {
        MenuAction::OpenInExplorer(repo) => open_in_explorer(&repo),
        MenuAction::CopyTicket(repo) => match share::ticket_for(&repo) {
            Ok(Some(ticket)) => {
                let _ = set_clipboard_text(hwnd, &ticket.encode());
                message_box(hwnd, "Remote URL copied to clipboard.", MB_ICONINFORMATION);
            }
            _ => message_box(hwnd, "Could not build the remote URL.", MB_ICONERROR),
        },
        MenuAction::AddMember(repo) => {
            if let Some(input) = prompt_grant(hwnd, Some(&repo)) {
                do_grant(hwnd, input);
            }
        }
        MenuAction::RevokeMember { repo, node, name } => {
            if confirm(hwnd, &format!("Revoke {name}'s access to this repository?")) {
                match share::revoke_at(&repo, &node, false) {
                    Ok(_) => message_box(hwnd, &format!("Revoked {name}'s access."), MB_ICONINFORMATION),
                    Err(e) => message_box(hwnd, &format!("Could not revoke:\n{e:#}"), MB_ICONERROR),
                }
            }
        }
        MenuAction::StopSharing(repo) => {
            let name = repo_basename(&repo);
            let prompt = format!(
                "Stop sharing \"{name}\"?\n\nThis removes the repository and everyone you granted. \
                 Their clones will no longer be able to fetch or push."
            );
            if confirm(hwnd, &prompt) {
                match share::unshare(&repo) {
                    Ok(_) => message_box(hwnd, &format!("Stopped sharing \"{name}\"."), MB_ICONINFORMATION),
                    Err(e) => message_box(hwnd, &format!("Could not stop sharing:\n{e:#}"), MB_ICONERROR),
                }
            }
        }
    }
}

unsafe fn copy_my_id(hwnd: HWND) {
    match status().lock().unwrap().node_id.clone() {
        Some(node) => {
            let _ = set_clipboard_text(hwnd, &node);
            message_box(hwnd, "Your node id is on the clipboard.", MB_ICONINFORMATION);
        }
        None => message_box(hwnd, "Still starting up - try again in a moment.", MB_ICONINFORMATION),
    }
}

unsafe fn do_grant(hwnd: HWND, input: GrantInput) {
    if input.node.trim().is_empty() || input.repo.trim().is_empty() {
        message_box(hwnd, "Please enter a node id and choose a repository.", MB_ICONINFORMATION);
        return;
    }
    match share::grant(Path::new(&input.repo), &input.node, input.write, &input.nickname) {
        Ok(g) => {
            let _ = set_clipboard_text(hwnd, &g.ticket.encode());
            let mode = if input.write { "read-write" } else { "read-only" };
            message_box(
                hwnd,
                &format!(
                    "Granted {mode} access to:\n{}\n\nThe remote URL is on your clipboard - send it to your friend.",
                    g.repo_path
                ),
                MB_ICONINFORMATION,
            );
        }
        Err(e) => message_box(hwnd, &format!("Could not grant access:\n{e:#}"), MB_ICONERROR),
    }
}

unsafe fn open_config_folder() {
    if let Ok(dir) = iroh_git::identity::config_dir() {
        open_in_explorer(&dir.to_string_lossy());
    }
}

/// Open a filesystem path in Explorer.
unsafe fn open_in_explorer(path: &str) {
    let wide = wide(path);
    let _ = ShellExecuteW(
        None,
        w!("open"),
        PCWSTR(wide.as_ptr()),
        PCWSTR::null(),
        PCWSTR::null(),
        SW_SHOWNORMAL,
    );
}

/// The last path component (folder name) of a repository path.
fn repo_basename(path: &str) -> String {
    path.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .find(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string()
}

// ---------------------------------------------------------------------------
// Start at login (HKCU\…\Run)
// ---------------------------------------------------------------------------

unsafe fn open_run_key() -> Option<HKEY> {
    let mut hkey = HKEY(std::ptr::null_mut());
    let rc = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        None,
        PCWSTR::null(),
        REG_OPTION_NON_VOLATILE,
        REG_SAM_FLAGS(KEY_READ.0 | KEY_WRITE.0),
        None,
        &mut hkey,
        None,
    );
    (rc == ERROR_SUCCESS).then_some(hkey)
}

fn startup_enabled() -> bool {
    unsafe {
        let Some(hkey) = open_run_key() else { return false };
        let rc = RegQueryValueExW(hkey, w!("iroh-git-tray"), None, None, None, None);
        let _ = RegCloseKey(hkey);
        rc == ERROR_SUCCESS
    }
}

fn set_startup(enable: bool) {
    unsafe {
        let Some(hkey) = open_run_key() else { return };
        if enable {
            if let Ok(exe) = std::env::current_exe() {
                let value = wide(&format!("\"{}\"", exe.display()));
                let bytes =
                    std::slice::from_raw_parts(value.as_ptr() as *const u8, value.len() * 2);
                let _ = RegSetValueExW(hkey, w!("iroh-git-tray"), None, REG_SZ, Some(bytes));
            }
        } else {
            let _ = RegDeleteValueW(hkey, w!("iroh-git-tray"));
        }
        let _ = RegCloseKey(hkey);
    }
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

unsafe fn set_clipboard_text(hwnd: HWND, text: &str) -> Result<()> {
    OpenClipboard(Some(hwnd)).context("OpenClipboard")?;
    let result = (|| -> Result<()> {
        EmptyClipboard().context("EmptyClipboard")?;
        let data = wide(text);
        let bytes = data.len() * std::mem::size_of::<u16>();
        let hmem: HGLOBAL = GlobalAlloc(GMEM_MOVEABLE, bytes).context("GlobalAlloc")?;
        let dst = GlobalLock(hmem) as *mut u16;
        if dst.is_null() {
            return Err(anyhow::anyhow!("GlobalLock failed"));
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        let _ = GlobalUnlock(hmem);
        SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hmem.0)))
            .context("SetClipboardData")?;
        Ok(())
    })();
    let _ = CloseClipboard();
    result
}

// ---------------------------------------------------------------------------
// Dialogs
// ---------------------------------------------------------------------------

unsafe fn message_box(hwnd: HWND, text: &str, icon: MESSAGEBOX_STYLE) {
    let t = wide(text);
    let c = wide("iroh-git");
    let _ = MessageBoxW(Some(hwnd), PCWSTR(t.as_ptr()), PCWSTR(c.as_ptr()), MB_OK | icon);
}

/// A Yes/No confirmation dialog; returns true if the user chose Yes.
unsafe fn confirm(hwnd: HWND, text: &str) -> bool {
    let t = wide(text);
    let c = wide("iroh-git");
    MessageBoxW(Some(hwnd), PCWSTR(t.as_ptr()), PCWSTR(c.as_ptr()), MB_YESNO | MB_ICONWARNING) == IDYES
}

unsafe fn pick_folder(owner: HWND) -> Option<PathBuf> {
    // The modern Common Item Dialog in folder-pick mode (the normal file-open
    // dialog, not the old tree-view "Browse For Folder").
    let dialog: IFileOpenDialog =
        CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
    let options = dialog.GetOptions().ok()?;
    dialog.SetOptions(options | FOS_PICKFOLDERS).ok()?;
    let _ = dialog.SetTitle(w!("Choose a git repository to share"));

    // Show returns an error (cancelled) if the user backs out.
    dialog.Show(Some(owner)).ok()?;
    let item: IShellItem = dialog.GetResult().ok()?;
    let pwstr = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
    let path = pwstr_to_string(pwstr);
    CoTaskMemFree(Some(pwstr.0 as *const c_void));
    Some(PathBuf::from(path))
}

unsafe fn pwstr_to_string(p: PWSTR) -> String {
    if p.0.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *p.0.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p.0, len))
}

/// The values entered in the grant dialog.
pub struct GrantInput {
    pub node: String,
    pub nickname: String,
    pub repo: String,
    pub write: bool,
}

/// Internal state shared with the dialog window procedure via GWLP_USERDATA.
struct Dlg {
    edit_node: HWND,
    edit_nick: HWND,
    edit_repo: HWND,
    chk_write: HWND,
    done: bool,
    accepted: bool,
}

static DIALOG_CLASS: Once = Once::new();

unsafe fn prompt_grant(owner: HWND, initial_repo: Option<&str>) -> Option<GrantInput> {
    DIALOG_OPEN.store(true, Ordering::SeqCst);
    let result = prompt_grant_inner(owner, initial_repo);
    DIALOG_OPEN.store(false, Ordering::SeqCst);
    result
}

unsafe fn prompt_grant_inner(owner: HWND, initial_repo: Option<&str>) -> Option<GrantInput> {
    let hinstance = HINSTANCE(GetModuleHandleW(PCWSTR::null()).ok()?.0);
    let class = w!("iroh-git-grant-dialog");
    DIALOG_CLASS.call_once(|| {
        let wc = WNDCLASSW {
            lpfnWndProc: Some(dlg_proc),
            hInstance: hinstance,
            lpszClassName: class,
            hbrBackground: GetSysColorBrush(COLOR_3DFACE),
            ..Default::default()
        };
        let _ = RegisterClassW(&wc);
    });

    // Create hidden so we can read the window's DPI before sizing and laying out.
    let style = WINDOW_STYLE(WS_OVERLAPPED.0 | WS_CAPTION.0 | WS_SYSMENU.0);
    let exstyle = WINDOW_EX_STYLE(0);
    let dlg_hwnd = CreateWindowExW(
        exstyle,
        class,
        w!("Grant access"),
        style,
        0,
        0,
        100,
        100,
        Some(owner),
        None,
        Some(hinstance),
        None,
    )
    .ok()?;

    let dpi = GetDpiForWindow(dlg_hwnd).max(96);
    let sc = |v: i32| (v * dpi as i32 + 48) / 96; // scale a 96-dpi value, rounded
    let font = dialog_font(dpi);

    // Size so the client area is the desired (scaled) size, then center it.
    let mut rect = RECT { left: 0, top: 0, right: sc(458), bottom: sc(208) };
    let _ = AdjustWindowRectExForDpi(&mut rect, style, false, exstyle, dpi);
    let (ww, hh) = (rect.right - rect.left, rect.bottom - rect.top);
    let sw = GetSystemMetrics(SM_CXSCREEN);
    let sh = GetSystemMetrics(SM_CYSCREEN);
    let _ = SetWindowPos(dlg_hwnd, None, (sw - ww) / 2, (sh - hh) / 2, ww, hh, SWP_NOZORDER);

    let mut state = Dlg {
        edit_node: HWND(std::ptr::null_mut()),
        edit_nick: HWND(std::ptr::null_mut()),
        edit_repo: HWND(std::ptr::null_mut()),
        chk_write: HWND(std::ptr::null_mut()),
        done: false,
        accepted: false,
    };
    SetWindowLongPtrW(dlg_hwnd, GWLP_USERDATA, &mut state as *mut Dlg as isize);

    let child = WS_CHILD.0 | WS_VISIBLE.0;
    let label = WINDOW_STYLE(child);
    let edit = WINDOW_STYLE(child | WS_TABSTOP.0 | ES_AUTOHSCROLL as u32);
    let sunken = WINDOW_EX_STYLE(WS_EX_CLIENTEDGE.0);
    let flat = WINDOW_EX_STYLE(0);
    let button = |extra: i32| WINDOW_STYLE(child | WS_TABSTOP.0 | extra as u32);

    control(dlg_hwnd, w!("STATIC"), w!("Friend's node id:"), flat, label, sc(12), sc(19), sc(120), sc(16), 0, hinstance, font);
    state.edit_node = control(dlg_hwnd, w!("EDIT"), w!(""), sunken, edit, sc(138), sc(16), sc(308), sc(21), ID_EDIT_NODE, hinstance, font);
    control(dlg_hwnd, w!("STATIC"), w!("Nickname:"), flat, label, sc(12), sc(55), sc(120), sc(16), 0, hinstance, font);
    state.edit_nick = control(dlg_hwnd, w!("EDIT"), w!(""), sunken, edit, sc(138), sc(52), sc(308), sc(21), ID_EDIT_NICK, hinstance, font);
    control(dlg_hwnd, w!("STATIC"), w!("Repository:"), flat, label, sc(12), sc(91), sc(120), sc(16), 0, hinstance, font);
    state.edit_repo = control(dlg_hwnd, w!("EDIT"), w!(""), sunken, edit, sc(138), sc(88), sc(224), sc(21), ID_EDIT_REPO, hinstance, font);
    control(dlg_hwnd, w!("BUTTON"), w!("Browse…"), flat, button(BS_PUSHBUTTON), sc(371), sc(87), sc(75), sc(23), ID_BTN_BROWSE, hinstance, font);
    state.chk_write = control(dlg_hwnd, w!("BUTTON"), w!("Allow push (read-write)"), flat, button(BS_AUTOCHECKBOX), sc(138), sc(122), sc(250), sc(20), ID_CHK_WRITE, hinstance, font);
    control(dlg_hwnd, w!("BUTTON"), w!("Grant"), flat, button(BS_DEFPUSHBUTTON), sc(290), sc(170), sc(75), sc(25), ID_OK, hinstance, font);
    control(dlg_hwnd, w!("BUTTON"), w!("Cancel"), flat, button(BS_PUSHBUTTON), sc(371), sc(170), sc(75), sc(25), ID_CANCEL, hinstance, font);

    if let Some(repo) = initial_repo {
        let _ = SetWindowTextW(state.edit_repo, PCWSTR(wide(repo).as_ptr()));
    }
    let _ = ShowWindow(dlg_hwnd, SW_SHOWNORMAL);
    let _ = SetFocus(Some(state.edit_node));

    // Nested modal loop.
    let _ = EnableWindow(owner, false);
    let mut msg = MSG::default();
    // `state.done` is set from `dlg_proc`, which reaches `state` through the
    // `*mut Dlg` we stashed in GWLP_USERDATA while pumping messages below.
    // Clippy can't see that cross-FFI write, so it thinks the condition is
    // loop-invariant.
    #[allow(clippy::while_immutable_condition)]
    while !state.done {
        let ret = GetMessageW(&mut msg, None, 0, 0).0;
        if ret <= 0 {
            if ret == 0 {
                PostQuitMessage(0);
            }
            break;
        }
        if !IsDialogMessageW(dlg_hwnd, &msg).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    let _ = EnableWindow(owner, true);
    let _ = SetForegroundWindow(owner);

    let out = if state.accepted {
        let write = SendMessageW(state.chk_write, BM_GETCHECK, None, None).0 == 1;
        Some(GrantInput {
            node: window_text(state.edit_node),
            nickname: window_text(state.edit_nick),
            repo: window_text(state.edit_repo),
            write,
        })
    } else {
        None
    };

    SetWindowLongPtrW(dlg_hwnd, GWLP_USERDATA, 0);
    let _ = DestroyWindow(dlg_hwnd);
    out
}

#[allow(clippy::too_many_arguments)]
unsafe fn control(
    parent: HWND,
    class: PCWSTR,
    text: PCWSTR,
    ex: WINDOW_EX_STYLE,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
    hinstance: HINSTANCE,
    font: HFONT,
) -> HWND {
    let hwnd = CreateWindowExW(
        ex,
        class,
        text,
        style,
        x,
        y,
        w,
        h,
        Some(parent),
        Some(HMENU((id as isize) as *mut c_void)),
        Some(hinstance),
        None,
    )
    .unwrap_or(HWND(std::ptr::null_mut()));
    if !hwnd.0.is_null() {
        SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
    }
    hwnd
}

unsafe fn window_text(hwnd: HWND) -> String {
    let mut buf = [0u16; 512];
    let n = GetWindowTextW(hwnd, &mut buf);
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

unsafe extern "system" fn dlg_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Dlg;
    match msg {
        WM_COMMAND if !ptr.is_null() => {
            let dlg = &mut *ptr;
            match (wparam.0 & 0xFFFF) as i32 {
                ID_BTN_BROWSE => {
                    if let Some(path) = pick_folder(hwnd) {
                        let _ = SetWindowTextW(dlg.edit_repo, PCWSTR(wide(&path.to_string_lossy()).as_ptr()));
                    }
                }
                ID_OK => {
                    dlg.accepted = true;
                    dlg.done = true;
                }
                ID_CANCEL => {
                    dlg.accepted = false;
                    dlg.done = true;
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE if !ptr.is_null() => {
            (*ptr).done = true;
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
