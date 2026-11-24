// Prevents an extra console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The StalkNet window: a Tauri shell over `stalknet_core::runtime::Node`.

use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use stalknet_core::runtime::{Node, NodeConfig, NodeStatus};
use tauri::State;

struct AppState {
    node: Arc<Node>,
    logs: Arc<Mutex<Vec<String>>>,
}

// ---- DTOs (the runtime types are not themselves serde) ---------------------

#[derive(Serialize)]
struct StatusDto {
    running: bool,
    relay: bool,
    host: String,
    port: u16,
    folder_address: String,
    nickname: String,
    relay_count: usize,
    kept_records: usize,
    own_circuits: usize,
    hidden_address: Option<String>,
    way_out_port: Option<u16>,
    seeding: bool,
    anonymous_exit: bool,
}

impl From<NodeStatus> for StatusDto {
    fn from(s: NodeStatus) -> Self {
        StatusDto {
            running: s.running,
            relay: s.relay,
            host: s.host,
            port: s.port,
            folder_address: s.folder_address,
            nickname: s.nickname,
            relay_count: s.relay_count,
            kept_records: s.kept_records,
            own_circuits: s.own_circuits,
            hidden_address: s.hidden_address,
            way_out_port: s.way_out_port,
            seeding: s.seeding,
            anonymous_exit: s.anonymous_exit,
        }
    }
}

#[derive(Serialize)]
struct RelayDto {
    nickname: String,
    address: String,
    fingerprint: String,
    allows_exit: bool,
    trusted: bool,
    is_self: bool,
}

#[derive(Serialize)]
struct SharedDto {
    alias: String,
    public: bool,
}

#[derive(Serialize)]
struct RemoteFolderDto {
    alias: String,
    public: bool,
}

#[derive(Serialize)]
struct RemoteFileDto {
    name: String,
    size: i64,
}

#[derive(Serialize)]
struct BundleDto {
    name: String,
    kind: String,
    size: String,
    progress: String,
    link: String,
}

// ---- Commands --------------------------------------------------------------

#[tauri::command(async)]
fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[tauri::command(async)]
fn default_identity_path() -> String {
    identity_dir().join("node.id").to_string_lossy().into_owned()
}

#[tauri::command(async)]
fn identity_exists(path: String) -> bool {
    std::path::Path::new(&path).exists()
}

/// Opens the identity at `path`, or makes a fresh one with no passphrase if
/// there is none in this app's format. The window calls this on start.
#[tauri::command(async)]
fn auto_identity(s: State<'_, AppState>, path: String) -> Result<(), String> {
    ensure_parent(&path);
    s.node.open_or_create(&path)?;
    // Pre-compute the relay pass in the background so joining later is quick.
    let node = s.node.clone();
    std::thread::spawn(move || node.warm_pass());
    Ok(())
}

#[tauri::command(async)]
fn create_identity(s: State<'_, AppState>, path: String, passphrase: String, nickname: String) -> Result<(), String> {
    ensure_parent(&path);
    s.node.create_identity(&path, &passphrase, &nickname)
}

#[tauri::command(async)]
fn open_identity(s: State<'_, AppState>, path: String, passphrase: String) -> Result<(), String> {
    s.node.open_identity(&path, &passphrase)
}

#[tauri::command(async)]
fn set_config(s: State<'_, AppState>, network: String, public_host: String, auto_map_port: bool) {
    s.node.set_config(NodeConfig { network, public_host, auto_map_port, force_relay: false });
}

#[tauri::command(async)]
fn start_node(s: State<'_, AppState>, port: u16, allow_exit: bool, relay: bool) {
    // The whole start + join runs on a background thread: counting the relay
    // pass and building circuits can take a while, and the window must stay
    // responsive. Progress shows in the log.
    let node = s.node.clone();
    let logs = s.logs.clone();
    std::thread::spawn(move || {
        if let Err(e) = node.start(port, allow_exit, relay) {
            logs.lock().unwrap().push(format!("could not start: {e}"));
            return;
        }
        node.reconnect(true);
    });
}

#[tauri::command(async)]
fn reconnect(s: State<'_, AppState>, via_torrent: bool) {
    let node = s.node.clone();
    std::thread::spawn(move || {
        node.reconnect(via_torrent);
    });
}

#[tauri::command(async)]
fn stop_node(s: State<'_, AppState>) {
    s.node.stop();
}

#[tauri::command(async)]
fn status(s: State<'_, AppState>) -> StatusDto {
    s.node.status().into()
}

#[tauri::command(async)]
fn take_logs(s: State<'_, AppState>) -> Vec<String> {
    std::mem::take(&mut *s.logs.lock().unwrap())
}

#[tauri::command(async)]
fn relays(s: State<'_, AppState>) -> Vec<RelayDto> {
    s.node
        .relays()
        .into_iter()
        .map(|r| RelayDto {
            nickname: r.nickname,
            address: r.address,
            fingerprint: r.fingerprint,
            allows_exit: r.allows_exit,
            trusted: r.trusted,
            is_self: r.is_self,
        })
        .collect()
}

#[tauri::command(async)]
fn set_trusted_exits(s: State<'_, AppState>, fingerprints: Vec<String>) {
    s.node.set_trusted_exits(&fingerprints);
}

#[tauri::command(async)]
fn trusted_exits(s: State<'_, AppState>) -> Vec<String> {
    s.node.trusted_exits_hex()
}

// --- Hidden service / way out ---

#[tauri::command(async)]
fn start_hidden(s: State<'_, AppState>, intro_points: usize) -> Result<String, String> {
    s.node.start_hidden_service(intro_points)
}

#[tauri::command(async)]
fn stop_hidden(s: State<'_, AppState>) {
    s.node.stop_hidden_service();
}

#[tauri::command(async)]
fn open_tunnel(s: State<'_, AppState>, local_port: u16) -> Result<u16, String> {
    s.node.open_tunnel(local_port)
}

#[tauri::command(async)]
fn close_tunnel(s: State<'_, AppState>) {
    s.node.close_way_out();
}

// --- My shared folders / exposed ports ---

#[tauri::command(async)]
fn add_shared_folder(s: State<'_, AppState>, path: String, alias: String, public: bool) -> Result<(), String> {
    s.node.add_shared_folder(&path, &alias, public)
}

#[tauri::command(async)]
fn remove_shared_folder(s: State<'_, AppState>, alias: String) {
    s.node.remove_shared_folder(&alias);
}

#[tauri::command(async)]
fn shared_folders(s: State<'_, AppState>) -> Vec<SharedDto> {
    s.node.shared_folders().into_iter().map(|f| SharedDto { alias: f.alias, public: f.public }).collect()
}

#[tauri::command(async)]
fn expose_port(s: State<'_, AppState>, internal: u16, local_host: String, local_port: u16) -> Result<(), String> {
    s.node.expose_port(internal, &local_host, local_port)
}

#[tauri::command(async)]
fn hide_port(s: State<'_, AppState>, internal: u16) {
    s.node.hide_port(internal);
}

#[tauri::command(async)]
fn exposed_ports(s: State<'_, AppState>) -> Vec<u16> {
    s.node.exposed_ports()
}

// --- Visiting someone else's folders ---

#[tauri::command(async)]
fn open_hidden_folders(s: State<'_, AppState>, address: String) -> Result<Vec<RemoteFolderDto>, String> {
    Ok(s.node.open_hidden(&address)?.into_iter().map(|f| RemoteFolderDto { alias: f.alias, public: f.public }).collect())
}

#[tauri::command(async)]
fn remote_login(s: State<'_, AppState>, user: String, password: String) -> Result<(), String> {
    s.node.remote_login(&user, &password)
}

#[tauri::command(async)]
fn remote_files(s: State<'_, AppState>, alias: String) -> Result<Vec<RemoteFileDto>, String> {
    Ok(s.node.remote_files(&alias)?.into_iter().map(|f| RemoteFileDto { name: f.name, size: f.size }).collect())
}

#[tauri::command(async)]
fn remote_download(s: State<'_, AppState>, alias: String, file_name: String, save_path: String) -> Result<(), String> {
    s.node.remote_download(&alias, &file_name, &save_path)
}

#[tauri::command(async)]
fn close_remote(s: State<'_, AppState>) {
    s.node.close_remote();
}

// --- Local forwards ---

#[tauri::command(async)]
fn forward_hidden(s: State<'_, AppState>, address: String, remote_port: u16, local_port: u16) -> Result<u16, String> {
    s.node.forward_hidden(&address, remote_port, local_port)
}

// --- Torrents ---

#[tauri::command(async)]
fn share(s: State<'_, AppState>, path: String) -> Result<String, String> {
    s.node.share(&path)
}

#[tauri::command(async)]
fn download(s: State<'_, AppState>, ont_link: String, save_folder: String) -> Result<String, String> {
    s.node.download(&ont_link, &save_folder)
}

#[tauri::command(async)]
fn bundles(s: State<'_, AppState>) -> Vec<BundleDto> {
    s.node
        .bundles()
        .into_iter()
        .map(|b| BundleDto { name: b.name, kind: b.kind, size: b.size, progress: b.progress, link: b.link })
        .collect()
}

// --- Sites ---

#[tauri::command(async)]
fn publish_site(s: State<'_, AppState>, folder: String) -> Result<String, String> {
    s.node.publish_site(&folder)
}

#[tauri::command(async)]
fn open_site(s: State<'_, AppState>, address: String) -> Result<String, String> {
    s.node.open_site(&address)
}

/// Opens a page on this machine's loopback in the system browser. Only local
/// addresses: the window never sends the browser anywhere else.
#[tauri::command(async)]
fn open_in_browser(url: String) -> Result<(), String> {
    if !url.starts_with("http://127.0.0.1:") {
        return Err("only a site opened on this machine can be shown".into());
    }
    #[cfg(windows)]
    let result = std::process::Command::new("rundll32").args(["url.dll,FileProtocolHandler", &url]).spawn();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(&url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = std::process::Command::new("xdg-open").arg(&url).spawn();
    result.map(|_| ()).map_err(|e| e.to_string())
}

// --- The anonymous exit ---

#[tauri::command(async)]
fn start_anonymous_exit(s: State<'_, AppState>) -> Result<(), String> {
    s.node.start_anonymous_exit()
}

#[tauri::command(async)]
fn stop_anonymous_exit(s: State<'_, AppState>) {
    s.node.stop_anonymous_exit();
}

// --- Guests' accounts ---

#[tauri::command(async)]
fn add_account(s: State<'_, AppState>, user: String, password: String) -> Result<(), String> {
    s.node.add_account(&user, &password)
}

#[tauri::command(async)]
fn remove_account(s: State<'_, AppState>, user: String) -> Result<(), String> {
    s.node.remove_account(&user)
}

#[tauri::command(async)]
fn accounts(s: State<'_, AppState>) -> Vec<String> {
    s.node.accounts()
}

// ---- Boot ------------------------------------------------------------------

fn identity_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("StalkNet");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".stalknet");
    }
    std::env::temp_dir().join("StalkNet")
}

fn ensure_parent(path: &str) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
}

fn main() {
    let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let node = Arc::new(Node::new());

    let sink = logs.clone();
    node.set_logger(Arc::new(move |line: String| {
        let mut buf = sink.lock().unwrap();
        buf.push(line);
        if buf.len() > 2000 {
            let drop = buf.len() - 2000;
            buf.drain(0..drop);
        }
    }));

    // Keepalive: trade cards with the network every quarter of an hour. Does
    // nothing while the node is not running.
    let keeper = node.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(15 * 60));
        keeper.gossip();
    });

    // Test hook: with STALKNET_TEST_AUTOSTART set, the node signs in and joins
    // by itself a moment after launch, so the window can be checked for
    // responsiveness during the join without a human clicking START.
    if std::env::var("STALKNET_TEST_AUTOSTART").is_ok() {
        let tester = node.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            let path = identity_dir().join("node.id");
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            if tester.open_or_create(&path.to_string_lossy()).is_ok() {
                tester.set_config(NodeConfig {
                    network: "stalknet".into(),
                    public_host: "127.0.0.1".into(),
                    auto_map_port: false,
                    force_relay: false,
                });
                tester.warm_pass();
                let _ = tester.start(9040, false, true);
                tester.reconnect(true);
            }
        });
    }

    let state = AppState { node, logs };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            core_version,
            default_identity_path,
            identity_exists,
            auto_identity,
            create_identity,
            open_identity,
            set_config,
            start_node,
            reconnect,
            stop_node,
            status,
            take_logs,
            relays,
            set_trusted_exits,
            trusted_exits,
            start_hidden,
            stop_hidden,
            open_tunnel,
            close_tunnel,
            add_shared_folder,
            remove_shared_folder,
            shared_folders,
            expose_port,
            hide_port,
            exposed_ports,
            open_hidden_folders,
            remote_login,
            remote_files,
            remote_download,
            close_remote,
            forward_hidden,
            share,
            download,
            bundles,
            publish_site,
            open_site,
            open_in_browser,
            start_anonymous_exit,
            stop_anonymous_exit,
            add_account,
            remove_account,
            accounts
        ])
        .run(tauri::generate_context!())
        .expect("error while running the StalkNet window");
}
