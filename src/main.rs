use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::{routing::{get, post}, Router, Json};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use clap::Parser;
use eframe::egui;
use rfd::FileDialog;
use serde_json::{json, Value};
use tokio::sync::{Mutex, oneshot};
use tokio::time::sleep;

// Patcher constants with variants for robustness
const SIGNATURE_VARIANTS: [[&[u8]; 2]; 3] = [
    [
        &[
            0x25, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x6F, 0x00, 0x61, 0x00, 0x75, 0x00, 0x74, 0x00,
            0x68, 0x00, 0x32, 0x00, 0x2F, 0x00, 0x6E, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x25, 0x00,
            0x73, 0x00, 0x2F, 0x00, 0x70, 0x00, 0x2F, 0x00, 0x25, 0x00, 0x73, 0x00, 0x2F, 0x00,
            0x61, 0x00, 0x75, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x69, 0x00,
            0x7A, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        &[
            0x61, 0x00, 0x75, 0x00, 0x74, 0x00, 0x68, 0x00, 0x6F, 0x00, 0x72, 0x00, 0x69, 0x00,
            0x7A, 0x00, 0x65, 0x00,
        ],
    ],
    [
        &[
            0x25, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x6F, 0x00, 0x61, 0x00, 0x75, 0x00, 0x74, 0x00,
            0x68, 0x00, 0x32, 0x00, 0x2F, 0x00, 0x6E, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x25, 0x00,
            0x73, 0x00, 0x2F, 0x00, 0x74, 0x00, 0x6F, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x6E, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        &[
            0x74, 0x00, 0x6F, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x6E, 0x00,
        ],
    ],
    [
        &[
            0x25, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x70, 0x00, 0x75, 0x00, 0x62, 0x00, 0x6C, 0x00,
            0x69, 0x00, 0x63, 0x00, 0x2F, 0x00, 0x76, 0x00, 0x31, 0x00, 0x2F, 0x00, 0x6E, 0x00,
            0x61, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x73, 0x00, 0x70, 0x00, 0x61, 0x00, 0x63, 0x00,
            0x65, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x25, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x75, 0x00,
            0x73, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x25, 0x00, 0x73, 0x00,
            0x2F, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x69, 0x00, 0x74, 0x00, 0x6C, 0x00,
            0x65, 0x00, 0x6D, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x73, 0x00, 0x2F, 0x00,
            0x64, 0x00, 0x75, 0x00, 0x72, 0x00, 0x61, 0x00, 0x62, 0x00, 0x6C, 0x00, 0x65, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ],
        &[
            0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x69, 0x00, 0x74, 0x00, 0x6C, 0x00, 0x65, 0x00,
            0x6D, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x73, 0x00, 0x2F, 0x00, 0x64, 0x00,
            0x75, 0x00, 0x72, 0x00, 0x61, 0x00, 0x62, 0x00, 0x6C, 0x00, 0x65, 0x00,
        ],
    ],
];

const PATCHES: [&[u8]; 3] = [
    &[
        0x25, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x73, 0x00, 0x3A, 0x00, 0x2F, 0x00, 0x2F, 0x00,
        0x31, 0x00, 0x32, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00,
        0x2F, 0x00, 0x25, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x73, 0x00, 0x61, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    &[
        0x25, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x73, 0x00, 0x3A, 0x00, 0x2F, 0x00, 0x2F, 0x00,
        0x31, 0x00, 0x32, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00,
        0x2F, 0x00, 0x25, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x73, 0x00, 0x62, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
    &[
        0x25, 0x00, 0x2E, 0x00, 0x34, 0x00, 0x73, 0x00, 0x3A, 0x00, 0x2F, 0x00, 0x2F, 0x00,
        0x31, 0x00, 0x32, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x30, 0x00, 0x31, 0x00,
        0x2F, 0x00, 0x25, 0x00, 0x2E, 0x00, 0x30, 0x00, 0x73, 0x00, 0x63, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ],
];

const ENTITLEMENTS_JSON: &str = r#"
{
  "durableEntitlements": [
    {"id": "5f7a2e91dca4132a8f49bd10", "sku": "TwitchReward_2025_EA_01", "source": "DROPS", "provider": "KRAFTON", "grantedAt": 1743186059},
    {"id": "3a6f5c72bcd9013e9c28de45", "sku": "TwitchReward_2025_EA_02", "source": "DROPS", "provider": "KRAFTON", "grantedAt": 1743186173},
    {"id": "8b9e7d31accc98d2f347fa63", "sku": "TwitchReward_2025_EA_03", "source": "DROPS", "provider": "KRAFTON", "grantedAt": 1743186241},
    {"id": "9d3a6f85bb2139fe8a20cd74", "sku": "FriendInvitationReward_2025_EA_01", "source": "INVITE", "provider": "KRAFTON", "grantedAt": 1743186359},
    {"id": "7b1c4e21dbb502f39e11ea29", "sku": "FriendInvitationReward_2025_EA_02", "source": "INVITE", "provider": "KRAFTON", "grantedAt": 1743186437},
    {"id": "1e29b5a4cabd671ed90aee57", "sku": "InfluencerReward_2025_EA_01", "source": "INFLUENCER", "provider": "KRAFTON", "grantedAt": 1743186520},
    {"id": "6c5f7b94edd2189fa443bb92", "sku": "ChinaReward_2025_EA_01", "source": "REGIONAL", "provider": "KRAFTON", "grantedAt": 1743186625},
    {"id": "4a8d3c07bae761efbd36dd20", "sku": "ChinaReward_2025_EA_02", "source": "REGIONAL", "provider": "KRAFTON", "grantedAt": 1743186701},
    {"id": "a93d2f85aefb445eab12cc61", "sku": "ChinaReward_2025_EA_03", "source": "REGIONAL", "provider": "KRAFTON", "grantedAt": 1743186799},
    {"id": "c21fb8de3470519dcd44ef88", "sku": "KCNReward_2025_EA_01", "source": "REGIONAL", "provider": "KRAFTON", "grantedAt": 1743186905}
  ]
}
"#;

// Patcher logic
#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    in_path: Option<PathBuf>,
    #[clap(short, long)]
    genuine: bool,
}

fn find_pattern(buffer: &[u8], pattern: &[u8]) -> Option<usize> {
    buffer.windows(pattern.len()).position(|window| window == pattern)
}

fn find_signatures(data: &[u8]) -> Result<Vec<(usize, usize)>, String> {
    let mut offsets = Vec::new();
    for (idx, variants) in SIGNATURE_VARIANTS.iter().enumerate() {
        let mut found = None;
        for (var_idx, sig) in variants.iter().enumerate() {
            if let Some(offset) = find_pattern(data, sig) {
                found = Some((offset, var_idx));
                break;
            }
        }
        let (offset, var_used) = found.ok_or_else(|| {
            format!("Couldn't find any signature variant for patch {} (auth, token, or entitlements)", idx + 1)
        })?;
        println!("Found signature {} (variant {}) at offset {}", idx + 1, var_used, offset);
        offsets.push((offset, idx));
    }
    Ok(offsets)
}

fn patch(data: &mut [u8], genuine: bool) -> Result<(), String> {
    let offsets = find_signatures(data)?;
    for (offset, idx) in offsets {
        if genuine && idx <= 1 {
            println!("Skipped patch {} (genuine mode)", idx + 1);
            continue;
        }
        let patch = PATCHES[idx];
        if data[offset..].len() < patch.len() {
            return Err(format!("Patch {} at offset {} exceeds binary length", idx + 1, offset));
        }
        data[offset..offset + patch.len()].copy_from_slice(patch);
        println!("Patch {} OK at offset {}", idx + 1, offset);
    }
    Ok(())
}

// Server logic
const ADDRESS_PORT: &str = "127.0.0.1:80";

async fn a() -> impl IntoResponse {
    println!("Game called auth endpoint.");
    let resp = json!({
        "code": "00000000-0000-0000-0000-000000000000",
        "state": "",
        "email": "",
        "ktag": ""
    });
    (StatusCode::OK, Json(resp)).into_response()
}

async fn b() -> impl IntoResponse {
    println!("Game called token endpoint.");
    let resp = json!({
        "access_token": "",
        "account_id": "00000000000000000000000000000000",
        "app_Version": "20250329.1346.W-147163",
        "bans": [],
        "country": "GB",
        "device": "PC",
        "display_name": "pooks",
        "expires_in": 999999,
        "game_server_id": "",
        "is_comply": true,
        "is_full_kid": false,
        "is_ga_full_account": false,
        "jflgs": 0,
        "krafton_id": "globalaccount.00000000-0000-0000-0000-000000000000",
        "krafton_tag": "Pooks#1337",
        "namespace": "inzoi",
        "namespace_roles": [{"roleId": "2251438839e948d783ec0e5281daf05b", "namespace": "*"}],
        "os": "Windows",
        "os_detail": "Windows 10 (10.0.19045)",
        "permissions": [],
        "platform": "SteamStore",
        "platform_id": "steam",
        "platform_user_id": "00000000000000000",
        "publisher": "gpp",
        "refresh_expires_in": 2592000,
        "refresh_token": "",
        "roles": ["2251438839e948d783ec0e5281daf05b"],
        "scope": "account commerce social publishing analytics",
        "server_time": 0,
        "token_type": "Bearer",
        "user_id": "00000000000000000000000000000000",
        "xuid": ""
    });
    (StatusCode::OK, Json(resp)).into_response()
}

async fn c(shared_json: Arc<Mutex<Value>>, shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>) -> impl IntoResponse {
    println!("Game called entitlements endpoint.");
    let json_data = shared_json.lock().await.clone();
    let mut shutdown_tx = shutdown_tx.lock().await;
    if let Some(tx) = shutdown_tx.take() {
        let _ = tx.send(());
    }
    println!("DLC unlocked.");
    (StatusCode::OK, Json(json_data)).into_response()
}

async fn start_server() {
    let json_value: Value = serde_json::from_str(ENTITLEMENTS_JSON).expect("Failed to parse embedded entitlements");
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shared_json = Arc::new(Mutex::new(json_value));
    let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));

    let app = Router::new()
        .route("/a", post(a))
        .route("/b", post(b))
        .route("/c", get({
            let shared_json = shared_json.clone();
            let shutdown_tx = shutdown_tx.clone();
            move || c(shared_json, shutdown_tx)
        }));

    let listener = tokio::net::TcpListener::bind(ADDRESS_PORT).await.expect("Failed to bind to port 80");
    println!("Serving API on {}...", ADDRESS_PORT);

    let server = axum::serve(listener, app.into_make_service());
    let shutdown_handle = tokio::spawn(async move {
        shutdown_rx.await.ok();
    });

    tokio::select! {
        _ = server => {}
        _ = shutdown_handle => {
            println!("Exiting server in 5 seconds...");
            sleep(Duration::from_secs(5)).await;
        }
    }
}

// GUI
struct InZOIApp {
    status: String,
    game_path: Option<PathBuf>,
    should_launch: bool,
}

impl InZOIApp {
    fn load_game_path() -> Option<PathBuf> {
        if let Ok(path_str) = fs::read_to_string("config.txt") {
            let path = PathBuf::from(path_str.trim());
            if path.exists() && path.is_file() {
                return Some(path);
            }
        }
        None
    }

    fn save_game_path(&self) {
        if let Some(path) = &self.game_path {
            if let Err(e) = fs::write("config.txt", path.to_string_lossy().as_ref()) {
                println!("Failed to save game path: {}", e);
            }
        }
    }
}

impl eframe::App for InZOIApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("inZOI DLC Unlocker");
            ui.label("Select your inZOI-Win64-Shipping.exe (saved after selection):");

            if ui.button("Select Game Binary").clicked() {
                if let Some(path) = FileDialog::new()
                    .add_filter("Executable", &["exe"])
                    .pick_file()
                {
                    self.game_path = Some(path);
                    self.status = format!("Selected: {}", self.game_path.as_ref().unwrap().display());
                    self.save_game_path();
                }
            }

            if let Some(path) = &self.game_path {
                ui.label(&self.status);

                if ui.button("Patch Non-Genuine").clicked() {
                    let result = patch_and_run(path, false);
                    self.status = result.status;
                    if result.success {
                        self.should_launch = true;
                    }
                }

                if ui.button("Patch Genuine").clicked() {
                    let result = patch_and_run(path, true);
                    self.status = result.status;
                    if result.success {
                        self.should_launch = true;
                    }
                }

                if ui.button("Start Game & Server API").clicked() {
                    self.status = "Launching game and server...".to_string();
                    self.should_launch = true;
                }

                if self.should_launch {
                    launch_game_and_server(path);
                    self.should_launch = false;
                }
            } else {
                ui.label("No binary selected yet.");
            }
        });
    }
}

// Helper struct to return patch result
struct PatchResult {
    status: String,
    success: bool,
}

fn patch_and_run(path: &PathBuf, genuine: bool) -> PatchResult {
    let mut data = match fs::read(path) {
        Ok(data) => data,
        Err(e) => return PatchResult { status: format!("Failed to read binary: {}", e), success: false },
    };

    if path.extension().unwrap_or_default() != "exe" {
        return PatchResult { status: "Invalid file type. Must be .exe".to_string(), success: false };
    }

    let backup_path = path.with_extension("exe.bak");
    if !backup_path.exists() {
        if let Err(e) = fs::copy(path, &backup_path) {
            return PatchResult { status: format!("Failed to create backup: {}", e), success: false };
        }
        println!("Created backup at {}", backup_path.display());
    }

    match patch(&mut data, genuine) {
        Ok(()) => {
            if let Err(e) = fs::write(path, &data) {
                return PatchResult { status: format!("Failed to write patched binary: {}", e), success: false };
            }
            PatchResult { status: "Patching successful! Launching game...".to_string(), success: true }
        }
        Err(e) => PatchResult { status: format!("Patching failed: {}. Restore from {}.exe.bak if needed.", e, path.file_stem().unwrap().to_string_lossy()), success: false },
    }
}

fn launch_game_and_server(path: &PathBuf) {
    let game_path = path.clone();
    std::thread::spawn(move || {
        Command::new(&game_path)
            .spawn()
            .expect("Failed to launch game");
    });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(start_server());
}

fn main() {
    let options = eframe::NativeOptions::default();
    let app = InZOIApp {
        status: if let Some(path) = InZOIApp::load_game_path() {
            format!("Loaded: {}", path.display())
        } else {
            "Ready".to_string()
        },
        game_path: InZOIApp::load_game_path(),
        should_launch: false,
    };
    eframe::run_native(
        "inZOI DLC Unlocker",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    ).expect("Failed to start GUI");
}