use std::error::Error;
use std::sync::{Arc, Mutex};

use codeischeap_adapters::AdapterRegistry;
#[cfg(test)]
use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::CapturePolicy;
#[cfg(test)]
use codeischeap_core::persist_capture;
use codeischeap_core::{GatewayCaptureOutcome, process_gateway_event};
use codeischeap_desktop_api::{WorkspaceBootstrap, load_workspace};
use codeischeap_gateway::{Gateway, GatewayCapture, GatewayCaptureEvent};
use codeischeap_storage::{EncryptedStore, OsKeyStore};
use serde::Serialize;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, WindowEvent};
use tokio::net::TcpListener;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use url::Url;

#[cfg(test)]
const DEMO_CAPTURE: &str = include_str!("../fixtures/demo-capture.json");
const LEGACY_DEMO_CAPTURE_ID: &str = "demo_openai_parser";
const KEY_SERVICE: &str = "com.codeischeap.desktop";
const KEY_ACCOUNT: &str = "capture-database-v1";
const DEFAULT_GATEWAY_ADDRESS: &str = "127.0.0.1:8787";
const DEFAULT_OPENAI_UPSTREAM: &str = "https://api.openai.com";
const CAPTURE_UPDATED_EVENT: &str = "capture-updated";
const CAPTURE_RUNTIME_ERROR_EVENT: &str = "capture-runtime-error";

type SharedStore = Arc<Mutex<Option<EncryptedStore>>>;

struct DesktopState {
    store: SharedStore,
    gateway: AsyncMutex<Option<GatewayRuntime>>,
}

struct GatewayRuntime {
    capture: GatewayCapture,
    endpoint: String,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for GatewayRuntime {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureUpdated {
    capture_id: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureRuntimeError {
    code: &'static str,
    detail: String,
}

#[tauri::command]
async fn bootstrap_workspace(
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<WorkspaceBootstrap, String> {
    initialize_store(&app, &state.store)?;
    ensure_gateway(&app, &state).await?;
    let gateway = state.gateway.lock().await;
    let runtime = gateway
        .as_ref()
        .ok_or_else(|| "local AI gateway is unavailable".to_owned())?;
    let mut workspace = {
        let store = state
            .store
            .lock()
            .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
        load_workspace(
            store
                .as_ref()
                .expect("desktop store is initialized before loading"),
        )
        .map_err(|error| error.to_string())?
    };
    apply_gateway_state(&mut workspace, runtime);
    Ok(workspace)
}

#[tauri::command]
async fn set_capture_active(active: bool, state: State<'_, DesktopState>) -> Result<bool, String> {
    let gateway = state.gateway.lock().await;
    let runtime = gateway
        .as_ref()
        .ok_or_else(|| "local AI gateway has not started".to_owned())?;
    runtime.capture.set_enabled(active);
    Ok(runtime.capture.is_enabled())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(DesktopState {
                store: Arc::new(Mutex::new(None)),
                gateway: AsyncMutex::new(None),
            });

            let show = MenuItem::with_id(app, "show", "Show CodeIsCheap", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if matches!(
                        event,
                        TrayIconEvent::Click {
                            button: MouseButton::Left,
                            button_state: MouseButtonState::Up,
                            ..
                        }
                    ) {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            bootstrap_workspace,
            set_capture_active
        ])
        .run(tauri::generate_context!())
        .expect("CodeIsCheap desktop runtime failed");
}

fn open_application_store(app: &AppHandle) -> Result<EncryptedStore, Box<dyn Error>> {
    let database_path = app.path().app_data_dir()?.join("captures.db");
    let key_store = OsKeyStore::new(KEY_SERVICE, KEY_ACCOUNT)?;
    Ok(EncryptedStore::open_with_key_store(
        database_path,
        &key_store,
    )?)
}

fn initialize_store(app: &AppHandle, store: &SharedStore) -> Result<(), String> {
    let mut store = store
        .lock()
        .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
    if store.is_none() {
        let mut initialized = open_application_store(app).map_err(|error| error.to_string())?;
        remove_legacy_demo_capture(&mut initialized).map_err(|error| error.to_string())?;
        *store = Some(initialized);
    }
    Ok(())
}

fn remove_legacy_demo_capture(
    store: &mut EncryptedStore,
) -> Result<bool, codeischeap_storage::StorageError> {
    store.delete_capture(LEGACY_DEMO_CAPTURE_ID)
}

async fn ensure_gateway(app: &AppHandle, state: &DesktopState) -> Result<(), String> {
    let mut runtime = state.gateway.lock().await;
    if runtime.is_some() {
        return Ok(());
    }

    let listener = TcpListener::bind(DEFAULT_GATEWAY_ADDRESS)
        .await
        .map_err(|error| {
            format!("local AI gateway could not bind {DEFAULT_GATEWAY_ADDRESS}: {error}")
        })?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("local AI gateway address is unavailable: {error}"))?;
    let upstream = Url::parse(DEFAULT_OPENAI_UPSTREAM)
        .map_err(|error| format!("default OpenAI upstream is invalid: {error}"))?;
    let (capture, receiver, _) = GatewayCapture::defaults();
    let gateway = Gateway::new(upstream).map_err(|error| error.to_string())?;
    let gateway = gateway.with_capture(capture.clone());
    let (shutdown, shutdown_rx) = oneshot::channel();
    let server_app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = gateway
            .serve(listener, async move {
                let _ = shutdown_rx.await;
            })
            .await
        {
            emit_runtime_error(&server_app, "gateway_serve_failed", error.to_string());
        }
    });
    tauri::async_runtime::spawn(process_capture_events(
        app.clone(),
        state.store.clone(),
        receiver,
    ));

    *runtime = Some(GatewayRuntime {
        capture,
        endpoint: format!("http://{address}"),
        shutdown: Some(shutdown),
    });
    Ok(())
}

async fn process_capture_events(
    app: AppHandle,
    store: SharedStore,
    mut receiver: mpsc::Receiver<GatewayCaptureEvent>,
) {
    let policy = match CapturePolicy::load_default() {
        Ok(policy) => policy,
        Err(error) => {
            emit_runtime_error(&app, "capture_policy_invalid", error.to_string());
            return;
        }
    };
    let adapters = AdapterRegistry::default();

    while let Some(event) = receiver.recv().await {
        let result = {
            let mut store = match store.lock() {
                Ok(store) => store,
                Err(_) => {
                    emit_runtime_error(
                        &app,
                        "capture_store_unavailable",
                        "encrypted workspace is temporarily unavailable".to_owned(),
                    );
                    return;
                }
            };
            let Some(store) = store.as_mut() else {
                emit_runtime_error(
                    &app,
                    "capture_store_uninitialized",
                    "encrypted workspace has not initialized".to_owned(),
                );
                return;
            };
            process_gateway_event(store, &policy, &adapters, event)
        };

        match result {
            Ok(GatewayCaptureOutcome::Persisted(capture)) => {
                let _ = app.emit(
                    CAPTURE_UPDATED_EVENT,
                    CaptureUpdated {
                        capture_id: capture.capture_id,
                    },
                );
            }
            Ok(
                GatewayCaptureOutcome::ResponseObserved(_)
                | GatewayCaptureOutcome::UpstreamFailed(_),
            ) => {}
            Err(error) => {
                emit_runtime_error(&app, "capture_processing_failed", error.to_string());
            }
        }
    }
}

fn apply_gateway_state(workspace: &mut WorkspaceBootstrap, runtime: &GatewayRuntime) {
    workspace.capture.active = runtime.capture.is_enabled();
    workspace.capture.can_control = true;
    workspace.capture.profile = "OpenAI-compatible local gateway".to_owned();
    workspace.capture.endpoint = runtime.endpoint.clone();
}

fn emit_runtime_error(app: &AppHandle, code: &'static str, detail: String) {
    let _ = app.emit(
        CAPTURE_RUNTIME_ERROR_EVENT,
        CaptureRuntimeError { code, detail },
    );
}

#[cfg(test)]
fn seed_demo_capture(store: &mut EncryptedStore) -> Result<(), Box<dyn Error>> {
    let envelope: CaptureEnvelope = serde_json::from_str(DEMO_CAPTURE)?;
    if store.get_capture(&envelope.capture_id)?.is_some() {
        return Ok(());
    }
    let policy = CapturePolicy::load_default()?;
    let sanitized = policy.sanitize_envelope(envelope)?;
    let parsed = AdapterRegistry::default().parse(&sanitized);
    persist_capture(store, &sanitized, parsed.prompt_ir.as_ref())?;
    Ok(())
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use codeischeap_storage::DatabaseKey;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn demo_capture_is_seeded_once_and_loaded_from_sqlcipher() {
        let directory = tempdir().expect("temp directory must be created");
        let mut store = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x61; 32]),
        )
        .expect("encrypted store must open");

        seed_demo_capture(&mut store).expect("demo capture must seed");
        seed_demo_capture(&mut store).expect("demo capture seeding must be idempotent");
        let workspace = load_workspace(&store).expect("workspace must load from SQLCipher");

        assert_eq!(workspace.capture.request_count, 1);
        assert_eq!(workspace.requests.len(), 1);
        assert_eq!(workspace.requests[0].id, "demo_openai_parser");
        assert_eq!(workspace.requests[0].provider, "OpenAI");
        assert_eq!(
            workspace.requests[0].prompt_preview,
            "Fix the failing parser test."
        );
        assert!(workspace.requests[0].has_tools);
        assert!(
            workspace.requests[0]
                .detail
                .anatomy
                .iter()
                .any(|section| section.id == "messages" && section.count == 1)
        );
        let encoded = serde_json::to_string(&workspace).expect("workspace must encode");
        for forbidden in ["Bearer ", "sk-", "x-api-key"] {
            assert!(
                !encoded
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "desktop workspace must not contain credential marker {forbidden}"
            );
        }
    }

    #[test]
    fn legacy_demo_capture_is_removed_from_live_workspaces() {
        let directory = tempdir().expect("temp directory must be created");
        let mut store = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x62; 32]),
        )
        .expect("encrypted store must open");
        seed_demo_capture(&mut store).expect("demo capture must seed");

        assert!(remove_legacy_demo_capture(&mut store).expect("demo cleanup must succeed"));
        assert_eq!(store.capture_count().expect("count must load"), 0);
    }

    #[test]
    fn gateway_runtime_controls_workspace_capture_state() {
        let directory = tempdir().expect("temp directory must be created");
        let store = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x63; 32]),
        )
        .expect("encrypted store must open");
        let mut workspace = load_workspace(&store).expect("workspace must load");
        let (capture, receiver, _) = GatewayCapture::defaults();
        drop(receiver);
        capture.set_enabled(false);
        let (shutdown, _shutdown_rx) = oneshot::channel();
        let runtime = GatewayRuntime {
            capture,
            endpoint: "http://127.0.0.1:8787".to_owned(),
            shutdown: Some(shutdown),
        };

        apply_gateway_state(&mut workspace, &runtime);

        assert!(!workspace.capture.active);
        assert!(workspace.capture.can_control);
        assert_eq!(workspace.capture.endpoint, "http://127.0.0.1:8787");
        assert_eq!(workspace.capture.profile, "OpenAI-compatible local gateway");
    }
}
