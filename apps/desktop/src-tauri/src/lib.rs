use std::error::Error;
use std::sync::Mutex;

use codeischeap_adapters::AdapterRegistry;
use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_core::persist_capture;
use codeischeap_desktop_api::{WorkspaceBootstrap, load_workspace};
use codeischeap_storage::{EncryptedStore, OsKeyStore};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, State, WindowEvent};

const DEMO_CAPTURE: &str = include_str!("../fixtures/demo-capture.json");
const KEY_SERVICE: &str = "com.codeischeap.desktop";
const KEY_ACCOUNT: &str = "capture-database-v1";

struct DesktopState {
    store: Mutex<Option<EncryptedStore>>,
}

#[tauri::command]
fn bootstrap_workspace(
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<WorkspaceBootstrap, String> {
    let mut store = state
        .store
        .lock()
        .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
    if store.is_none() {
        let mut initialized = open_application_store(&app).map_err(|error| error.to_string())?;
        seed_demo_capture(&mut initialized).map_err(|error| error.to_string())?;
        *store = Some(initialized);
    }
    load_workspace(
        store
            .as_ref()
            .expect("desktop store is initialized before loading"),
    )
    .map_err(|error| error.to_string())
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(DesktopState {
                store: Mutex::new(None),
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
        .invoke_handler(tauri::generate_handler![bootstrap_workspace])
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
}
