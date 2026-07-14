use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, WindowEvent};

const WORKSPACE_FIXTURE: &str = include_str!("../../src/data/workspace.json");

#[tauri::command]
fn bootstrap_workspace() -> Result<serde_json::Value, String> {
    serde_json::from_str(WORKSPACE_FIXTURE)
        .map_err(|error| format!("synthetic workspace fixture is invalid: {error}"))
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
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

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_fixture_is_valid_and_contains_no_credentials() {
        let value = bootstrap_workspace().expect("fixture must parse");
        assert_eq!(value["fixture"], "synthetic");
        assert_eq!(value["requests"].as_array().map(Vec::len), Some(6));

        let encoded = serde_json::to_string(&value).expect("fixture must encode");
        for forbidden in ["sk-", "Bearer ", "x-api-key"] {
            assert!(
                !encoded
                    .to_ascii_lowercase()
                    .contains(&forbidden.to_ascii_lowercase()),
                "fixture must not contain credential marker {forbidden}"
            );
        }
    }
}
