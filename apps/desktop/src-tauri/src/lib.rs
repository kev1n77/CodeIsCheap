use std::collections::{BTreeSet, HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use codeischeap_adapters::AdapterRegistry;
#[cfg(test)]
use codeischeap_capture_ipc::CaptureEnvelope;
use codeischeap_capture_policy::CapturePolicy;
use codeischeap_core::{
    GatewayCaptureError, GatewayCaptureOutcome, IngestError, ingest_one, persist_capture,
    process_gateway_event,
};
use codeischeap_desktop_api::{
    CaptureMode, CapturedRequest, CertificateAuthority, CertificateAuthorityState,
    CertificatePrivateMaterial, CertificateTrust, DesktopApiError, ExportPreview, ExportProfile,
    ExportReceipt, WorkspaceBootstrap, build_batch_export_preview, build_export_preview,
    load_request, load_workspace, search_requests,
};
use codeischeap_gateway::{Gateway, GatewayCapture, GatewayCaptureEvent};
use codeischeap_proxy_recovery::recover_from_journal;
#[cfg(windows)]
use codeischeap_proxy_recovery::{ProxySession, ProxySettings, WindowsProxyBackend};
use codeischeap_sidecar_runtime::{
    BundleRequirements, CertificateAuthorityState as SidecarCertificateAuthorityState,
    CertificateTrustState as SidecarCertificateTrustState, MANIFEST_FILENAME,
    PrivateMaterialState as SidecarPrivateMaterialState, SidecarBundle, SidecarLaunchConfig,
    SidecarProcess, inspect_certificate_authority,
    install_certificate_authority as install_ca_trust,
    uninstall_certificate_authority as uninstall_ca_trust,
};
use codeischeap_storage::{
    EncryptedStore, OsKeyStore, RetentionPolicy, RetentionReport, StorageError,
};
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
const MAX_PENDING_CAPTURE_OUTCOMES: usize = 256;
const CAPTURES_PER_RETENTION_RUN: usize = 100;
const MAX_BATCH_EXPORT_REQUESTS: usize = 200;
const SIDECAR_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const SIDECAR_MONITOR_INTERVAL: Duration = Duration::from_millis(250);
const PROXY_RECOVERY_JOURNAL_FILENAME: &str = "proxy-recovery.v0.1.json";

type SharedStore = Arc<Mutex<Option<EncryptedStore>>>;

struct DesktopState {
    store: SharedStore,
    gateway: AsyncMutex<Option<GatewayRuntime>>,
    proxy: AsyncMutex<Option<ProxyRuntime>>,
    mode: AsyncMutex<CaptureMode>,
    capture_active: Arc<AtomicBool>,
    next_proxy_generation: AtomicU64,
    proxy_recovery_checked: AtomicBool,
    sidecar_bundle: Option<Arc<SidecarBundle>>,
    sidecar_error: Mutex<Option<String>>,
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

struct ProxyRuntime {
    generation: u64,
    system_proxy: Option<PlatformProxySession>,
    process: Option<SidecarProcess>,
    endpoint: String,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ProxyRuntime {
    fn shutdown(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(session) = self.system_proxy.take() {
            session.restore()?;
        }
        self.process.take();
        Ok(())
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

enum PlatformProxySession {
    #[cfg(windows)]
    Windows(ProxySession<WindowsProxyBackend>),
}

impl PlatformProxySession {
    fn restore(self) -> Result<(), String> {
        match self {
            #[cfg(windows)]
            Self::Windows(session) => session.restore().map_err(|error| error.to_string()),
        }
    }
}

struct RuntimeSnapshot {
    mode: CaptureMode,
    active: bool,
    proxy_available: bool,
    gateway_endpoint: Option<String>,
    proxy_endpoint: Option<String>,
    system_proxy_active: bool,
    certificate_authority: CertificateAuthority,
}

#[derive(Debug)]
enum ProxyCaptureError {
    Ingest(IngestError),
    StoreUnavailable,
    StoreUninitialized,
    Storage(StorageError),
}

impl fmt::Display for ProxyCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ingest(error) => write!(formatter, "{error}"),
            Self::StoreUnavailable => {
                write!(formatter, "encrypted workspace is temporarily unavailable")
            }
            Self::StoreUninitialized => {
                write!(formatter, "encrypted workspace has not initialized")
            }
            Self::Storage(error) => write!(formatter, "{error}"),
        }
    }
}

impl From<IngestError> for ProxyCaptureError {
    fn from(error: IngestError) -> Self {
        Self::Ingest(error)
    }
}

impl From<StorageError> for ProxyCaptureError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
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
    ensure_proxy_recovery(&app, &state).await?;
    initialize_store(&app, &state.store)?;
    ensure_gateway(&app, &state).await?;
    let workspace = load_runtime_workspace(&app, &state).await?;
    emit_sidecar_error_once(&app, &state);
    Ok(workspace)
}

#[tauri::command]
async fn search_workspace(
    query: String,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<Vec<CapturedRequest>, String> {
    initialize_store(&app, &state.store)?;
    let store = state
        .store
        .lock()
        .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
    search_requests(
        store
            .as_ref()
            .ok_or_else(|| "encrypted workspace has not initialized".to_owned())?,
        &query,
    )
    .map_err(|error| error.to_string())
}

#[tauri::command]
async fn set_capture_active(active: bool, state: State<'_, DesktopState>) -> Result<bool, String> {
    let mode = *state.mode.lock().await;
    match mode {
        CaptureMode::Gateway => {
            let gateway = state.gateway.lock().await;
            let runtime = gateway
                .as_ref()
                .ok_or_else(|| "local AI gateway has not started".to_owned())?;
            runtime.capture.set_enabled(active);
        }
        CaptureMode::Proxy => {
            if state.proxy.lock().await.is_none() {
                return Err("explicit proxy has not started".to_owned());
            }
        }
    }
    state.capture_active.store(active, Ordering::Release);
    Ok(active)
}

#[tauri::command]
async fn set_capture_mode(
    mode: CaptureMode,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<WorkspaceBootstrap, String> {
    initialize_store(&app, &state.store)?;
    ensure_gateway(&app, &state).await?;
    switch_capture_mode(&app, &state, mode).await?;
    load_runtime_workspace(&app, &state).await
}

#[tauri::command]
async fn install_certificate_authority_trust(
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<WorkspaceBootstrap, String> {
    initialize_store(&app, &state.store)?;
    let confdir = application_certificate_confdir(&app)?;
    tokio::task::spawn_blocking(move || install_ca_trust(confdir))
        .await
        .map_err(|error| format!("certificate trust task failed: {error}"))?
        .map_err(|error| error.to_string())?;
    if *state.mode.lock().await == CaptureMode::Proxy {
        let mut runtime = state.proxy.lock().await;
        if let Some(runtime) = runtime.as_mut() {
            activate_system_proxy(&app, runtime).await?;
        }
    }
    load_runtime_workspace(&app, &state).await
}

#[tauri::command]
async fn uninstall_certificate_authority_trust(
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<WorkspaceBootstrap, String> {
    initialize_store(&app, &state.store)?;
    if *state.mode.lock().await == CaptureMode::Proxy {
        switch_capture_mode(&app, &state, CaptureMode::Gateway).await?;
    }
    let confdir = application_certificate_confdir(&app)?;
    tokio::task::spawn_blocking(move || uninstall_ca_trust(confdir))
        .await
        .map_err(|error| format!("certificate trust task failed: {error}"))?
        .map_err(|error| error.to_string())?;
    load_runtime_workspace(&app, &state).await
}

#[tauri::command]
async fn preview_capture_export(
    capture_id: String,
    profile: ExportProfile,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<ExportPreview, String> {
    initialize_store(&app, &state.store)?;
    let store = state.store.clone();
    tauri::async_runtime::spawn_blocking(move || {
        build_capture_export(&store, &capture_id, profile, current_unix_ms()?)
    })
    .await
    .map_err(|error| format!("capture export preview task failed: {error}"))?
}

#[tauri::command]
async fn preview_batch_capture_export(
    capture_ids: Vec<String>,
    profile: ExportProfile,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<ExportPreview, String> {
    initialize_store(&app, &state.store)?;
    let store = state.store.clone();
    tauri::async_runtime::spawn_blocking(move || {
        build_batch_capture_export(&store, &capture_ids, profile, current_unix_ms()?)
    })
    .await
    .map_err(|error| format!("batch capture export preview task failed: {error}"))?
}

#[tauri::command]
async fn write_capture_export(
    capture_id: String,
    profile: ExportProfile,
    exported_at_unix_ms: u64,
    expected_sha256: String,
    path: PathBuf,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<ExportReceipt, String> {
    initialize_store(&app, &state.store)?;
    let store = state.store.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let preview = build_capture_export(&store, &capture_id, profile, exported_at_unix_ms)?;
        if preview.content_sha256 != expected_sha256 {
            return Err("capture changed after preview; review the refreshed export".to_owned());
        }
        write_export_file(&path, preview.content.as_bytes())?;
        Ok(ExportReceipt {
            path: path.to_string_lossy().into_owned(),
            byte_count: preview.byte_count,
            redaction_count: u64::try_from(preview.redactions.len()).unwrap_or(u64::MAX),
        })
    })
    .await
    .map_err(|error| format!("capture export write task failed: {error}"))?
}

#[tauri::command]
async fn write_batch_capture_export(
    capture_ids: Vec<String>,
    profile: ExportProfile,
    exported_at_unix_ms: u64,
    expected_sha256: String,
    path: PathBuf,
    app: AppHandle,
    state: State<'_, DesktopState>,
) -> Result<ExportReceipt, String> {
    initialize_store(&app, &state.store)?;
    let store = state.store.clone();
    tauri::async_runtime::spawn_blocking(move || {
        write_batch_capture_export_file(
            &store,
            &capture_ids,
            profile,
            exported_at_unix_ms,
            &expected_sha256,
            &path,
        )
    })
    .await
    .map_err(|error| format!("batch capture export write task failed: {error}"))?
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let (sidecar_bundle, sidecar_error) =
                optional_sidecar(open_application_sidecar(app.handle()));
            app.manage(DesktopState {
                store: Arc::new(Mutex::new(None)),
                gateway: AsyncMutex::new(None),
                proxy: AsyncMutex::new(None),
                mode: AsyncMutex::new(CaptureMode::Gateway),
                capture_active: Arc::new(AtomicBool::new(true)),
                next_proxy_generation: AtomicU64::new(1),
                proxy_recovery_checked: AtomicBool::new(false),
                sidecar_bundle,
                sidecar_error: Mutex::new(sidecar_error),
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
            install_certificate_authority_trust,
            preview_batch_capture_export,
            preview_capture_export,
            search_workspace,
            set_capture_active,
            set_capture_mode,
            uninstall_certificate_authority_trust,
            write_batch_capture_export,
            write_capture_export
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

fn open_application_sidecar(app: &AppHandle) -> Result<Option<Arc<SidecarBundle>>, Box<dyn Error>> {
    let bundle = sidecar_resource_path(
        &app.path().resource_dir()?,
        Path::new(env!("CARGO_MANIFEST_DIR")),
        cfg!(debug_assertions),
    );
    if !bundle.join(MANIFEST_FILENAME).is_file() {
        return Ok(None);
    }
    let requirements = if cfg!(debug_assertions) {
        BundleRequirements::development()
    } else {
        BundleRequirements::release()
    };
    Ok(Some(Arc::new(SidecarBundle::load(bundle, requirements)?)))
}

fn sidecar_resource_path(resource_dir: &Path, manifest_dir: &Path, development: bool) -> PathBuf {
    if development {
        manifest_dir.join("resources").join("sidecar")
    } else {
        resource_dir.join("resources").join("sidecar")
    }
}

fn optional_sidecar<T, E>(result: Result<Option<T>, E>) -> (Option<T>, Option<String>)
where
    E: fmt::Display,
{
    match result {
        Ok(bundle) => (bundle, None),
        Err(error) => (None, Some(error.to_string())),
    }
}

fn initialize_store(app: &AppHandle, store: &SharedStore) -> Result<(), String> {
    let mut store = store
        .lock()
        .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
    if store.is_none() {
        let mut initialized = open_application_store(app).map_err(|error| error.to_string())?;
        remove_legacy_demo_capture(&mut initialized).map_err(|error| error.to_string())?;
        if let Err(error) = maintain_store(&mut initialized) {
            emit_runtime_error(app, "capture_retention_failed", error.to_string());
        }
        *store = Some(initialized);
    }
    Ok(())
}

fn remove_legacy_demo_capture(
    store: &mut EncryptedStore,
) -> Result<bool, codeischeap_storage::StorageError> {
    store.delete_capture(LEGACY_DEMO_CAPTURE_ID)
}

async fn load_runtime_workspace(
    app: &AppHandle,
    state: &DesktopState,
) -> Result<WorkspaceBootstrap, String> {
    let mut workspace = {
        let store = state
            .store
            .lock()
            .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
        load_workspace(
            store
                .as_ref()
                .ok_or_else(|| "encrypted workspace has not initialized".to_owned())?,
        )
        .map_err(|error| error.to_string())?
    };
    apply_runtime_state(&mut workspace, runtime_snapshot(app, state).await);
    Ok(workspace)
}

fn build_capture_export(
    store: &SharedStore,
    capture_id: &str,
    profile: ExportProfile,
    exported_at_unix_ms: u64,
) -> Result<ExportPreview, String> {
    let request = export_request(store, capture_id)?;
    build_export_preview(&request, profile, exported_at_unix_ms)
        .map_err(|error| format!("capture export could not be encoded: {error}"))
}

fn build_batch_capture_export(
    store: &SharedStore,
    capture_ids: &[String],
    profile: ExportProfile,
    exported_at_unix_ms: u64,
) -> Result<ExportPreview, String> {
    validate_batch_capture_ids(capture_ids)?;
    let requests = export_requests(store, capture_ids)?;
    build_batch_export_preview(&requests, profile, exported_at_unix_ms)
        .map_err(|error| format!("batch capture export could not be encoded: {error}"))
}

fn export_request(store: &SharedStore, capture_id: &str) -> Result<CapturedRequest, String> {
    export_requests(store, &[capture_id.to_owned()]).map(|mut requests| requests.remove(0))
}

fn export_requests(
    store: &SharedStore,
    capture_ids: &[String],
) -> Result<Vec<CapturedRequest>, String> {
    let store = store
        .lock()
        .map_err(|_| "encrypted workspace is temporarily unavailable".to_owned())?;
    let store = store
        .as_ref()
        .ok_or_else(|| "encrypted workspace has not initialized".to_owned())?;
    capture_ids
        .iter()
        .map(|capture_id| {
            load_request(store, capture_id).map_err(|error| match error {
                DesktopApiError::MissingCapture(_) => {
                    format!("capture {capture_id} is unavailable for export")
                }
                other => other.to_string(),
            })
        })
        .collect()
}

fn validate_batch_capture_ids(capture_ids: &[String]) -> Result<(), String> {
    if capture_ids.is_empty() {
        return Err("batch export requires at least one capture".to_owned());
    }
    if capture_ids.len() > MAX_BATCH_EXPORT_REQUESTS {
        return Err(format!(
            "batch export supports at most {MAX_BATCH_EXPORT_REQUESTS} captures"
        ));
    }
    let mut unique = BTreeSet::new();
    for capture_id in capture_ids {
        if capture_id.is_empty() {
            return Err("batch export capture IDs cannot be empty".to_owned());
        }
        if !unique.insert(capture_id) {
            return Err(format!(
                "capture {capture_id} appears more than once in the batch export"
            ));
        }
    }
    Ok(())
}

fn write_batch_capture_export_file(
    store: &SharedStore,
    capture_ids: &[String],
    profile: ExportProfile,
    exported_at_unix_ms: u64,
    expected_sha256: &str,
    path: &Path,
) -> Result<ExportReceipt, String> {
    let preview = build_batch_capture_export(store, capture_ids, profile, exported_at_unix_ms)?;
    if preview.content_sha256 != expected_sha256 {
        return Err("a capture changed after preview; review the refreshed export".to_owned());
    }
    write_export_file(path, preview.content.as_bytes())?;
    Ok(ExportReceipt {
        path: path.to_string_lossy().into_owned(),
        byte_count: preview.byte_count,
        redaction_count: u64::try_from(preview.redactions.len()).unwrap_or(u64::MAX),
    })
}

fn current_unix_ms() -> Result<u64, String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
    u64::try_from(elapsed.as_millis()).map_err(|_| "system time is out of range".to_owned())
}

fn write_export_file(path: &Path, content: &[u8]) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_none_or(|extension| !extension.eq_ignore_ascii_case("json"))
    {
        return Err("capture exports require a new absolute .json path".to_owned());
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .map_err(|error| format!("capture export file could not be created: {error}"))?;
    file.write_all(content)
        .map_err(|error| format!("capture export file could not be written: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("capture export file could not be synced: {error}"))
}

async fn runtime_snapshot(app: &AppHandle, state: &DesktopState) -> RuntimeSnapshot {
    let mode = *state.mode.lock().await;
    let gateway_endpoint = state
        .gateway
        .lock()
        .await
        .as_ref()
        .map(|runtime| runtime.endpoint.clone());
    let (proxy_endpoint, system_proxy_active) =
        state
            .proxy
            .lock()
            .await
            .as_ref()
            .map_or((None, false), |runtime| {
                (
                    Some(runtime.endpoint.clone()),
                    runtime.system_proxy.is_some(),
                )
            });
    RuntimeSnapshot {
        mode,
        active: state.capture_active.load(Ordering::Acquire),
        proxy_available: state.sidecar_bundle.is_some(),
        gateway_endpoint,
        proxy_endpoint,
        system_proxy_active,
        certificate_authority: application_certificate_authority(app),
    }
}

fn apply_runtime_state(workspace: &mut WorkspaceBootstrap, snapshot: RuntimeSnapshot) {
    let (profile, endpoint) = match snapshot.mode {
        CaptureMode::Gateway => (
            "OpenAI-compatible local gateway",
            snapshot.gateway_endpoint.as_deref(),
        ),
        CaptureMode::Proxy => (
            if snapshot.system_proxy_active {
                "System-managed explicit TLS proxy"
            } else {
                "Manual explicit TLS proxy"
            },
            snapshot.proxy_endpoint.as_deref(),
        ),
    };
    workspace.capture.active = snapshot.active && endpoint.is_some();
    workspace.capture.can_control = endpoint.is_some();
    workspace.capture.proxy_available = snapshot.proxy_available;
    workspace.capture.mode = snapshot.mode;
    workspace.capture.profile = profile.to_owned();
    workspace.capture.endpoint = endpoint.unwrap_or("Not connected").to_owned();
    workspace.capture.certificate_authority = snapshot.certificate_authority;
}

fn application_certificate_authority(app: &AppHandle) -> CertificateAuthority {
    let confdir = match application_certificate_confdir(app) {
        Ok(path) => path,
        Err(error) => {
            return CertificateAuthority {
                state: CertificateAuthorityState::Invalid,
                can_manage_trust: false,
                fingerprint_sha256: None,
                subject: None,
                valid_from_unix_ms: None,
                valid_until_unix_ms: None,
                private_material: CertificatePrivateMaterial::Missing,
                trust: CertificateTrust::Unchecked,
                detail: Some(error),
            };
        }
    };
    let status = inspect_certificate_authority(confdir);
    CertificateAuthority {
        state: match status.state {
            SidecarCertificateAuthorityState::Missing => CertificateAuthorityState::Missing,
            SidecarCertificateAuthorityState::Ready => CertificateAuthorityState::Ready,
            SidecarCertificateAuthorityState::Invalid => CertificateAuthorityState::Invalid,
        },
        can_manage_trust: status.can_manage_trust,
        fingerprint_sha256: status.fingerprint_sha256,
        subject: status.subject,
        valid_from_unix_ms: status.valid_from_unix_ms,
        valid_until_unix_ms: status.valid_until_unix_ms,
        private_material: match status.private_material {
            SidecarPrivateMaterialState::Missing => CertificatePrivateMaterial::Missing,
            SidecarPrivateMaterialState::Restricted => CertificatePrivateMaterial::Restricted,
            SidecarPrivateMaterialState::Unchecked => CertificatePrivateMaterial::Unchecked,
            SidecarPrivateMaterialState::Insecure => CertificatePrivateMaterial::Insecure,
        },
        trust: match status.trust {
            SidecarCertificateTrustState::Unchecked => CertificateTrust::Unchecked,
            SidecarCertificateTrustState::Trusted => CertificateTrust::Trusted,
            SidecarCertificateTrustState::NotTrusted => CertificateTrust::NotTrusted,
            SidecarCertificateTrustState::Unsupported => CertificateTrust::Unsupported,
        },
        detail: status.detail,
    }
}

fn application_certificate_confdir(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join("mitmproxy"))
        .map_err(|error| format!("certificate directory is unavailable: {error}"))
}

fn application_proxy_recovery_journal(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|path| path.join("recovery").join(PROXY_RECOVERY_JOURNAL_FILENAME))
        .map_err(|error| format!("proxy recovery directory is unavailable: {error}"))
}

async fn ensure_proxy_recovery(app: &AppHandle, state: &DesktopState) -> Result<(), String> {
    if state.proxy_recovery_checked.load(Ordering::Acquire) {
        return Ok(());
    }
    let journal = application_proxy_recovery_journal(app)?;
    tauri::async_runtime::spawn_blocking(move || recover_from_journal(&journal))
        .await
        .map_err(|error| format!("proxy recovery task failed: {error}"))?
        .map_err(|error| error.to_string())?;
    state.proxy_recovery_checked.store(true, Ordering::Release);
    Ok(())
}

async fn ensure_gateway(app: &AppHandle, state: &DesktopState) -> Result<(), String> {
    let mode = *state.mode.lock().await;
    let capture_enabled =
        mode == CaptureMode::Gateway && state.capture_active.load(Ordering::Acquire);
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
    capture.set_enabled(capture_enabled);
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
        capture.clone(),
        state.capture_active.clone(),
        receiver,
    ));

    *runtime = Some(GatewayRuntime {
        capture,
        endpoint: format!("http://{address}"),
        shutdown: Some(shutdown),
    });
    Ok(())
}

async fn switch_capture_mode(
    app: &AppHandle,
    state: &DesktopState,
    requested: CaptureMode,
) -> Result<(), String> {
    let mut mode = state.mode.lock().await;
    if *mode == requested {
        return Ok(());
    }

    match requested {
        CaptureMode::Gateway => {
            let active = state.capture_active.load(Ordering::Acquire);
            let gateway = state.gateway.lock().await;
            let runtime = gateway
                .as_ref()
                .ok_or_else(|| "local AI gateway has not started".to_owned())?;
            runtime.capture.set_enabled(active);
            drop(gateway);
            *mode = CaptureMode::Gateway;
            stop_proxy(state).await?;
        }
        CaptureMode::Proxy => {
            ensure_proxy(app, state).await?;
            let gateway = state.gateway.lock().await;
            let runtime = gateway
                .as_ref()
                .ok_or_else(|| "local AI gateway has not started".to_owned())?;
            runtime.capture.set_enabled(false);
            *mode = CaptureMode::Proxy;
        }
    }
    Ok(())
}

async fn ensure_proxy(app: &AppHandle, state: &DesktopState) -> Result<(), String> {
    let mut runtime = state.proxy.lock().await;
    if let Some(runtime) = runtime.as_mut() {
        activate_system_proxy(app, runtime).await?;
        return Ok(());
    }

    let bundle = state
        .sidecar_bundle
        .clone()
        .ok_or_else(|| "verified explicit proxy bundle is unavailable".to_owned())?;
    let policy = CapturePolicy::load_default().map_err(|error| error.to_string())?;
    let target_hosts = policy
        .targets
        .iter()
        .flat_map(|target| target.hosts.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("capture IPC could not bind to loopback: {error}"))?;
    let ipc_addr = listener
        .local_addr()
        .map_err(|error| format!("capture IPC address is unavailable: {error}"))?;
    let listen_addr = reserve_loopback_address()?;
    let token = generate_ipc_token()?;
    let confdir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?
        .join("mitmproxy");
    let config =
        SidecarLaunchConfig::new(ipc_addr, token.clone(), target_hosts, listen_addr, confdir);
    let process = tauri::async_runtime::spawn_blocking(move || {
        bundle.launch(&config, SIDECAR_STARTUP_TIMEOUT)
    })
    .await
    .map_err(|error| format!("explicit proxy launch task failed: {error}"))?
    .map_err(|error| error.to_string())?;
    let endpoint = format!("http://{}", process.endpoint());
    let generation = state.next_proxy_generation.fetch_add(1, Ordering::Relaxed);
    let mut next_runtime = ProxyRuntime {
        generation,
        system_proxy: None,
        process: Some(process),
        endpoint: endpoint.clone(),
        shutdown: None,
    };
    activate_system_proxy(app, &mut next_runtime).await?;
    let (shutdown, shutdown_rx) = oneshot::channel();
    tauri::async_runtime::spawn(process_proxy_events(
        app.clone(),
        state.store.clone(),
        state.capture_active.clone(),
        listener,
        token,
        policy,
        shutdown_rx,
    ));
    next_runtime.shutdown = Some(shutdown);
    *runtime = Some(next_runtime);
    drop(runtime);
    tauri::async_runtime::spawn(monitor_proxy_process(app.clone(), generation));
    Ok(())
}

async fn stop_proxy(state: &DesktopState) -> Result<(), String> {
    let runtime = state.proxy.lock().await.take();
    if let Some(runtime) = runtime {
        tauri::async_runtime::spawn_blocking(move || runtime.shutdown())
            .await
            .map_err(|error| format!("explicit proxy shutdown task failed: {error}"))??;
    }
    Ok(())
}

async fn monitor_proxy_process(app: AppHandle, generation: u64) {
    let state = app.state::<DesktopState>();
    loop {
        tokio::time::sleep(SIDECAR_MONITOR_INTERVAL).await;
        let status = {
            let mut proxy = state.proxy.lock().await;
            let Some(runtime) = proxy.as_mut() else {
                return;
            };
            if runtime.generation != generation {
                return;
            }
            let Some(process) = runtime.process.as_mut() else {
                return;
            };
            process.try_wait()
        };
        let (code, mut detail) = match status {
            Ok(None) => continue,
            Ok(Some(status)) => (
                "sidecar_process_exited",
                format!("The explicit proxy process exited unexpectedly ({status})."),
            ),
            Err(error) => (
                "sidecar_process_monitor_failed",
                format!("The explicit proxy process could not be monitored: {error}"),
            ),
        };
        let Some(runtime) = take_failed_proxy_runtime(&state, generation).await else {
            return;
        };
        let restore = tauri::async_runtime::spawn_blocking(move || runtime.shutdown()).await;
        match restore {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                detail.push_str(&format!(
                    " Original system proxy restoration failed: {error}"
                ));
            }
            Err(error) => {
                detail.push_str(&format!(" Proxy shutdown task failed: {error}"));
            }
        }
        emit_runtime_error(&app, code, detail);
        return;
    }
}

async fn take_failed_proxy_runtime(state: &DesktopState, generation: u64) -> Option<ProxyRuntime> {
    let runtime = {
        let mut proxy = state.proxy.lock().await;
        if proxy.as_ref().map(|runtime| runtime.generation) != Some(generation) {
            return None;
        }
        proxy.take()
    };
    let mut mode = state.mode.lock().await;
    if *mode == CaptureMode::Proxy {
        *mode = CaptureMode::Gateway;
        let gateway = state.gateway.lock().await;
        if let Some(gateway) = gateway.as_ref() {
            gateway
                .capture
                .set_enabled(state.capture_active.load(Ordering::Acquire));
        }
    }
    runtime
}

#[cfg(windows)]
async fn activate_system_proxy(app: &AppHandle, runtime: &mut ProxyRuntime) -> Result<(), String> {
    if runtime.system_proxy.is_some() {
        return Ok(());
    }
    let certificate = application_certificate_authority(app);
    if certificate.state != CertificateAuthorityState::Ready
        || certificate.trust != CertificateTrust::Trusted
    {
        return Ok(());
    }
    let desired = system_proxy_settings(&runtime.endpoint);
    let journal = application_proxy_recovery_journal(app)?;
    let watchdog = std::env::current_exe()
        .map_err(|error| format!("proxy watchdog executable is unavailable: {error}"))?;
    let session = tauri::async_runtime::spawn_blocking(move || {
        begin_platform_proxy_session(desired, journal, watchdog)
    })
    .await
    .map_err(|error| format!("system proxy task failed: {error}"))??;
    runtime.system_proxy = Some(session);
    Ok(())
}

#[cfg(not(windows))]
async fn activate_system_proxy(
    _app: &AppHandle,
    _runtime: &mut ProxyRuntime,
) -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
fn system_proxy_settings(endpoint: &str) -> ProxySettings {
    ProxySettings::Manual {
        http_proxy: endpoint.to_owned(),
        https_proxy: endpoint.to_owned(),
        bypass: system_proxy_bypass(),
    }
}

#[cfg(windows)]
fn system_proxy_bypass() -> Vec<String> {
    vec![
        "<local>".to_owned(),
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ]
}

#[cfg(windows)]
fn begin_platform_proxy_session(
    desired: ProxySettings,
    journal: PathBuf,
    watchdog: PathBuf,
) -> Result<PlatformProxySession, String> {
    ProxySession::begin(WindowsProxyBackend::system(), desired, journal, watchdog)
        .map(PlatformProxySession::Windows)
        .map_err(|error| error.to_string())
}

fn reserve_loopback_address() -> Result<SocketAddr, String> {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("explicit proxy could not reserve a loopback port: {error}"))?;
    listener
        .local_addr()
        .map_err(|error| format!("explicit proxy address is unavailable: {error}"))
}

fn generate_ipc_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| "secure randomness for capture IPC is unavailable".to_owned())?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(token)
}

async fn process_proxy_events(
    app: AppHandle,
    store: SharedStore,
    capture_active: Arc<AtomicBool>,
    listener: TcpListener,
    token: String,
    policy: CapturePolicy,
    mut shutdown: oneshot::Receiver<()>,
) {
    let adapters = AdapterRegistry::default();
    let mut captures_since_retention = 0_usize;
    loop {
        let result = tokio::select! {
            _ = &mut shutdown => break,
            result = receive_and_persist_proxy_capture(
                &listener,
                &token,
                &policy,
                &adapters,
                &store,
                &capture_active,
            ) => result,
        };
        match result {
            Ok(Some(capture_id)) => {
                captures_since_retention += 1;
                emit_capture_updated(&app, capture_id);
                if captures_since_retention >= CAPTURES_PER_RETENTION_RUN {
                    captures_since_retention = 0;
                    let maintenance = store
                        .lock()
                        .map_err(|_| ProxyCaptureError::StoreUnavailable)
                        .and_then(|mut store| {
                            maintain_store(
                                store
                                    .as_mut()
                                    .ok_or(ProxyCaptureError::StoreUninitialized)?,
                            )
                            .map_err(ProxyCaptureError::Storage)
                        });
                    if let Err(error) = maintenance {
                        apply_proxy_error_policy(&capture_active, &app, &error);
                    }
                }
            }
            Ok(None) => {}
            Err(error) => {
                apply_proxy_error_policy(&capture_active, &app, &error);
                if matches!(error, ProxyCaptureError::Ingest(_)) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

async fn receive_and_persist_proxy_capture(
    listener: &TcpListener,
    token: &str,
    policy: &CapturePolicy,
    adapters: &AdapterRegistry,
    store: &SharedStore,
    capture_active: &AtomicBool,
) -> Result<Option<String>, ProxyCaptureError> {
    let capture = ingest_one(listener, token, policy).await?;
    if !capture_active.load(Ordering::Acquire) {
        return Ok(None);
    }
    let capture_id = capture.envelope().capture_id.clone();
    let parsed = adapters.parse(&capture);
    let mut store = store
        .lock()
        .map_err(|_| ProxyCaptureError::StoreUnavailable)?;
    let store = store
        .as_mut()
        .ok_or(ProxyCaptureError::StoreUninitialized)?;
    persist_capture(store, &capture, parsed.prompt_ir.as_ref())?;
    Ok(Some(capture_id))
}

fn apply_proxy_error_policy(
    capture_active: &AtomicBool,
    app: &AppHandle,
    error: &ProxyCaptureError,
) {
    let code = match error {
        ProxyCaptureError::Storage(storage) if storage.is_disk_pressure() => {
            capture_active.store(false, Ordering::Release);
            "capture_disk_pressure"
        }
        ProxyCaptureError::Ingest(_) => "proxy_ipc_rejected",
        ProxyCaptureError::StoreUnavailable | ProxyCaptureError::StoreUninitialized => {
            "capture_store_unavailable"
        }
        ProxyCaptureError::Storage(_) => "capture_processing_failed",
    };
    emit_runtime_error(app, code, error.to_string());
}

async fn process_capture_events(
    app: AppHandle,
    store: SharedStore,
    capture: GatewayCapture,
    capture_active: Arc<AtomicBool>,
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
    let mut pending = HashMap::<String, GatewayCaptureEvent>::new();
    let mut captures_since_retention = 0_usize;

    while let Some(event) = receiver.recv().await {
        let mut ready = VecDeque::from([event]);
        while let Some(event) = ready.pop_front() {
            let retry_event = event.clone();
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
                    captures_since_retention += 1;
                    if captures_since_retention >= CAPTURES_PER_RETENTION_RUN {
                        captures_since_retention = 0;
                        let maintenance = store
                            .lock()
                            .map_err(|_| {
                                "encrypted workspace is temporarily unavailable".to_owned()
                            })
                            .and_then(|mut store| {
                                maintain_store(store.as_mut().ok_or_else(|| {
                                    "encrypted workspace has not initialized".to_owned()
                                })?)
                                .map_err(|error| error.to_string())
                            });
                        if let Err(detail) = maintenance {
                            emit_runtime_error(&app, "capture_retention_failed", detail);
                        }
                    }
                    emit_capture_updated(&app, capture.capture_id.clone());
                    if let Some(outcome) = pending.remove(&capture.capture_id) {
                        ready.push_back(outcome);
                    }
                }
                Ok(GatewayCaptureOutcome::ResponseObserved(response)) => {
                    if response.persisted {
                        emit_capture_updated(&app, response.capture_id);
                    } else if !queue_pending_outcome(&mut pending, retry_event) {
                        emit_runtime_error(
                            &app,
                            "capture_pending_overflow",
                            "too many capture outcomes arrived before their requests".to_owned(),
                        );
                    }
                }
                Ok(GatewayCaptureOutcome::UpstreamFailed(failure)) => {
                    if failure.persisted {
                        emit_capture_updated(&app, failure.capture_id);
                    } else if !queue_pending_outcome(&mut pending, retry_event) {
                        emit_runtime_error(
                            &app,
                            "capture_pending_overflow",
                            "too many capture outcomes arrived before their requests".to_owned(),
                        );
                    }
                }
                Err(error) => {
                    let code = apply_capture_error_policy(&capture, &capture_active, &error);
                    emit_runtime_error(&app, code, error.to_string());
                }
            }
        }
    }
}

fn maintain_store(store: &mut EncryptedStore) -> Result<RetentionReport, StorageError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::NumericOutOfRange)?;
    let now_unix_ms =
        u64::try_from(elapsed.as_millis()).map_err(|_| StorageError::NumericOutOfRange)?;
    store.enforce_retention(&RetentionPolicy::default(), now_unix_ms)
}

fn apply_capture_error_policy(
    capture: &GatewayCapture,
    capture_active: &AtomicBool,
    error: &GatewayCaptureError,
) -> &'static str {
    if matches!(
        error,
        GatewayCaptureError::Storage(storage) if storage.is_disk_pressure()
    ) {
        capture.set_enabled(false);
        capture_active.store(false, Ordering::Release);
        "capture_disk_pressure"
    } else {
        "capture_processing_failed"
    }
}

fn queue_pending_outcome(
    pending: &mut HashMap<String, GatewayCaptureEvent>,
    event: GatewayCaptureEvent,
) -> bool {
    let capture_id = match &event {
        GatewayCaptureEvent::Request(_) => return false,
        GatewayCaptureEvent::Response(response) => response.capture_id.clone(),
        GatewayCaptureEvent::UpstreamFailure(failure) => failure.capture_id.clone(),
    };
    if pending.len() >= MAX_PENDING_CAPTURE_OUTCOMES && !pending.contains_key(&capture_id) {
        return false;
    }
    pending.insert(capture_id, event);
    true
}

fn emit_capture_updated(app: &AppHandle, capture_id: String) {
    let _ = app.emit(CAPTURE_UPDATED_EVENT, CaptureUpdated { capture_id });
}

fn emit_runtime_error(app: &AppHandle, code: &'static str, detail: String) {
    let _ = app.emit(
        CAPTURE_RUNTIME_ERROR_EVENT,
        CaptureRuntimeError { code, detail },
    );
}

fn emit_sidecar_error_once(app: &AppHandle, state: &DesktopState) {
    let detail = state
        .sidecar_error
        .lock()
        .ok()
        .and_then(|mut error| error.take());
    if let Some(detail) = detail {
        emit_runtime_error(app, "sidecar_bundle_invalid", detail);
    }
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
    use codeischeap_capture_ipc::{
        CaptureOutcome, CapturedBody, CapturedBodyState, CapturedResponse, ResponseCompleteness,
    };
    use codeischeap_gateway::{CapturedPayload, GatewayResponseCapture};
    use codeischeap_storage::DatabaseKey;
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

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
        apply_runtime_state(
            &mut workspace,
            RuntimeSnapshot {
                mode: CaptureMode::Gateway,
                active: false,
                proxy_available: true,
                gateway_endpoint: Some("http://127.0.0.1:8787".to_owned()),
                proxy_endpoint: None,
                system_proxy_active: false,
                certificate_authority: CertificateAuthority::missing(),
            },
        );

        assert!(!workspace.capture.active);
        assert!(workspace.capture.can_control);
        assert!(workspace.capture.proxy_available);
        assert_eq!(workspace.capture.mode, CaptureMode::Gateway);
        assert_eq!(workspace.capture.endpoint, "http://127.0.0.1:8787");
        assert_eq!(workspace.capture.profile, "OpenAI-compatible local gateway");
    }

    #[test]
    fn proxy_runtime_controls_workspace_capture_state() {
        let directory = tempdir().expect("temp directory must be created");
        let store = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x64; 32]),
        )
        .expect("encrypted store must open");
        let mut workspace = load_workspace(&store).expect("workspace must load");
        let certificate_authority = CertificateAuthority {
            state: CertificateAuthorityState::Ready,
            can_manage_trust: true,
            fingerprint_sha256: Some("AA:BB:CC:DD".to_owned()),
            subject: Some("mitmproxy".to_owned()),
            valid_from_unix_ms: Some(1_577_836_800_000),
            valid_until_unix_ms: Some(4_070_908_800_000),
            private_material: CertificatePrivateMaterial::Unchecked,
            trust: CertificateTrust::Unchecked,
            detail: None,
        };

        apply_runtime_state(
            &mut workspace,
            RuntimeSnapshot {
                mode: CaptureMode::Proxy,
                active: true,
                proxy_available: true,
                gateway_endpoint: Some("http://127.0.0.1:8787".to_owned()),
                proxy_endpoint: Some("http://127.0.0.1:43125".to_owned()),
                system_proxy_active: true,
                certificate_authority: certificate_authority.clone(),
            },
        );

        assert!(workspace.capture.active);
        assert!(workspace.capture.can_control);
        assert!(workspace.capture.proxy_available);
        assert_eq!(workspace.capture.mode, CaptureMode::Proxy);
        assert_eq!(workspace.capture.endpoint, "http://127.0.0.1:43125");
        assert_eq!(
            workspace.capture.profile,
            "System-managed explicit TLS proxy"
        );
        assert_eq!(
            workspace.capture.certificate_authority,
            certificate_authority
        );
    }

    #[cfg(windows)]
    #[test]
    fn system_proxy_settings_use_the_verified_loopback_endpoint() {
        let settings = system_proxy_settings("http://127.0.0.1:43125");
        assert_eq!(
            settings,
            ProxySettings::Manual {
                http_proxy: "http://127.0.0.1:43125".to_owned(),
                https_proxy: "http://127.0.0.1:43125".to_owned(),
                bypass: vec![
                    "<local>".to_owned(),
                    "localhost".to_owned(),
                    "127.0.0.1".to_owned(),
                    "::1".to_owned(),
                ],
            }
        );
    }

    #[test]
    fn ipc_tokens_are_random_fixed_width_hex() {
        let first = generate_ipc_token().expect("first IPC token must generate");
        let second = generate_ipc_token().expect("second IPC token must generate");

        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn sidecar_resources_follow_the_tauri_bundle_layout() {
        let resource_dir = Path::new("application-resources");
        let manifest_dir = Path::new("src-tauri");

        assert_eq!(
            sidecar_resource_path(resource_dir, manifest_dir, true),
            manifest_dir.join("resources").join("sidecar")
        );
        assert_eq!(
            sidecar_resource_path(resource_dir, manifest_dir, false),
            resource_dir.join("resources").join("sidecar")
        );
    }

    #[test]
    fn invalid_sidecar_degrades_without_blocking_the_workspace() {
        let (bundle, error) = optional_sidecar::<(), _>(Err("manifest mismatch"));

        assert!(bundle.is_none());
        assert_eq!(error.as_deref(), Some("manifest mismatch"));
    }

    #[tokio::test]
    async fn authenticated_proxy_ipc_persists_outcomes_and_pause_discards_events() {
        let directory = tempdir().expect("temp directory must be created");
        let store = Arc::new(Mutex::new(Some(
            EncryptedStore::open(
                directory.path().join("captures.db"),
                DatabaseKey::from_bytes([0x65; 32]),
            )
            .expect("encrypted store must open"),
        )));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("IPC listener must bind");
        let address = listener.local_addr().expect("IPC address must exist");
        let token = generate_ipc_token().expect("IPC token must generate");
        let policy = CapturePolicy::load_default().expect("capture policy must load");
        let adapters = AdapterRegistry::default();
        let active = AtomicBool::new(true);
        let request: CaptureEnvelope = serde_json::from_str(include_str!(
            "../../../../crates/capture-ipc/tests/fixtures/mitmproxy-request.json"
        ))
        .expect("request fixture must parse");

        send_ipc_capture(address, &token, &request).await;
        assert_eq!(
            receive_and_persist_proxy_capture(
                &listener, &token, &policy, &adapters, &store, &active,
            )
            .await
            .expect("request must persist"),
            Some(request.capture_id.clone())
        );

        let mut response = request.clone();
        response.outcome = Some(CaptureOutcome::Response(CapturedResponse {
            status: 200,
            headers: Vec::new(),
            body: CapturedBody {
                state: CapturedBodyState::Json,
                content: Some(serde_json::json!({"ok": true})),
            },
            duration_ms: 42,
            completeness: ResponseCompleteness::Complete,
        }));
        send_ipc_capture(address, &token, &response).await;
        receive_and_persist_proxy_capture(&listener, &token, &policy, &adapters, &store, &active)
            .await
            .expect("response must persist");

        active.store(false, Ordering::Release);
        let mut paused = request.clone();
        paused.capture_id = "paused_capture".to_owned();
        send_ipc_capture(address, &token, &paused).await;
        assert_eq!(
            receive_and_persist_proxy_capture(
                &listener, &token, &policy, &adapters, &store, &active,
            )
            .await
            .expect("paused event must be accepted and discarded"),
            None
        );

        let store = store.lock().expect("store lock must be available");
        let workspace = load_workspace(store.as_ref().expect("store must be initialized"))
            .expect("workspace must load");
        assert_eq!(workspace.capture.request_count, 1);
        assert_eq!(workspace.requests[0].duration_ms, Some(42));
        assert_eq!(
            workspace.requests[0].status,
            codeischeap_desktop_api::CaptureStatus::Complete
        );
    }

    async fn send_ipc_capture(address: SocketAddr, token: &str, envelope: &CaptureEnvelope) {
        let mut stream = TcpStream::connect(address)
            .await
            .expect("IPC client must connect");
        let auth = serde_json::json!({
            "protocol": "codeischeap.capture-ipc",
            "version": "0.1",
            "token": token,
        });
        stream
            .write_all(format!("{auth}\n{}\n", serde_json::to_string(envelope).unwrap()).as_bytes())
            .await
            .expect("IPC frames must write");
        stream.shutdown().await.expect("IPC client must close");
    }

    #[test]
    fn pending_outcomes_are_keyed_replaced_and_bounded() {
        let mut pending = HashMap::new();
        for index in 0..MAX_PENDING_CAPTURE_OUTCOMES {
            assert!(queue_pending_outcome(
                &mut pending,
                response_event(&format!("capture_{index}"), 200)
            ));
        }
        assert_eq!(pending.len(), MAX_PENDING_CAPTURE_OUTCOMES);
        assert!(queue_pending_outcome(
            &mut pending,
            response_event("capture_0", 429)
        ));
        assert!(!queue_pending_outcome(
            &mut pending,
            response_event("overflow", 200)
        ));
        let GatewayCaptureEvent::Response(replaced) = pending
            .get("capture_0")
            .expect("existing outcome must remain")
        else {
            panic!("pending event must be a response");
        };
        assert_eq!(replaced.status, 429);
    }

    fn response_event(capture_id: &str, status: u16) -> GatewayCaptureEvent {
        GatewayCaptureEvent::Response(GatewayResponseCapture {
            capture_id: capture_id.to_owned(),
            status,
            headers: Vec::new(),
            duration_ms: 1,
            body: CapturedPayload {
                bytes: Vec::new().into(),
                truncated: false,
                complete: true,
            },
        })
    }

    #[tokio::test]
    async fn failed_proxy_runtime_returns_to_gateway_and_ignores_stale_monitors() {
        let (capture, _receiver, _) = GatewayCapture::defaults();
        capture.set_enabled(false);
        let state = DesktopState {
            store: Arc::new(Mutex::new(None)),
            gateway: AsyncMutex::new(Some(GatewayRuntime {
                capture: capture.clone(),
                endpoint: "http://127.0.0.1:8787".to_owned(),
                shutdown: None,
            })),
            proxy: AsyncMutex::new(Some(ProxyRuntime {
                generation: 7,
                system_proxy: None,
                process: None,
                endpoint: "http://127.0.0.1:43125".to_owned(),
                shutdown: None,
            })),
            mode: AsyncMutex::new(CaptureMode::Proxy),
            capture_active: Arc::new(AtomicBool::new(true)),
            next_proxy_generation: AtomicU64::new(8),
            proxy_recovery_checked: AtomicBool::new(true),
            sidecar_bundle: None,
            sidecar_error: Mutex::new(None),
        };

        assert!(take_failed_proxy_runtime(&state, 6).await.is_none());
        assert_eq!(*state.mode.lock().await, CaptureMode::Proxy);
        assert!(state.proxy.lock().await.is_some());

        let runtime = take_failed_proxy_runtime(&state, 7)
            .await
            .expect("current failed runtime must be removed");
        assert_eq!(*state.mode.lock().await, CaptureMode::Gateway);
        assert!(state.proxy.lock().await.is_none());
        assert!(capture.is_enabled());
        runtime.shutdown().expect("empty runtime must shut down");
    }

    #[test]
    fn export_files_are_new_json_documents_and_never_overwrite() {
        let directory = tempdir().expect("export directory");
        let path = directory.path().join("capture.json");

        write_export_file(&path, b"{\"safe\":true}\n").expect("new export must write");
        assert_eq!(
            std::fs::read(&path).expect("export must be readable"),
            b"{\"safe\":true}\n"
        );
        assert!(write_export_file(&path, b"replacement").is_err());
        assert!(write_export_file(&directory.path().join("capture.txt"), b"{}").is_err());
    }

    #[test]
    fn batch_export_rejects_invalid_capture_lists() {
        assert!(validate_batch_capture_ids(&[]).is_err());
        assert!(validate_batch_capture_ids(&[String::new()]).is_err());
        assert!(
            validate_batch_capture_ids(&["capture-1".to_owned(), "capture-1".to_owned()]).is_err()
        );
        assert!(
            validate_batch_capture_ids(
                &(0..=MAX_BATCH_EXPORT_REQUESTS)
                    .map(|index| format!("capture-{index}"))
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
    }

    #[test]
    fn batch_export_rejects_missing_captures() {
        let directory = tempdir().expect("temp directory must be created");
        let store = Arc::new(Mutex::new(Some(
            EncryptedStore::open(
                directory.path().join("captures.db"),
                DatabaseKey::from_bytes([0x66; 32]),
            )
            .expect("encrypted store must open"),
        )));

        let error = build_batch_capture_export(
            &store,
            &["missing-capture".to_owned()],
            ExportProfile::Minimal,
            10,
        )
        .expect_err("missing capture must reject the entire batch");

        assert!(error.contains("missing-capture"));
    }

    #[test]
    fn batch_export_hash_mismatch_does_not_create_a_file() {
        let directory = tempdir().expect("temp directory must be created");
        let mut encrypted = EncryptedStore::open(
            directory.path().join("captures.db"),
            DatabaseKey::from_bytes([0x67; 32]),
        )
        .expect("encrypted store must open");
        seed_demo_capture(&mut encrypted).expect("demo capture must seed");
        let store = Arc::new(Mutex::new(Some(encrypted)));
        let path = directory.path().join("batch.json");

        let error = write_batch_capture_export_file(
            &store,
            &[LEGACY_DEMO_CAPTURE_ID.to_owned()],
            ExportProfile::Forensic,
            10,
            &"0".repeat(64),
            &path,
        )
        .expect_err("stale preview hash must reject the write");

        assert!(error.contains("changed after preview"));
        assert!(!path.exists());
    }

    #[test]
    fn disk_pressure_pauses_capture_without_stopping_the_gateway() {
        let (capture, receiver, _) = GatewayCapture::defaults();
        let active = AtomicBool::new(true);
        assert!(capture.is_enabled());

        let code = apply_capture_error_policy(
            &capture,
            &active,
            &GatewayCaptureError::Storage(StorageError::DiskFull),
        );

        assert_eq!(code, "capture_disk_pressure");
        assert!(!capture.is_enabled());
        assert!(!active.load(Ordering::Acquire));
        assert!(
            !receiver.is_closed(),
            "the gateway event channel remains alive"
        );
    }
}
