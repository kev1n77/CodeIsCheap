import { useEffect, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Copy,
  Download,
  LoaderCircle,
  Network,
  Pause,
  Play,
  RotateCcw,
  RefreshCw,
  Save,
  ShieldCheck,
  SlidersHorizontal,
  Stethoscope,
  UploadCloud,
  X,
} from "lucide-react";
import type {
  BetaMetricsPreview,
  CaptureMode,
  CaptureProfile,
  CertificateAuthority,
  SupportBundlePreview,
  UpdateStatus,
  WorkspaceBootstrap,
} from "./types";
import {
  checkForUpdate,
  installUpdate,
  previewBetaMetrics,
  previewSupportBundle,
  saveBetaMetrics,
  saveSupportBundle,
  subscribeToUpdateProgress,
  type UpdateDownloadProgress,
} from "./workspace";
import { handleTabListKeyDown, useModalDialog } from "./accessibility";

type SettingsTab = "connection" | "profiles" | "metrics" | "diagnostics" | "updates";

export function SettingsDialog({ workspace, active, runtimeError, certificateError, modeChanging, certificateChanging, onToggleCapture, onModeChange, onCaptureProfileChange, onCertificateTrustChange, onClose }: {
  workspace: WorkspaceBootstrap;
  active: boolean;
  runtimeError: string;
  certificateError: string;
  modeChanging: boolean;
  certificateChanging: boolean;
  onToggleCapture: () => void;
  onModeChange: (mode: CaptureMode) => void;
  onCaptureProfileChange: (profile: CaptureProfile) => Promise<CaptureProfile>;
  onCertificateTrustChange: (trusted: boolean) => void;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<SettingsTab>("connection");
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  const [supportPreview, setSupportPreview] = useState<SupportBundlePreview | null>(null);
  const [supportError, setSupportError] = useState("");
  const [supportSaving, setSupportSaving] = useState(false);
  const [supportSavedPath, setSupportSavedPath] = useState("");
  const [metricsPreview, setMetricsPreview] = useState<BetaMetricsPreview | null>(null);
  const [metricsError, setMetricsError] = useState("");
  const [metricsSaving, setMetricsSaving] = useState(false);
  const [metricsSavedPath, setMetricsSavedPath] = useState("");
  const [metricsCopied, setMetricsCopied] = useState(false);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);
  const [updateProgress, setUpdateProgress] = useState<UpdateDownloadProgress | null>(null);
  const [updateChecking, setUpdateChecking] = useState(false);
  const [updateInstalling, setUpdateInstalling] = useState(false);
  const [updateError, setUpdateError] = useState("");
  const [profileName, setProfileName] = useState(workspace.captureProfile.name);
  const [profileGateway, setProfileGateway] = useState(workspace.captureProfile.gatewayUpstream);
  const [profileHosts, setProfileHosts] = useState(workspace.captureProfile.additionalHosts.join("\n"));
  const [profileSaving, setProfileSaving] = useState(false);
  const [profileError, setProfileError] = useState("");
  const [profileSaved, setProfileSaved] = useState(false);
  const { dialogRef, initialFocusRef } = useModalDialog(onClose);
  const certificate = workspace.capture.certificateAuthority;
  const compatibility = workspace.compatibility;
  const recoveryMode = workspace.source === "recovery_backup";
  const canTrust = certificate.canManageTrust
    && certificate.state === "ready"
    && certificate.trust === "not_trusted";
  const canRemoveTrust = certificate.canManageTrust && certificate.trust === "trusted";
  const profileDraft = captureProfileDraft(
    workspace.captureProfile.version,
    profileName,
    profileGateway,
    profileHosts,
  );
  const profileValidationError = validateCaptureProfileDraft(profileDraft);
  const profileDirty = !captureProfilesEqual(profileDraft, workspace.captureProfile);
  const profileReady = !recoveryMode
    && workspace.capture.canControl
    && workspace.capture.mode === "gateway"
    && !active;
  const canSaveProfile = profileReady
    && profileDirty
    && !profileValidationError
    && !profileSaving;

  useEffect(() => {
    if (tab !== "metrics") return;
    let cancelled = false;
    setMetricsPreview(null);
    setMetricsError("");
    setMetricsSavedPath("");
    setMetricsCopied(false);
    previewBetaMetrics()
      .then((preview) => { if (!cancelled) setMetricsPreview(preview); })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setMetricsError(
            reason instanceof Error ? reason.message : "Beta metrics could not be generated.",
          );
        }
      });
    return () => { cancelled = true; };
  }, [tab]);

  useEffect(() => {
    if (tab !== "diagnostics") return;
    let cancelled = false;
    setSupportPreview(null);
    setSupportError("");
    setSupportSavedPath("");
    setCopied(false);
    setCopyError("");
    previewSupportBundle(workspace, runtimeError || null)
      .then((preview) => { if (!cancelled) setSupportPreview(preview); })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setSupportError(
            reason instanceof Error ? reason.message : "Support bundle could not be generated.",
          );
        }
      });
    return () => { cancelled = true; };
  }, [runtimeError, tab, workspace]);

  useEffect(() => {
    if (tab !== "updates") return;
    let cancelled = false;
    let unlisten = () => {};
    subscribeToUpdateProgress((progress) => {
      if (!cancelled) setUpdateProgress(progress);
    }).then((dispose) => {
      if (cancelled) dispose();
      else unlisten = dispose;
    }).catch((reason: unknown) => {
      if (!cancelled) {
        setUpdateError(reason instanceof Error ? reason.message : "Update progress is unavailable.");
      }
    });
    return () => {
      cancelled = true;
      unlisten();
    };
  }, [tab]);

  const copyReport = async () => {
    if (!supportPreview) return;
    try {
      await navigator.clipboard.writeText(supportPreview.content);
      setCopied(true);
      setCopyError("");
    } catch {
      setCopyError("Diagnostic report could not be copied.");
    }
  };

  const saveBundle = () => {
    if (!supportPreview || supportSaving || supportSavedPath) return;
    setSupportSaving(true);
    setSupportError("");
    saveSupportBundle(runtimeError || null, supportPreview)
      .then((receipt) => { if (receipt) setSupportSavedPath(receipt.path); })
      .catch((reason: unknown) => {
        setSupportError(
          reason instanceof Error ? reason.message : "Support bundle could not be written.",
        );
      })
      .finally(() => setSupportSaving(false));
  };

  const copyMetrics = async () => {
    if (!metricsPreview) return;
    try {
      await navigator.clipboard.writeText(metricsPreview.content);
      setMetricsCopied(true);
      setMetricsError("");
    } catch {
      setMetricsError("Beta metrics could not be copied.");
    }
  };

  const saveMetrics = () => {
    if (!metricsPreview || metricsSaving || metricsSavedPath) return;
    setMetricsSaving(true);
    setMetricsError("");
    saveBetaMetrics(metricsPreview)
      .then((receipt) => { if (receipt) setMetricsSavedPath(receipt.path); })
      .catch((reason: unknown) => {
        setMetricsError(
          reason instanceof Error ? reason.message : "Beta metrics could not be written.",
        );
      })
      .finally(() => setMetricsSaving(false));
  };

  const checkUpdates = () => {
    if (updateChecking || updateInstalling) return;
    setUpdateChecking(true);
    setUpdateError("");
    setUpdateProgress(null);
    setUpdateStatus(null);
    checkForUpdate()
      .then(setUpdateStatus)
      .catch((reason: unknown) => {
        setUpdateError(reason instanceof Error ? reason.message : "Signed updates could not be checked.");
      })
      .finally(() => setUpdateChecking(false));
  };

  const installAvailableUpdate = () => {
    if (!updateStatus?.availableVersion || updateInstalling) return;
    setUpdateInstalling(true);
    setUpdateError("");
    setUpdateProgress({ downloadedBytes: 0, totalBytes: null, finished: false });
    installUpdate(updateStatus.availableVersion)
      .catch((reason: unknown) => {
        setUpdateError(reason instanceof Error ? reason.message : "Signed update installation failed.");
        setUpdateInstalling(false);
      });
  };

  const restoreDefaultProfile = () => {
    setProfileName("OpenAI default");
    setProfileGateway("https://api.openai.com");
    setProfileHosts("");
    setProfileError("");
    setProfileSaved(false);
  };

  const saveProfile = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canSaveProfile) return;
    setProfileSaving(true);
    setProfileError("");
    setProfileSaved(false);
    onCaptureProfileChange(profileDraft)
      .then((profile) => {
        setProfileName(profile.name);
        setProfileGateway(profile.gatewayUpstream);
        setProfileHosts(profile.additionalHosts.join("\n"));
        setProfileSaved(true);
      })
      .catch((reason: unknown) => {
        setProfileError(
          reason instanceof Error ? reason.message : "Capture Profile could not be saved.",
        );
      })
      .finally(() => setProfileSaving(false));
  };

  return (
    <div className="dialog-backdrop">
      <section ref={dialogRef} className="settings-dialog" role="dialog" aria-modal="true" aria-labelledby="settings-title" tabIndex={-1}>
        <header>
          <div><span className="dialog-eyebrow">Local workspace</span><h2 id="settings-title">Settings & diagnostics</h2></div>
          <button ref={initialFocusRef} className="icon-button" title="Close settings" aria-label="Close settings" onClick={onClose}><X size={17} /></button>
        </header>
        <div className="settings-tabs" role="tablist" aria-label="Settings views" onKeyDown={handleTabListKeyDown}>
          <button id="settings-tab-connection" role="tab" aria-controls="settings-panel-connection" aria-selected={tab === "connection"} tabIndex={tab === "connection" ? 0 : -1} onClick={() => setTab("connection")}><Network size={14} />Connection</button>
          <button id="settings-tab-profiles" role="tab" aria-controls="settings-panel-profiles" aria-selected={tab === "profiles"} tabIndex={tab === "profiles" ? 0 : -1} onClick={() => setTab("profiles")}><SlidersHorizontal size={14} />Profiles</button>
          <button id="settings-tab-metrics" role="tab" aria-controls="settings-panel-metrics" aria-selected={tab === "metrics"} tabIndex={tab === "metrics" ? 0 : -1} onClick={() => setTab("metrics")}><BarChart3 size={14} />Metrics</button>
          <button id="settings-tab-diagnostics" role="tab" aria-controls="settings-panel-diagnostics" aria-selected={tab === "diagnostics"} tabIndex={tab === "diagnostics" ? 0 : -1} onClick={() => setTab("diagnostics")}><Stethoscope size={14} />Diagnostics</button>
          <button id="settings-tab-updates" role="tab" aria-controls="settings-panel-updates" aria-selected={tab === "updates"} tabIndex={tab === "updates" ? 0 : -1} onClick={() => setTab("updates")}><UploadCloud size={14} />Updates</button>
        </div>
        {tab === "connection" && <div id="settings-panel-connection" className="settings-content" role="tabpanel" aria-labelledby="settings-tab-connection" tabIndex={0}>
          <section className="settings-band">
            <div><span>Capture mode</span><strong>{workspace.capture.mode === "gateway" ? "Local Gateway" : "Explicit TLS proxy"}</strong><small>{workspace.capture.endpoint}</small></div>
            <div className="segmented-control settings-mode" aria-label="Settings capture mode">
              <button aria-pressed={workspace.capture.mode === "gateway"} disabled={!workspace.capture.canControl || modeChanging} onClick={() => onModeChange("gateway")}><Network size={14} />Gateway</button>
              <button aria-pressed={workspace.capture.mode === "proxy"} disabled={!workspace.capture.canControl || !workspace.capture.proxyAvailable || modeChanging} onClick={() => onModeChange("proxy")}><ShieldCheck size={14} />Proxy</button>
            </div>
          </section>
          <section className="settings-band">
            <div><span>Recording</span><strong>{active ? "Capturing requests" : "Capture paused"}</strong><small>{workspace.capture.requestCount === 0 ? "Waiting for the first request" : `${workspace.capture.requestCount} requests stored locally`}</small></div>
            <button className="settings-command" disabled={!workspace.capture.canControl} onClick={onToggleCapture}>{active ? <Pause size={14} /> : <Play size={14} />}{active ? "Pause" : "Resume"}</button>
          </section>
          <section className="settings-band">
            <div><span>Local certificate authority</span><strong>{certificateLabel(certificate)}</strong><small className={certificateError ? "settings-error" : undefined}>{certificateError || certificate.detail || certificate.fingerprintSha256 || "No local CA material"}</small></div>
            {(canTrust || canRemoveTrust) && compatibility.action !== "trust_certificate" && <button className="settings-command" disabled={certificateChanging} onClick={() => onCertificateTrustChange(canTrust)}>{certificateChanging ? <LoaderCircle className="is-spinning" size={14} /> : <ShieldCheck size={14} />}{canTrust ? "Trust CA" : "Remove trust"}</button>}
          </section>
          <section className={`compatibility-diagnostic compatibility-${compatibility.status}`} aria-labelledby="compatibility-title">
            <header>
              <div>
                <span>Compatibility</span>
                <strong id="compatibility-title">{compatibility.title}</strong>
              </div>
              <span className="compatibility-confidence">{compatibility.confidence} confidence</span>
            </header>
            <p>{compatibility.summary}</p>
            <ul aria-label="Compatibility checks">
              {compatibility.steps.map((step) => <li key={step.id} className={`compatibility-step-${step.status}`}>
                {step.status === "pass" ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                <div><strong>{step.label}</strong><span>{step.detail}</span></div>
              </li>)}
            </ul>
            {compatibility.action !== "none" && <CompatibilityCommand
              action={compatibility.action}
              disabled={modeChanging || certificateChanging || (compatibility.action !== "trust_certificate" && !workspace.capture.canControl)}
              onResume={onToggleCapture}
              onTrust={() => onCertificateTrustChange(true)}
              onGateway={() => onModeChange("gateway")}
            />}
          </section>
          <section className="settings-band recovery-band">
            <div><span>Safe recovery</span><strong>Return traffic to the local Gateway</strong><small>Stops the explicit proxy runtime and restores managed system proxy settings.</small></div>
            <button className="settings-command" disabled={!workspace.capture.canControl || workspace.capture.mode === "gateway" || modeChanging} onClick={() => onModeChange("gateway")}><RotateCcw size={14} />Return to Gateway</button>
          </section>
        </div>}
        {tab === "profiles" && <div id="settings-panel-profiles" className="settings-content profile-content" role="tabpanel" aria-labelledby="settings-tab-profiles" tabIndex={0}>
          {!profileReady && <section className="profile-prerequisite" role="status">
            <div>
              <span>Runtime lock</span>
              <strong>{recoveryMode ? "Read-only recovery" : workspace.capture.mode === "proxy" ? "Return to Gateway" : active ? "Pause capture" : "Profile changes unavailable"}</strong>
              <small>The active runtime must be a paused local Gateway before its capture boundary changes.</small>
            </div>
            {!recoveryMode && workspace.capture.mode === "proxy" && <button className="settings-command" disabled={!workspace.capture.canControl || modeChanging} onClick={() => onModeChange("gateway")}><RotateCcw size={14} />Return to Gateway</button>}
            {!recoveryMode && workspace.capture.mode === "gateway" && active && <button className="settings-command" disabled={!workspace.capture.canControl} onClick={onToggleCapture}><Pause size={14} />Pause</button>}
          </section>}
          <form className="profile-form" noValidate onSubmit={saveProfile}>
            <div className="profile-fields">
              <label htmlFor="profile-name">
                <span>Profile name</span>
                <input id="profile-name" aria-label="Profile name" aria-describedby="profile-name-detail" value={profileName} autoComplete="off" onChange={(event) => { setProfileName(event.target.value); setProfileError(""); setProfileSaved(false); }} />
                <small id="profile-name-detail">{new TextEncoder().encode(profileName.trim()).byteLength}/64 bytes</small>
              </label>
              <label htmlFor="profile-gateway">
                <span>Gateway origin</span>
                <input id="profile-gateway" aria-label="Gateway origin" aria-describedby="profile-gateway-detail" type="url" inputMode="url" value={profileGateway} autoComplete="url" spellCheck={false} onChange={(event) => { setProfileGateway(event.target.value); setProfileError(""); setProfileSaved(false); }} />
                <small id="profile-gateway-detail">HTTP(S) origin without credentials, path, query, or fragment</small>
              </label>
              <label htmlFor="profile-hosts" className="profile-hosts-field">
                <span>Additional capture hosts</span>
                <textarea id="profile-hosts" aria-label="Additional capture hosts" aria-describedby="profile-hosts-detail" rows={7} value={profileHosts} autoComplete="off" spellCheck={false} onChange={(event) => { setProfileHosts(event.target.value); setProfileError(""); setProfileSaved(false); }} />
                <small id="profile-hosts-detail">{profileDraft.additionalHosts.length}/16 exact hosts · approved methods and paths remain unchanged</small>
              </label>
            </div>
            {(profileError || profileValidationError) && <span className="settings-error profile-error" role="alert">{profileError || profileValidationError}</span>}
            {profileSaved && <div className="profile-saved" role="status"><CheckCircle2 size={14} /><span>Profile saved</span><code>{workspace.captureProfile.name}</code></div>}
            <footer className="profile-actions">
              <button type="button" className="settings-command" disabled={profileSaving} onClick={restoreDefaultProfile}><RotateCcw size={14} />Restore defaults</button>
              <button type="submit" className="settings-command primary-settings-command" disabled={!canSaveProfile}>{profileSaving ? <LoaderCircle className="is-spinning" size={14} /> : <Save size={14} />}{profileSaving ? "Saving" : "Save Profile"}</button>
            </footer>
          </form>
        </div>}
        {tab === "metrics" && <div id="settings-panel-metrics" className="settings-content metrics-content" role="tabpanel" aria-labelledby="settings-tab-metrics" tabIndex={0}>
          <div className="diagnostics-toolbar"><span>Aggregate evidence with a random deduplication ID. No prompts, request IDs, logs, or automatic upload.</span><div className="diagnostics-actions"><button className="settings-command" disabled={!metricsPreview} onClick={copyMetrics}><Copy size={14} />{metricsCopied ? "Copied" : "Copy evidence"}</button><button className="settings-command" disabled={!metricsPreview || metricsSaving || Boolean(metricsSavedPath)} onClick={saveMetrics}>{metricsSaving ? <LoaderCircle className="is-spinning" size={14} /> : <Download size={14} />}{metricsSavedPath ? "Saved" : "Save evidence"}</button></div></div>
          {metricsError && <span className="settings-error diagnostics-error" role="alert">{metricsError}</span>}
          <div className="metrics-summary" aria-label="Beta metrics summary">
            <MetricSummary label="First capture" value={formatDuration(metricsPreview?.metrics.firstCaptureElapsedMs ?? null)} detail="Elapsed from the first eligible launch" />
            <MetricSummary label="Endpoint parse rate" value={formatRate(metricsPreview?.parseRateBasisPoints ?? null)} detail={metricsPreview ? `${metricsPreview.metrics.parsedCaptureCount} of ${metricsPreview.metrics.supportedCaptureCount} supported requests` : "Waiting for local evidence"} />
            <MetricSummary label="Crash-free sessions" value={formatRate(metricsPreview?.crashFreeRateBasisPoints ?? null)} detail={metricsPreview ? `${metricsPreview.metrics.completedSessionCount - metricsPreview.metrics.uncleanSessionCount} of ${metricsPreview.metrics.completedSessionCount} completed sessions` : "Waiting for local evidence"} />
          </div>
          {metricsSavedPath && <div className="diagnostics-saved" role="status"><CheckCircle2 size={14} /><span>Beta evidence saved</span><code title={metricsSavedPath}>{metricsSavedPath}</code></div>}
          <pre className="diagnostics-preview" aria-label="Beta metrics evidence preview">{metricsPreview?.content ?? "Generating Beta metrics preview"}</pre>
        </div>}
        {tab === "diagnostics" && <div id="settings-panel-diagnostics" className="settings-content diagnostics-content" role="tabpanel" aria-labelledby="settings-tab-diagnostics" tabIndex={0}>
          <div className="diagnostics-toolbar"><span>Request content, identifiers, Raw capture, and log details are excluded.</span><div className="diagnostics-actions"><button className="settings-command" disabled={!supportPreview} onClick={copyReport}><Copy size={14} />{copied ? "Copied" : "Copy report"}</button><button className="settings-command" disabled={!supportPreview || supportSaving || Boolean(supportSavedPath)} onClick={saveBundle}>{supportSaving ? <LoaderCircle className="is-spinning" size={14} /> : <Download size={14} />}{supportSavedPath ? "Saved" : "Save support bundle"}</button></div></div>
          {(copyError || supportError) && <span className="settings-error diagnostics-error" role="alert">{copyError || supportError}</span>}
          <table className="diagnostics-table">
            <tbody>
              <DiagnosticRow label="Encrypted store" healthy={workspace.capture.storage.toLocaleLowerCase().includes("sqlcipher") || workspace.source === "synthetic_fixture"} detail={workspace.capture.storage} />
              <DiagnosticRow label="Capture runtime" healthy={!recoveryMode && !runtimeError} detail={recoveryMode ? "Disabled by read-only recovery mode" : runtimeError || `${workspace.capture.mode} · ${active ? "active" : "paused"}`} />
              <DiagnosticRow label="Gateway endpoint" healthy={!recoveryMode && workspace.capture.endpoint !== "Not connected"} detail={workspace.capture.endpoint} />
              <DiagnosticRow label="Proxy bundle" healthy={workspace.capture.proxyAvailable} detail={workspace.capture.proxyAvailable ? "Verified and available" : "Unavailable"} />
              <DiagnosticRow label="Local CA" healthy={certificate.state === "ready"} detail={certificateLabel(certificate)} />
              <DiagnosticRow label="System trust" healthy={certificate.trust === "trusted" || workspace.capture.mode === "gateway"} detail={certificate.trust.replaceAll("_", " ")} />
              <DiagnosticRow label="Compatibility" healthy={compatibility.status === "ready"} detail={`${compatibility.title} · ${compatibility.confidence} confidence`} />
              <DiagnosticRow label="Stored requests" healthy={true} detail={String(workspace.capture.requestCount)} />
            </tbody>
          </table>
          {supportSavedPath && <div className="diagnostics-saved" role="status"><CheckCircle2 size={14} /><span>Support bundle saved</span><code title={supportSavedPath}>{supportSavedPath}</code></div>}
          <pre className="diagnostics-preview" aria-label="Diagnostic report preview">{supportPreview?.content ?? "Generating support bundle preview"}</pre>
        </div>}
        {tab === "updates" && <div id="settings-panel-updates" className="settings-content updates-content" role="tabpanel" aria-labelledby="settings-tab-updates" tabIndex={0}>
          {recoveryMode && <section className="settings-band recovery-band" role="status">
            <div><span>Recovery lock</span><strong>Updates are disabled</strong><small>Export required history and repair or restore the primary workspace before installing another release.</small></div>
          </section>}
          <section className="settings-band">
            <div><span>Installed version</span><strong>{updateStatus?.currentVersion ?? "Current build"}</strong><small>Stable channel · signed packages only</small></div>
            <button className="settings-command" disabled={recoveryMode || updateChecking || updateInstalling} onClick={checkUpdates}>{updateChecking ? <LoaderCircle className="is-spinning" size={14} /> : <RefreshCw size={14} />}Check</button>
          </section>
          {updateStatus && <section className="settings-band update-release-band">
            <div>
              <span>Update channel</span>
              <strong>{updateStatus.configured ? updateStatus.availableVersion ? `Version ${updateStatus.availableVersion}` : "Up to date" : "Not configured"}</strong>
              <small>{updateStatus.configured ? updateStatus.notes || updateStatus.publishedAt || "No newer signed release is available." : "This build does not contain a trusted update public key."}</small>
            </div>
            {updateStatus.availableVersion && <button className="settings-command" disabled={recoveryMode || updateInstalling} onClick={installAvailableUpdate}>{updateInstalling ? <LoaderCircle className="is-spinning" size={14} /> : <Download size={14} />}Install & restart</button>}
          </section>}
          {updateInstalling && <section className="update-progress" aria-live="polite">
            <div><span>{updateProgress?.finished ? "Verifying signed package" : "Downloading update"}</span><strong>{formatUpdateProgress(updateProgress)}</strong></div>
            <progress aria-label="Update download progress" value={updateProgress?.downloadedBytes ?? 0} max={updateProgress?.totalBytes ?? Math.max(updateProgress?.downloadedBytes ?? 0, 1)} />
            <small>Capture is in Gateway mode and managed system proxy settings have been restored.</small>
          </section>}
          {updateError && <span className="settings-error update-error" role="alert">{updateError}</span>}
          <p className="update-safety-note">Before installation, CodeIsCheap returns capture to the local Gateway and writes an encrypted recovery snapshot.</p>
        </div>}
      </section>
    </div>
  );
}

function formatUpdateProgress(progress: UpdateDownloadProgress | null) {
  if (!progress) return "Preparing";
  if (progress.finished) return "Downloaded";
  if (!progress.totalBytes) return `${formatBytes(progress.downloadedBytes)} received`;
  return `${Math.min(100, Math.round((progress.downloadedBytes / progress.totalBytes) * 100))}%`;
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function formatDuration(milliseconds: number | null) {
  if (milliseconds == null) return "Not observed";
  if (milliseconds < 1_000) return `${milliseconds} ms`;
  if (milliseconds < 60_000) return `${(milliseconds / 1_000).toFixed(1)} s`;
  return `${(milliseconds / 60_000).toFixed(1)} min`;
}

function formatRate(basisPoints: number | null) {
  return basisPoints == null ? "Not enough data" : `${(basisPoints / 100).toFixed(2)}%`;
}

function MetricSummary({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <section><span>{label}</span><strong>{value}</strong><small>{detail}</small></section>;
}

function CompatibilityCommand({ action, disabled, onResume, onTrust, onGateway }: {
  action: WorkspaceBootstrap["compatibility"]["action"];
  disabled: boolean;
  onResume: () => void;
  onTrust: () => void;
  onGateway: () => void;
}) {
  if (action === "resume_capture") {
    return <button className="settings-command compatibility-command" disabled={disabled} onClick={onResume}><Play size={14} />Resume capture</button>;
  }
  if (action === "trust_certificate") {
    return <button className="settings-command compatibility-command" disabled={disabled} onClick={onTrust}><ShieldCheck size={14} />Trust CA</button>;
  }
  return <button className="settings-command compatibility-command" disabled={disabled} onClick={onGateway}><RotateCcw size={14} />Use Gateway</button>;
}

function DiagnosticRow({ label, healthy, detail }: { label: string; healthy: boolean; detail: string }) {
  return <tr><th scope="row">{healthy ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}<span>{label}</span></th><td className={healthy ? "diagnostic-ok" : "diagnostic-warning"}>{healthy ? "Ready" : "Attention"}</td><td>{detail}</td></tr>;
}

function certificateLabel(certificate: CertificateAuthority) {
  const state = certificate.state === "missing" ? "Not generated" : certificate.state === "invalid" ? "Invalid" : "Ready";
  return `${state} · ${certificate.trust.replaceAll("_", " ")}`;
}

function captureProfileDraft(
  version: string,
  name: string,
  gatewayUpstream: string,
  hosts: string,
): CaptureProfile {
  return {
    version,
    name: name.trim(),
    gatewayUpstream: gatewayUpstream.trim(),
    additionalHosts: hosts
      .split(/\r?\n/)
      .map((host) => host.trim().replace(/\.$/, "").toLowerCase())
      .filter(Boolean)
      .sort(),
  };
}

function validateCaptureProfileDraft(profile: CaptureProfile) {
  const nameBytes = new TextEncoder().encode(profile.name).byteLength;
  if (!profile.name || nameBytes > 64 || /[\u0000-\u001f\u007f]/.test(profile.name)) {
    return "Profile name must be 1-64 bytes without control characters.";
  }
  let upstream: URL;
  try {
    upstream = new URL(profile.gatewayUpstream);
  } catch {
    return "Gateway origin must be an absolute HTTP or HTTPS URL.";
  }
  if (!(["http:", "https:"] as string[]).includes(upstream.protocol) || !upstream.hostname) {
    return "Gateway origin must be an absolute HTTP or HTTPS URL.";
  }
  if (upstream.username || upstream.password) {
    return "Gateway origin must not contain embedded credentials.";
  }
  if (upstream.pathname !== "/" || upstream.search || upstream.hash) {
    return "Gateway origin must not contain a path, query, or fragment.";
  }
  if (profile.additionalHosts.length > 16) {
    return "At most 16 additional capture hosts are allowed.";
  }
  const uniqueHosts = new Set(profile.additionalHosts);
  if (uniqueHosts.size !== profile.additionalHosts.length) {
    return "Additional capture hosts must be unique.";
  }
  if (profile.additionalHosts.some((host) => host.includes(",") || /\s/.test(host))) {
    return "Each additional capture host must be an exact hostname or IP address.";
  }
  return "";
}

function captureProfilesEqual(left: CaptureProfile, right: CaptureProfile) {
  return left.version === right.version
    && left.name === right.name
    && left.gatewayUpstream === right.gatewayUpstream
    && left.additionalHosts.length === right.additionalHosts.length
    && left.additionalHosts.every((host, index) => host === right.additionalHosts[index]);
}
