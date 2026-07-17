import { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  LoaderCircle,
  Network,
  Pause,
  Play,
  RotateCcw,
  ShieldCheck,
  Stethoscope,
  X,
} from "lucide-react";
import type { CaptureMode, CertificateAuthority, WorkspaceBootstrap } from "./types";

type SettingsTab = "connection" | "diagnostics";

export function SettingsDialog({ workspace, active, runtimeError, certificateError, modeChanging, certificateChanging, onToggleCapture, onModeChange, onCertificateTrustChange, onClose }: {
  workspace: WorkspaceBootstrap;
  active: boolean;
  runtimeError: string;
  certificateError: string;
  modeChanging: boolean;
  certificateChanging: boolean;
  onToggleCapture: () => void;
  onModeChange: (mode: CaptureMode) => void;
  onCertificateTrustChange: (trusted: boolean) => void;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<SettingsTab>("connection");
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState("");
  const closeRef = useRef<HTMLButtonElement>(null);
  const certificate = workspace.capture.certificateAuthority;
  const canTrust = certificate.canManageTrust
    && certificate.state === "ready"
    && certificate.trust === "not_trusted";
  const canRemoveTrust = certificate.canManageTrust && certificate.trust === "trusted";
  const report = useMemo(() => diagnosticReport(workspace, active, runtimeError), [workspace, active, runtimeError]);

  useEffect(() => {
    const background = document.querySelectorAll(".app-shell > .titlebar, .app-shell > .workspace");
    background.forEach((element) => element.setAttribute("inert", ""));
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      background.forEach((element) => element.removeAttribute("inert"));
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);

  const copyReport = async () => {
    try {
      await navigator.clipboard.writeText(`${JSON.stringify(report, null, 2)}\n`);
      setCopied(true);
      setCopyError("");
    } catch {
      setCopyError("Diagnostic report could not be copied.");
    }
  };

  return (
    <div className="dialog-backdrop">
      <section className="settings-dialog" role="dialog" aria-modal="true" aria-labelledby="settings-title">
        <header>
          <div><span className="dialog-eyebrow">Local workspace</span><h2 id="settings-title">Settings & diagnostics</h2></div>
          <button ref={closeRef} className="icon-button" title="Close settings" aria-label="Close settings" onClick={onClose}><X size={17} /></button>
        </header>
        <nav className="settings-tabs" aria-label="Settings views">
          <button aria-selected={tab === "connection"} onClick={() => setTab("connection")}><Network size={14} />Connection</button>
          <button aria-selected={tab === "diagnostics"} onClick={() => setTab("diagnostics")}><Stethoscope size={14} />Diagnostics</button>
        </nav>
        {tab === "connection" && <div className="settings-content">
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
            {(canTrust || canRemoveTrust) && <button className="settings-command" disabled={certificateChanging} onClick={() => onCertificateTrustChange(canTrust)}>{certificateChanging ? <LoaderCircle className="is-spinning" size={14} /> : <ShieldCheck size={14} />}{canTrust ? "Trust CA" : "Remove trust"}</button>}
          </section>
          <section className="settings-band recovery-band">
            <div><span>Safe recovery</span><strong>Return traffic to the local Gateway</strong><small>Stops the explicit proxy runtime and restores managed system proxy settings.</small></div>
            <button className="settings-command" disabled={!workspace.capture.canControl || workspace.capture.mode === "gateway" || modeChanging} onClick={() => onModeChange("gateway")}><RotateCcw size={14} />Return to Gateway</button>
          </section>
        </div>}
        {tab === "diagnostics" && <div className="settings-content diagnostics-content">
          <div className="diagnostics-toolbar"><span>Request content is excluded from this report.</span><button className="settings-command" onClick={copyReport}><Copy size={14} />{copied ? "Copied" : "Copy report"}</button></div>
          {copyError && <span className="settings-error diagnostics-error" role="alert">{copyError}</span>}
          <table className="diagnostics-table">
            <tbody>
              <DiagnosticRow label="Encrypted store" healthy={workspace.capture.storage.toLocaleLowerCase().includes("sqlcipher") || workspace.source === "synthetic_fixture"} detail={workspace.capture.storage} />
              <DiagnosticRow label="Capture runtime" healthy={!runtimeError} detail={runtimeError || `${workspace.capture.mode} · ${active ? "active" : "paused"}`} />
              <DiagnosticRow label="Gateway endpoint" healthy={workspace.capture.endpoint !== "Not connected"} detail={workspace.capture.endpoint} />
              <DiagnosticRow label="Proxy bundle" healthy={workspace.capture.proxyAvailable} detail={workspace.capture.proxyAvailable ? "Verified and available" : "Unavailable"} />
              <DiagnosticRow label="Local CA" healthy={certificate.state === "ready"} detail={certificateLabel(certificate)} />
              <DiagnosticRow label="System trust" healthy={certificate.trust === "trusted" || workspace.capture.mode === "gateway"} detail={certificate.trust.replaceAll("_", " ")} />
              <DiagnosticRow label="Stored requests" healthy={true} detail={String(workspace.capture.requestCount)} />
            </tbody>
          </table>
          <pre className="diagnostics-preview" aria-label="Diagnostic report preview">{JSON.stringify(report, null, 2)}</pre>
        </div>}
      </section>
    </div>
  );
}

function DiagnosticRow({ label, healthy, detail }: { label: string; healthy: boolean; detail: string }) {
  return <tr><th scope="row">{healthy ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}<span>{label}</span></th><td className={healthy ? "diagnostic-ok" : "diagnostic-warning"}>{healthy ? "Ready" : "Attention"}</td><td>{detail}</td></tr>;
}

function certificateLabel(certificate: CertificateAuthority) {
  const state = certificate.state === "missing" ? "Not generated" : certificate.state === "invalid" ? "Invalid" : "Ready";
  return `${state} · ${certificate.trust.replaceAll("_", " ")}`;
}

function diagnosticReport(workspace: WorkspaceBootstrap, active: boolean, runtimeError: string) {
  return {
    generatedAt: new Date().toISOString(),
    apiVersion: workspace.apiVersion,
    source: workspace.source,
    capture: {
      active,
      canControl: workspace.capture.canControl,
      mode: workspace.capture.mode,
      endpoint: workspace.capture.endpoint,
      profile: workspace.capture.profile,
      proxyAvailable: workspace.capture.proxyAvailable,
      requestCount: workspace.capture.requestCount,
      storage: workspace.capture.storage,
    },
    certificateAuthority: {
      state: workspace.capture.certificateAuthority.state,
      trust: workspace.capture.certificateAuthority.trust,
      privateMaterial: workspace.capture.certificateAuthority.privateMaterial,
      fingerprintSha256: workspace.capture.certificateAuthority.fingerprintSha256,
      detail: workspace.capture.certificateAuthority.detail,
    },
    runtimeIssue: runtimeError || null,
  };
}
