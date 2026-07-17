import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  Activity,
  AlertTriangle,
  BadgeCheck,
  Braces,
  ChevronDown,
  ChevronRight,
  CircleStop,
  Database,
  Download,
  Filter,
  LocateFixed,
  LoaderCircle,
  Moon,
  Network,
  Pause,
  Play,
  Search,
  Settings,
  ShieldCheck,
  ShieldOff,
  Sun,
  TerminalSquare,
  Wrench,
  X,
} from "lucide-react";
import type {
  AnatomySection,
  CaptureMode,
  CapturedRequest,
  CertificateAuthority,
  EvidenceLocator,
  ExportPreview,
  ExportProfile,
  InspectorTab,
  WorkspaceBootstrap,
  WorkspaceSource,
} from "./types";
import {
  installCertificateAuthorityTrust,
  loadWorkspace,
  previewCaptureExport,
  saveCaptureExport,
  setCaptureActive as persistCaptureActive,
  setCaptureMode as persistCaptureMode,
  subscribeToCaptureEvents,
  uninstallCertificateAuthorityTrust,
} from "./workspace";
import { formatRawJson, resolveEvidenceLocator, resolveEvidencePointer } from "./raw-evidence";
import type { ResolvedRawEvidence } from "./raw-evidence";

const number = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const clock = new Intl.DateTimeFormat(undefined, {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});
const REQUEST_ROW_HEIGHT = 116;

export function App() {
  const [workspace, setWorkspace] = useState<WorkspaceBootstrap | null>(null);
  const [loadError, setLoadError] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const [selectedId, setSelectedId] = useState("");
  const [query, setQuery] = useState("");
  const [provider, setProvider] = useState("All providers");
  const [application, setApplication] = useState("All apps");
  const [toolsOnly, setToolsOnly] = useState(false);
  const [errorsOnly, setErrorsOnly] = useState(false);
  const [tab, setTab] = useState<InspectorTab>("anatomy");
  const [theme, setTheme] = useState<"light" | "dark">(
    () => (localStorage.getItem("codeischeap.theme") as "light" | "dark") || "light",
  );
  const [captureActive, setCaptureActive] = useState(true);
  const [captureError, setCaptureError] = useState("");
  const [captureMode, setCaptureMode] = useState<CaptureMode>("gateway");
  const [modeChanging, setModeChanging] = useState(false);
  const [certificateChanging, setCertificateChanging] = useState(false);
  const [certificateError, setCertificateError] = useState("");
  const [exportRequestId, setExportRequestId] = useState<string | null>(null);
  const [sidebarWidth, setSidebarWidth] = useState(218);
  const [listWidth, setListWidth] = useState(390);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let cancelled = false;
    setLoadError("");
    loadWorkspace()
      .then((value) => {
        if (cancelled) return;
        setWorkspace(value);
        setSelectedId((current) =>
          value.requests.some((request) => request.id === current)
            ? current
            : (value.requests[0]?.id ?? ""),
        );
        setCaptureActive(value.capture.active);
        setCaptureMode(value.capture.mode);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setWorkspace(null);
        setLoadError(error instanceof Error ? error.message : "The encrypted workspace could not be opened.");
      });
    return () => { cancelled = true; };
  }, [reloadToken]);

  useEffect(() => {
    let disposed = false;
    let unsubscribe: (() => void) | undefined;
    subscribeToCaptureEvents({
      onUpdated: () => {
        setCaptureError("");
        setReloadToken((value) => value + 1);
      },
      onError: (event) => {
        setCaptureError(event.detail);
        if (event.code === "capture_disk_pressure") {
          setCaptureActive(false);
          setWorkspace((current) => current && {
            ...current,
            capture: { ...current.capture, active: false },
          });
        }
        if (
          event.code === "sidecar_process_exited" ||
          event.code === "sidecar_process_monitor_failed"
        ) {
          setReloadToken((value) => value + 1);
        }
      },
    })
      .then((value) => {
        if (disposed) value();
        else unsubscribe = value;
      })
      .catch((error: unknown) => {
        if (!disposed) {
          setCaptureError(
            error instanceof Error ? error.message : "Capture events are unavailable.",
          );
        }
      });
    return () => {
      disposed = true;
      unsubscribe?.();
    };
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("codeischeap.theme", theme);
  }, [theme]);

  const requests = useMemo(
    () => workspace ? filteredRequests(workspace.requests, query, provider, application, toolsOnly, errorsOnly) : [],
    [workspace, query, provider, application, toolsOnly, errorsOnly],
  );
  const effectiveSelectedId = requests.some((request) => request.id === selectedId)
    ? selectedId
    : (requests[0]?.id ?? "");
  const selected = workspace?.requests.find((request) => request.id === effectiveSelectedId);
  const exportRequest = workspace?.requests.find((request) => request.id === exportRequestId) ?? null;

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "/" && document.activeElement !== searchRef.current) {
        event.preventDefault();
        searchRef.current?.focus();
      }
      if (!workspace || event.target instanceof HTMLInputElement || event.target instanceof HTMLSelectElement) {
        return;
      }
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        const current = Math.max(0, requests.findIndex((request) => request.id === effectiveSelectedId));
        const next = event.key === "ArrowDown" ? Math.min(requests.length - 1, current + 1) : Math.max(0, current - 1);
        setSelectedId(requests[next]?.id ?? effectiveSelectedId);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [workspace, requests, effectiveSelectedId]);

  const toggleCapture = () => {
    const next = !captureActive;
    persistCaptureActive(next)
      .then((active) => {
        setCaptureActive(active);
        setCaptureError("");
        setWorkspace((current) => current && {
          ...current,
          capture: { ...current.capture, active },
        });
      })
      .catch((error: unknown) => {
        setCaptureError(error instanceof Error ? error.message : "Capture state could not change.");
      });
  };

  const changeCaptureMode = (mode: CaptureMode) => {
    if (mode === captureMode || modeChanging) return;
    setModeChanging(true);
    persistCaptureMode(mode)
      .then((nextWorkspace) => {
        setWorkspace(nextWorkspace);
        setCaptureActive(nextWorkspace.capture.active);
        setCaptureMode(nextWorkspace.capture.mode);
        setCaptureError("");
      })
      .catch((error: unknown) => {
        setCaptureError(error instanceof Error ? error.message : "Capture mode could not change.");
      })
      .finally(() => setModeChanging(false));
  };

  const changeCertificateTrust = (trusted: boolean) => {
    if (certificateChanging) return;
    setCertificateChanging(true);
    setCertificateError("");
    const operation = trusted
      ? installCertificateAuthorityTrust()
      : uninstallCertificateAuthorityTrust();
    operation
      .then((nextWorkspace) => {
        setWorkspace(nextWorkspace);
        setCaptureActive(nextWorkspace.capture.active);
        setCaptureMode(nextWorkspace.capture.mode);
      })
      .catch((error: unknown) => {
        setCertificateError(
          error instanceof Error ? error.message : "Certificate trust could not change.",
        );
      })
      .finally(() => setCertificateChanging(false));
  };

  if (loadError) {
    return <LoadFailure detail={loadError} onRetry={() => setReloadToken((value) => value + 1)} />;
  }

  if (!workspace) {
    return <div className="loading-state"><span className="brand-glyph">C</span><span>Loading workspace</span></div>;
  }

  return (
    <div className="app-shell">
      <Titlebar
        active={captureActive}
        canControl={workspace.capture.canControl}
        source={workspace.source}
        theme={theme}
        onToggleCapture={toggleCapture}
        onToggleTheme={() => setTheme((value) => value === "light" ? "dark" : "light")}
      />
      <main
        className="workspace"
        style={{ gridTemplateColumns: `${sidebarWidth}px 5px ${listWidth}px 5px minmax(430px, 1fr)` }}
      >
        <CaptureSidebar
          workspace={workspace}
          active={captureActive}
          canControl={workspace.capture.canControl}
          proxyAvailable={workspace.capture.proxyAvailable}
          mode={captureMode}
          modeChanging={modeChanging}
          certificateChanging={certificateChanging}
          certificateError={certificateError}
          toolsOnly={toolsOnly}
          errorsOnly={errorsOnly}
          runtimeError={captureError}
          onModeChange={changeCaptureMode}
          onCertificateTrustChange={changeCertificateTrust}
          onToolsOnly={setToolsOnly}
          onErrorsOnly={setErrorsOnly}
        />
        <ResizeHandle label="Resize capture sidebar" onResize={(delta) => setSidebarWidth((width) => clamp(width + delta, 184, 292))} />
        <RequestPane
          requests={requests}
          allRequests={workspace.requests}
          selectedId={effectiveSelectedId}
          query={query}
          provider={provider}
          application={application}
          searchRef={searchRef}
          onQuery={setQuery}
          onProvider={setProvider}
          onApplication={setApplication}
          onSelect={(id) => { setSelectedId(id); setTab("anatomy"); }}
        />
        <ResizeHandle label="Resize request list" onResize={(delta) => setListWidth((width) => clamp(width + delta, 320, 560))} />
        {selected ? <Inspector request={selected} tab={tab} onTab={setTab} onExport={() => setExportRequestId(selected.id)} /> : <EmptyInspector />}
      </main>
      {exportRequest && <ExportDialog request={exportRequest} onClose={() => setExportRequestId(null)} />}
    </div>
  );
}

function Titlebar({ active, canControl, source, theme, onToggleCapture, onToggleTheme }: {
  active: boolean;
  canControl: boolean;
  source: WorkspaceSource;
  theme: "light" | "dark";
  onToggleCapture: () => void;
  onToggleTheme: () => void;
}) {
  return (
    <header className="titlebar">
      <div className="brand-lockup"><span className="brand-glyph">C</span><strong>CodeIsCheap</strong><span className="fixture-label">{source === "encrypted_local" ? "Encrypted local workspace" : "Synthetic workspace"}</span></div>
      <div className="titlebar-actions">
        <span className={`capture-indicator ${active ? "is-live" : ""}`}><span />{active ? "Capturing" : "Paused"}</span>
        <button className="icon-button" title={canControl ? (active ? "Pause capture" : "Resume capture") : "Capture controls are not connected"} aria-label={active ? "Pause capture" : "Resume capture"} disabled={!canControl} onClick={onToggleCapture}>
          {active ? <Pause size={16} /> : <Play size={16} />}
        </button>
        <button className="icon-button" title={`Use ${theme === "light" ? "dark" : "light"} theme`} aria-label="Toggle theme" onClick={onToggleTheme}>
          {theme === "light" ? <Moon size={16} /> : <Sun size={16} />}
        </button>
        <button className="icon-button" title="Settings" aria-label="Settings"><Settings size={16} /></button>
      </div>
    </header>
  );
}

function CaptureSidebar({ workspace, active, canControl, proxyAvailable, mode, modeChanging, certificateChanging, certificateError, toolsOnly, errorsOnly, runtimeError, onModeChange, onCertificateTrustChange, onToolsOnly, onErrorsOnly }: {
  workspace: WorkspaceBootstrap;
  active: boolean;
  canControl: boolean;
  proxyAvailable: boolean;
  mode: CaptureMode;
  modeChanging: boolean;
  certificateChanging: boolean;
  certificateError: string;
  toolsOnly: boolean;
  errorsOnly: boolean;
  runtimeError: string;
  onModeChange: (mode: CaptureMode) => void;
  onCertificateTrustChange: (trusted: boolean) => void;
  onToolsOnly: (value: boolean) => void;
  onErrorsOnly: (value: boolean) => void;
}) {
  const certificate = workspace.capture.certificateAuthority;
  const showCertificate = proxyAvailable || certificate.state !== "missing";
  const canChangeTrust = certificate.canManageTrust
    && certificate.fingerprintSha256 != null
    && (certificate.trust === "trusted"
      || (certificate.state === "ready" && certificate.trust === "not_trusted"));
  return (
    <aside className="capture-sidebar" aria-label="Capture controls">
      <section className="sidebar-section capture-summary">
        <div className="section-label">Capture</div>
        <div className="capture-state"><span className={`state-dot ${active ? "is-live" : ""}`} /><strong>{active ? "Active" : "Paused"}</strong></div>
        <div className="segmented-control" aria-label="Capture mode">
          <button aria-pressed={mode === "gateway"} disabled={!canControl || modeChanging} onClick={() => onModeChange("gateway")}><Network size={14} />Gateway</button>
          <button title={proxyAvailable ? "Use explicit TLS proxy" : "Verified proxy bundle unavailable"} aria-pressed={mode === "proxy"} disabled={!canControl || !proxyAvailable || modeChanging} onClick={() => onModeChange("proxy")}><ShieldCheck size={14} />Proxy</button>
        </div>
        <dl className="capture-facts">
          <div><dt>Profile</dt><dd>{workspace.capture.profile}</dd></div>
          <div><dt>Endpoint</dt><dd>{workspace.capture.endpoint}</dd></div>
          <div><dt>Storage</dt><dd>{workspace.capture.storage}</dd></div>
          {showCertificate && <div><dt>Local CA</dt><dd title={certificateDetail(certificate)}>{certificateSummary(certificate)}</dd></div>}
          {showCertificate && certificate.fingerprintSha256 && <div className="certificate-fingerprint"><dt>SHA-256 fingerprint</dt><dd><code>{certificate.fingerprintSha256}</code></dd></div>}
        </dl>
        {canChangeTrust && <div className="certificate-actions">
          <button disabled={certificateChanging} onClick={() => onCertificateTrustChange(certificate.trust !== "trusted")}>
            {certificateChanging
              ? <LoaderCircle className="is-spinning" size={13} />
              : certificate.trust === "trusted" ? <ShieldOff size={13} /> : <BadgeCheck size={13} />}
            {certificate.trust === "trusted" ? "Remove trust" : "Trust CA"}
          </button>
          {certificateError && <span role="alert">{certificateError}</span>}
        </div>}
      </section>
      <section className="sidebar-section">
        <div className="section-label"><Filter size={13} />Filters</div>
        <label className="check-row"><input type="checkbox" checked={toolsOnly} onChange={(event) => onToolsOnly(event.target.checked)} /><Wrench size={14} /><span>Has tools</span><b>{workspace.requests.filter((request) => request.hasTools).length}</b></label>
        <label className="check-row"><input type="checkbox" checked={errorsOnly} onChange={(event) => onErrorsOnly(event.target.checked)} /><AlertTriangle size={14} /><span>Errors</span><b>{workspace.requests.filter((request) => request.status === "error").length}</b></label>
      </section>
      <section className="sidebar-section system-health">
        <div className="section-label">Health</div>
        <div title={runtimeError || undefined}><Activity size={14} /><span>{mode === "gateway" ? "Gateway" : "Proxy"}</span><b className={runtimeError ? "health-error" : "health-ok"}>{runtimeError ? "Issue" : "Healthy"}</b></div>
        <div><Database size={14} /><span>Local store</span><b className="health-ok">Ready</b></div>
        <div><ShieldCheck size={14} /><span>Credentials</span><b className="health-ok">Excluded</b></div>
      </section>
      <div className="sidebar-footer"><CircleStop size={13} />No request data leaves this device</div>
    </aside>
  );
}

function RequestPane({ requests, allRequests, selectedId, query, provider, application, searchRef, onQuery, onProvider, onApplication, onSelect }: {
  requests: CapturedRequest[];
  allRequests: CapturedRequest[];
  selectedId: string;
  query: string;
  provider: string;
  application: string;
  searchRef: React.RefObject<HTMLInputElement | null>;
  onQuery: (value: string) => void;
  onProvider: (value: string) => void;
  onApplication: (value: string) => void;
  onSelect: (id: string) => void;
}) {
  const listRef = useRef<HTMLDivElement>(null);
  const providers = ["All providers", ...new Set(allRequests.map((request) => request.provider))];
  const applications = ["All apps", ...new Set(allRequests.map((request) => request.application))];
  const selectedIndex = requests.findIndex((request) => request.id === selectedId);
  const rowVirtualizer = useVirtualizer({
    count: requests.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => REQUEST_ROW_HEIGHT,
    getItemKey: (index) => requests[index]?.id ?? index,
    overscan: 5,
  });

  useEffect(() => {
    if (selectedIndex >= 0) {
      rowVirtualizer.scrollToIndex(selectedIndex, { align: "auto" });
    }
  }, [rowVirtualizer, selectedIndex]);

  return (
    <section className="request-pane" aria-label="Captured requests">
      <div className="pane-heading"><div><h1>Requests</h1><span>{requests.length} visible</span></div><button className="icon-button" title="Request list options" aria-label="Request list options"><Filter size={15} /></button></div>
      <div className="request-toolbar">
        <label className="search-field"><Search size={15} /><input ref={searchRef} value={query} onChange={(event) => onQuery(event.target.value)} placeholder="Search prompts, apps, models" aria-label="Search requests" /><kbd>/</kbd></label>
        <div className="select-row">
          <select aria-label="Provider filter" value={provider} onChange={(event) => onProvider(event.target.value)}>{providers.map((value) => <option key={value}>{value}</option>)}</select>
          <select aria-label="Application filter" value={application} onChange={(event) => onApplication(event.target.value)}>{applications.map((value) => <option key={value}>{value}</option>)}</select>
        </div>
      </div>
      <div ref={listRef} className="request-list" role="listbox" aria-label="Request results">
        {requests.length > 0 && <div className="request-virtualizer" style={{ height: rowVirtualizer.getTotalSize() }}>
          {rowVirtualizer.getVirtualItems().map((virtualRow) => {
            const request = requests[virtualRow.index];
            return (
              <button
                key={request.id}
                role="option"
                aria-posinset={virtualRow.index + 1}
                aria-setsize={requests.length}
                aria-selected={request.id === selectedId}
                className="request-row"
                data-index={virtualRow.index}
                style={{ transform: `translateY(${virtualRow.start}px)` }}
                tabIndex={request.id === selectedId ? 0 : -1}
                onClick={() => onSelect(request.id)}
              >
                <div className="request-row-top"><span className={`status-mark status-${request.status}`} /><strong>{request.application}</strong><time>{clock.format(new Date(request.observedAtUnixMs))}</time></div>
                <div className="request-operation"><span>{request.provider}</span><b>{request.operation}</b></div>
                <p>{request.promptPreview}</p>
                <div className="request-meta"><span>{request.model}</span><span>{formatTokens(request.tokens, request.tokenSource)}</span><span>{request.durationMs == null ? "Duration unknown" : formatDuration(request.durationMs)}</span>{request.hasTools && <Wrench size={12} aria-label="Uses tools" />}</div>
              </button>
            );
          })}
        </div>}
        {requests.length === 0 && <div className="empty-list"><Search size={22} /><strong>No matching requests</strong><span>Adjust search or filters.</span></div>}
      </div>
    </section>
  );
}

function Inspector({ request, tab, onTab, onExport }: { request: CapturedRequest; tab: InspectorTab; onTab: (tab: InspectorTab) => void; onExport: () => void }) {
  const [rawEvidence, setRawEvidence] = useState<ResolvedRawEvidence | null>(null);
  useEffect(() => { setRawEvidence(null); }, [request.id]);
  const locateRawEvidence = (source: string) => {
    const pointer = resolveEvidencePointer(request.detail.raw, source);
    if (!pointer) return;
    setRawEvidence({ pointer, fragment: null, start: null, end: null });
    onTab("raw");
  };
  const locateTimelineEvidence = (locator: EvidenceLocator) => {
    const evidence = resolveEvidenceLocator(request.detail.raw, locator);
    if (!evidence) return;
    setRawEvidence(evidence);
    onTab("raw");
  };
  return (
    <section className="inspector" aria-label="Request inspector">
      <header className="inspector-header">
        <div><div className="inspector-provider"><span className={`provider-mark provider-${request.provider.toLowerCase()}`}>{request.provider[0]}</span><strong>{request.provider}</strong><span>{request.operation}</span></div><h2>{request.model}</h2>{request.semanticFingerprint && <code className="semantic-fingerprint" title={`BLAKE3 semantic fingerprint: ${request.semanticFingerprint}`}>{request.semanticFingerprint.slice(0, 12)}</code>}</div>
        <div className="inspector-actions"><div className="inspector-metrics"><span><b>{formatTokens(request.tokens, request.tokenSource)}</b> tokens</span><span title={request.pricingVersion ?? undefined}><b>{formatCost(request.costUsd, request.costSource)}</b> cost</span><span><b>{request.durationMs == null ? "Unknown" : formatDuration(request.durationMs)}</b> duration</span><span className={`request-state state-${request.status}`}>{request.status}</span></div><button className="icon-button" title="Export request" aria-label="Export request" onClick={onExport}><Download size={16} /></button></div>
      </header>
      <nav className="inspector-tabs" aria-label="Inspector views">
        <button aria-selected={tab === "anatomy"} onClick={() => onTab("anatomy")}><Braces size={14} />Anatomy</button>
        <button aria-selected={tab === "timeline"} onClick={() => onTab("timeline")}><Activity size={14} />Timeline</button>
        <button aria-selected={tab === "raw"} onClick={() => onTab("raw")}><TerminalSquare size={14} />Raw</button>
      </nav>
      <div className="inspector-content">
        {tab === "anatomy" && <AnatomyView sections={request.detail.anatomy} raw={request.detail.raw} onLocate={locateRawEvidence} />}
        {tab === "timeline" && <TimelineView request={request} onLocate={locateTimelineEvidence} />}
        {tab === "raw" && <RawView request={request} evidence={rawEvidence} />}
      </div>
    </section>
  );
}

function ExportDialog({ request, onClose }: { request: CapturedRequest; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null);
  const [profile, setProfile] = useState<ExportProfile>("minimal");
  const [preview, setPreview] = useState<ExportPreview | null>(null);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [savedPath, setSavedPath] = useState("");

  useEffect(() => {
    const background = document.querySelectorAll(".app-shell > .titlebar, .app-shell > .workspace");
    background.forEach((element) => element.setAttribute("inert", ""));
    closeRef.current?.focus();
    return () => background.forEach((element) => element.removeAttribute("inert"));
  }, []);

  useEffect(() => {
    let cancelled = false;
    setPreview(null);
    setError("");
    setSavedPath("");
    previewCaptureExport(request.id, profile)
      .then((value) => { if (!cancelled) setPreview(value); })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : "Export preview could not be generated.");
      });
    return () => { cancelled = true; };
  }, [request.id, profile]);

  useEffect(() => {
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !saving) onClose();
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose, saving]);

  const savePreview = () => {
    if (!preview || saving) return;
    setSaving(true);
    setError("");
    saveCaptureExport(request.id, preview)
      .then((receipt) => { if (receipt) setSavedPath(receipt.path); })
      .catch((reason: unknown) => {
        setError(reason instanceof Error ? reason.message : "Export file could not be written.");
      })
      .finally(() => setSaving(false));
  };

  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !saving) onClose(); }}>
    <section className="export-dialog" role="dialog" aria-modal="true" aria-labelledby="export-title">
      <header><div><span className="dialog-eyebrow">{request.provider} · {request.operation}</span><h2 id="export-title">Export request</h2></div><button ref={closeRef} className="icon-button" title="Close" aria-label="Close export" disabled={saving} onClick={onClose}><X size={17} /></button></header>
      <div className="export-toolbar">
        <div className="export-profiles" aria-label="Export profile">
          {(["minimal", "reproducible", "forensic"] as ExportProfile[]).map((value) => <button key={value} aria-pressed={profile === value} onClick={() => setProfile(value)}>{value}</button>)}
        </div>
        <div className={`export-scan ${preview?.redactions.length ? "has-redactions" : ""}`}><ShieldCheck size={14} /><span>{preview ? `${preview.redactions.length} credential${preview.redactions.length === 1 ? "" : "s"} replaced` : "Scanning"}</span></div>
      </div>
      <div className="export-meta"><span>{preview ? `${number.format(preview.byteCount)} bytes` : "Generating preview"}</span><code>{preview?.policyVersion ? `policy ${preview.policyVersion}` : ""}</code></div>
      <pre className="export-preview" aria-label="Export JSON preview">{preview?.content ?? ""}</pre>
      {preview && preview.redactions.length > 0 && <div className="export-redactions"><strong>Replacements</strong>{preview.redactions.map((redaction, index) => <span key={`${redaction.pointer}-${redaction.category}-${index}`}><code>{redaction.category}</code><code title={redaction.pointer}>{redaction.pointer}</code></span>)}</div>}
      {error && <div className="export-error" role="alert"><AlertTriangle size={14} />{error}</div>}
      {savedPath && <div className="export-success" role="status"><ShieldCheck size={14} /><span>Saved</span><code title={savedPath}>{savedPath}</code></div>}
      <footer><button onClick={onClose} disabled={saving}>{savedPath ? "Done" : "Cancel"}</button>{!savedPath && <button className="primary-command" onClick={savePreview} disabled={!preview || saving}>{saving ? <LoaderCircle className="is-spinning" size={14} /> : <Download size={14} />}Save JSON</button>}</footer>
    </section>
  </div>;
}

function AnatomyView({ sections, raw, onLocate }: { sections: AnatomySection[]; raw: CapturedRequest["detail"]["raw"]; onLocate: (source: string) => void }) {
  const [open, setOpen] = useState(() => new Set(["instructions", "messages"]));
  const toggle = (id: string) => setOpen((current) => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  return <div className="anatomy-view">{sections.map((section) => (
    <section className="anatomy-section" key={section.id}>
      <button className="anatomy-heading" aria-expanded={open.has(section.id)} onClick={() => toggle(section.id)}>
        {open.has(section.id) ? <ChevronDown size={15} /> : <ChevronRight size={15} />}<strong>{section.title}</strong><span>{section.count}</span>{section.tokenCount != null && <b>{number.format(section.tokenCount)} tok</b>}<EvidenceBadge level={section.evidence} />
      </button>
      {open.has(section.id) && <div className="anatomy-items">{section.items.length ? section.items.map((item) => {
        const pointer = resolveEvidencePointer(raw, item.source);
        return <article className="anatomy-item" key={item.id}><div><span className={`role-label role-${item.role ?? "field"}`}>{item.label}</span><button className="evidence-link" disabled={!pointer} title={pointer ? "Show raw evidence" : "Raw evidence is unavailable for this derived value"} aria-label={pointer ? `Show raw evidence for ${item.label}` : `Raw evidence unavailable for ${item.label}`} onClick={() => onLocate(item.source)}><LocateFixed size={12} /><code>{item.source}</code></button></div><p>{item.content}</p></article>;
      }) : <div className="empty-section">No tools were included in this request.</div>}</div>}
    </section>
  ))}</div>;
}

function TimelineView({ request, onLocate }: { request: CapturedRequest; onLocate: (locator: EvidenceLocator) => void }) {
  return <div className="timeline-view">{request.detail.timeline.map((event) => {
    const locator = event.locator && resolveEvidenceLocator(request.detail.raw, event.locator) ? event.locator : null;
    return <article className="timeline-event" key={event.id}><div className={`timeline-dot event-${event.kind}`} /><time>{event.offsetMs == null ? `#${event.sequence ?? "?"}` : `+${event.offsetMs} ms`}</time><div><strong>{event.title}</strong><p>{event.detail}</p></div>{locator && <button className="timeline-locate" title="Show raw evidence" aria-label={`Show raw evidence for ${event.title}`} onClick={() => onLocate(locator)}><LocateFixed size={14} /></button>}</article>;
  })}</div>;
}

function RawView({ request, evidence }: { request: CapturedRequest; evidence: ResolvedRawEvidence | null }) {
  const highlightedRef = useRef<HTMLSpanElement>(null);
  const lines = useMemo(() => formatRawJson(request.detail.raw), [request.detail.raw]);
  const pointer = evidence?.pointer ?? null;
  useEffect(() => { highlightedRef.current?.scrollIntoView?.({ block: "center" }); }, [pointer]);
  return <div className="raw-view">
    <div className="raw-banner"><ShieldCheck size={14} /><span>Authorization, cookies, and API key headers are excluded before this view.</span></div>
    {evidence && <div className="raw-location" role="status"><LocateFixed size={13} /><span>Evidence</span><code>{evidence.pointer}</code>{evidence.start != null && evidence.end != null && <b>bytes {evidence.start}..{evidence.end}</b>}</div>}
    {evidence?.fragment && <pre className="raw-fragment" aria-label="Selected raw response frame">{evidence.fragment}</pre>}
    <pre aria-label="Raw JSON evidence">{lines.map((line, index) => <span key={`${line.pointer}-${index}`} ref={line.pointer === pointer ? highlightedRef : undefined} className={`raw-line${line.pointer === pointer ? " is-highlighted" : ""}`} data-pointer={line.pointer}>{line.text}</span>)}</pre>
  </div>;
}

function EvidenceBadge({ level }: { level: AnatomySection["evidence"] }) {
  return <span className={`evidence-badge evidence-${level}`}>{level}</span>;
}

function ResizeHandle({ label, onResize }: { label: string; onResize: (delta: number) => void }) {
  const start = (event: React.PointerEvent) => {
    event.currentTarget.setPointerCapture(event.pointerId);
    let x = event.clientX;
    const move = (moveEvent: PointerEvent) => { onResize(moveEvent.clientX - x); x = moveEvent.clientX; };
    const stop = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", stop); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", stop);
  };
  return <div className="resize-handle" role="separator" aria-label={label} aria-orientation="vertical" onPointerDown={start} />;
}

function EmptyInspector() {
  return <section className="empty-inspector"><Braces size={28} /><strong>Select a request</strong><span>Its Prompt Anatomy and raw evidence will appear here.</span></section>;
}

function LoadFailure({ detail, onRetry }: { detail: string; onRetry: () => void }) {
  return <section className="load-failure" role="alert"><AlertTriangle size={26} /><strong>Workspace unavailable</strong><p>{detail}</p><button onClick={onRetry}>Retry</button></section>;
}

function filteredRequests(requests: CapturedRequest[], query: string, provider: string, application: string, toolsOnly: boolean, errorsOnly: boolean) {
  const normalized = query.trim().toLowerCase();
  return requests.filter((request) => {
    const matchesText = !normalized || [request.application, request.provider, request.operation, request.model, request.promptPreview].some((value) => value.toLowerCase().includes(normalized));
    return matchesText && (provider === "All providers" || request.provider === provider) && (application === "All apps" || request.application === application) && (!toolsOnly || request.hasTools) && (!errorsOnly || request.status === "error");
  });
}

function formatTokens(tokens: number | null, source?: "reported" | "estimated" | null) {
  if (tokens == null) return "Tokens unknown";
  return `${source === "estimated" ? "~" : ""}${number.format(tokens)} tok`;
}

function formatCost(cost: number | null, source?: "reported" | "estimated" | null) {
  if (cost == null) return "Unknown";
  const formatted = cost < 0.01 ? cost.toFixed(6) : cost.toFixed(4);
  return `${source === "estimated" ? "~" : ""}$${formatted}`;
}

function formatDuration(milliseconds: number) {
  return milliseconds >= 1000 ? `${(milliseconds / 1000).toFixed(1)} s` : `${milliseconds} ms`;
}

function certificateSummary(certificate: CertificateAuthority) {
  if (certificate.state === "missing") return "Not generated";
  const state = certificate.state === "invalid" ? "Invalid" : "Ready";
  const trust = {
    trusted: "trusted",
    not_trusted: "not trusted",
    unsupported: "trust unsupported",
    unchecked: "trust unchecked",
  }[certificate.trust];
  return `${state} · ${trust}`;
}

function certificateDetail(certificate: CertificateAuthority) {
  return [
    certificate.detail,
    certificate.subject,
    certificate.fingerprintSha256,
    certificate.validUntilUnixMs == null ? null : `Valid until ${new Date(certificate.validUntilUnixMs).toLocaleDateString()}`,
    `Private material: ${certificate.privateMaterial}`,
    `System trust: ${certificate.trust}`,
  ].filter(Boolean).join("\n");
}

function clamp(value: number, minimum: number, maximum: number) {
  return Math.min(maximum, Math.max(minimum, value));
}
