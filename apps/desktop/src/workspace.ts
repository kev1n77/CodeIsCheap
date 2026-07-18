import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import fixture from "./data/workspace.json";
import credentialCorpus from "../../../policies/credential-corpus.v0.1.json";
import type {
  CaptureMode,
  CapturedRequest,
  ExportPreview,
  ExportProfile,
  ExportReceipt,
  SupportBundlePreview,
  WorkspaceBootstrap,
} from "./types";
import { requestSearchText } from "./compare";

export interface CaptureUpdated {
  captureId: string;
}

export interface CaptureRuntimeError {
  code: string;
  detail: string;
}

const MAX_BATCH_EXPORT_REQUESTS = 200;

export async function loadWorkspace(): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("bootstrap_workspace");
  }
  return fixture as unknown as WorkspaceBootstrap;
}

export async function searchWorkspace(query: string): Promise<CapturedRequest[]> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<CapturedRequest[]>("search_workspace", { query });
  }
  const normalized = query.trim().toLocaleLowerCase();
  if (!normalized) return structuredClone(fixture.requests) as unknown as CapturedRequest[];
  return (structuredClone(fixture.requests) as unknown as CapturedRequest[])
    .filter((request) => requestSearchText(request).includes(normalized));
}

export async function setCaptureActive(active: boolean): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("set_capture_active", { active });
  }
  const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
  workspace.capture.active = active;
  workspace.compatibility = active
    ? structuredClone((fixture as unknown as WorkspaceBootstrap).compatibility)
    : {
        code: "capture_paused",
        status: "attention",
        confidence: "high",
        title: "Gateway capture paused",
        summary: "Traffic can still be forwarded, but new requests are not being recorded.",
        recommendedMode: "gateway",
        action: "resume_capture",
        steps: [
          { id: "gateway_runtime", status: "pass", label: "Local Gateway", detail: workspace.capture.endpoint },
          { id: "certificate_interception", status: "pass", label: "Certificate interception", detail: "Not required in Gateway mode" },
          { id: "recording", status: "attention", label: "Recording", detail: "Paused" },
        ],
      };
  return workspace;
}

export async function setCaptureMode(mode: CaptureMode): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("set_capture_mode", { mode });
  }
  const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
  workspace.capture = { ...workspace.capture, mode };
  return workspace;
}

export async function installCertificateAuthorityTrust(): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("install_certificate_authority_trust");
  }
  return structuredClone(fixture) as unknown as WorkspaceBootstrap;
}

export async function uninstallCertificateAuthorityTrust(): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("uninstall_certificate_authority_trust");
  }
  return structuredClone(fixture) as unknown as WorkspaceBootstrap;
}

export async function previewCaptureExport(
  captureId: string,
  profile: ExportProfile,
): Promise<ExportPreview> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<ExportPreview>("preview_capture_export", { captureId, profile });
  }
  const workspace = fixture as unknown as WorkspaceBootstrap;
  const request = workspace.requests.find((candidate) => candidate.id === captureId);
  if (!request) throw new Error(`Capture ${captureId} is unavailable for export.`);
  return fixtureExportPreview(request, profile);
}

export async function saveCaptureExport(
  captureId: string,
  preview: ExportPreview,
): Promise<ExportReceipt | null> {
  if (window.__TAURI_INTERNALS__) {
    const path = await save({
      defaultPath: preview.suggestedFilename,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!path) return null;
    return invoke<ExportReceipt>("write_capture_export", {
      captureId,
      profile: preview.profile,
      exportedAtUnixMs: preview.exportedAtUnixMs,
      expectedSha256: preview.contentSha256,
      path,
    });
  }
  const url = URL.createObjectURL(new Blob([preview.content], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = preview.suggestedFilename;
  anchor.click();
  URL.revokeObjectURL(url);
  return {
    path: preview.suggestedFilename,
    byteCount: preview.byteCount,
    redactionCount: preview.redactions.length,
  };
}

export async function previewBatchCaptureExport(
  captureIds: string[],
  profile: ExportProfile,
): Promise<ExportPreview> {
  validateBatchCaptureIds(captureIds);
  if (window.__TAURI_INTERNALS__) {
    return invoke<ExportPreview>("preview_batch_capture_export", { captureIds, profile });
  }
  const workspace = fixture as unknown as WorkspaceBootstrap;
  const requests = captureIds.map((captureId) => {
    const request = workspace.requests.find((candidate) => candidate.id === captureId);
    if (!request) throw new Error(`Capture ${captureId} is unavailable for export.`);
    return request;
  });
  return fixtureBatchExportPreview(requests, profile);
}

export async function saveBatchCaptureExport(
  captureIds: string[],
  preview: ExportPreview,
): Promise<ExportReceipt | null> {
  validateBatchCaptureIds(captureIds);
  if (window.__TAURI_INTERNALS__) {
    const path = await save({
      defaultPath: preview.suggestedFilename,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!path) return null;
    return invoke<ExportReceipt>("write_batch_capture_export", {
      captureIds,
      profile: preview.profile,
      exportedAtUnixMs: preview.exportedAtUnixMs,
      expectedSha256: preview.contentSha256,
      path,
    });
  }
  return downloadExportPreview(preview);
}

export async function previewSupportBundle(
  workspace: WorkspaceBootstrap,
  runtimeIssue: string | null,
): Promise<SupportBundlePreview> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<SupportBundlePreview>("preview_support_bundle", { runtimeIssue });
  }
  return fixtureSupportBundlePreview(workspace, runtimeIssue);
}

export async function saveSupportBundle(
  runtimeIssue: string | null,
  preview: SupportBundlePreview,
): Promise<ExportReceipt | null> {
  if (window.__TAURI_INTERNALS__) {
    const path = await save({
      defaultPath: preview.suggestedFilename,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    if (!path) return null;
    return invoke<ExportReceipt>("write_support_bundle", {
      runtimeIssue,
      generatedAtUnixMs: preview.generatedAtUnixMs,
      expectedSha256: preview.contentSha256,
      path,
    });
  }
  return downloadJsonDocument(preview);
}

export async function subscribeToCaptureEvents(handlers: {
  onUpdated: (event: CaptureUpdated) => void;
  onError: (event: CaptureRuntimeError) => void;
}): Promise<() => void> {
  if (!window.__TAURI_INTERNALS__) {
    return () => {};
  }

  const unlistenUpdated = await listen<CaptureUpdated>("capture-updated", ({ payload }) => {
    handlers.onUpdated(payload);
  });
  try {
    const unlistenError = await listen<CaptureRuntimeError>(
      "capture-runtime-error",
      ({ payload }) => handlers.onError(payload),
    );
    return () => {
      unlistenUpdated();
      unlistenError();
    };
  } catch (error) {
    unlistenUpdated();
    throw error;
  }
}

async function fixtureExportPreview(
  request: CapturedRequest,
  profile: ExportProfile,
): Promise<ExportPreview> {
  const exportedAtUnixMs = Date.now();
  return finishFixtureExport(
    {
      formatVersion: "0.1",
      policyVersion: "0.1",
      desktopApiVersion: "0.1",
      profile,
      exportedAtUnixMs,
      request: fixtureExportPayload(request, profile),
    },
    profile,
    exportedAtUnixMs,
    `codeischeap-${request.id.replace(/[^a-z0-9_-]/gi, "_")}-${profile}.json`,
  );
}

async function fixtureBatchExportPreview(
  requests: CapturedRequest[],
  profile: ExportProfile,
): Promise<ExportPreview> {
  const exportedAtUnixMs = Date.now();
  return finishFixtureExport(
    {
      formatVersion: "0.1",
      policyVersion: "0.1",
      desktopApiVersion: "0.1",
      profile,
      exportedAtUnixMs,
      requestCount: requests.length,
      requests: requests.map((request) => fixtureExportPayload(request, profile)),
    },
    profile,
    exportedAtUnixMs,
    `codeischeap-batch-${requests.length}-${profile}.json`,
  );
}

async function fixtureSupportBundlePreview(
  workspace: WorkspaceBootstrap,
  runtimeIssue: string | null,
): Promise<SupportBundlePreview> {
  const generatedAtUnixMs = Date.now();
  const scannedIssue = fixtureCredentialScan(runtimeIssue);
  const certificate = workspace.capture.certificateAuthority;
  const content = `${JSON.stringify({
    formatVersion: "0.1",
    policyVersion: "0.1",
    generatedAtUnixMs,
    product: {
      name: "CodeIsCheap",
      version: "0.1.0",
      desktopApiVersion: workspace.apiVersion,
      platform: navigator.platform || "web",
      architecture: "web",
    },
    privacy: {
      requestContentIncluded: false,
      requestIdentifiersIncluded: false,
      rawCaptureIncluded: false,
      logsIncluded: false,
      logDetailsIncluded: false,
    },
    diagnostics: {
      source: workspace.source,
      capture: {
        active: workspace.capture.active,
        canControl: workspace.capture.canControl,
        mode: workspace.capture.mode,
        endpoint: workspace.capture.endpoint,
        profile: workspace.capture.profile,
        proxyAvailable: workspace.capture.proxyAvailable,
        requestCount: workspace.capture.requestCount,
        storage: workspace.capture.storage,
      },
      certificateAuthority: {
        state: certificate.state,
        trust: certificate.trust,
        privateMaterial: certificate.privateMaterial,
        canManageTrust: certificate.canManageTrust,
        fingerprintSha256: certificate.fingerprintSha256,
      },
      health: {
        encryptedStore: workspace.capture.storage.toLocaleLowerCase().includes("sqlcipher")
          || workspace.source === "synthetic_fixture",
        captureRuntime: runtimeIssue == null,
        endpointConnected: workspace.capture.endpoint !== "Not connected",
        proxyBundle: workspace.capture.proxyAvailable,
      },
      compatibility: workspace.compatibility,
      runtimeIssue: scannedIssue.value,
      diagnosticEvents: [],
    },
    redactionCount: scannedIssue.redactions.length,
  }, null, 2)}\n`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
  return {
    suggestedFilename: `codeischeap-support-${generatedAtUnixMs}.json`,
    content,
    byteCount: new TextEncoder().encode(content).length,
    contentSha256: hexDigest(digest),
    generatedAtUnixMs,
    redactions: scannedIssue.redactions,
    policyVersion: "0.1",
    formatVersion: "0.1",
  };
}

function fixtureExportPayload(request: CapturedRequest, profile: ExportProfile): unknown {
  const metadata = {
    id: request.id,
    observedAtUnixMs: request.observedAtUnixMs,
    application: request.application,
    applicationSource: request.applicationSource,
    applicationConfidence: request.applicationConfidence,
    applicationProcessId: request.applicationProcessId,
    provider: request.provider,
    operation: request.operation,
    model: request.model,
    tokens: request.tokens,
    durationMs: request.durationMs,
    status: request.status,
    hasTools: request.hasTools,
  };
  const minimalAnatomy = request.detail.anatomy.map((section) => ({
    id: section.id,
    title: section.title,
    count: section.count,
    evidence: section.evidence,
    items: section.items.map((item) => ({
      label: item.label,
      role: item.role,
      content: item.content,
    })),
  }));
  const payload = {
    minimal: {
      metadata,
      promptPreview: request.promptPreview,
      anatomy: minimalAnatomy,
    },
    reproducible: {
      metadata,
      promptPreview: request.promptPreview,
      anatomy: request.detail.anatomy,
      parameters: fixtureReproductionParameters(request),
    },
    forensic: {
      metadata,
      promptPreview: request.promptPreview,
      ...request.detail,
    },
  }[profile];
  return payload;
}

async function finishFixtureExport(
  document: Record<string, unknown>,
  profile: ExportProfile,
  exportedAtUnixMs: number,
  suggestedFilename: string,
): Promise<ExportPreview> {
  const content = `${JSON.stringify({ ...document, redactionCount: 0 }, null, 2)}\n`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
  const contentSha256 = hexDigest(digest);
  return {
    profile,
    suggestedFilename,
    content,
    byteCount: new TextEncoder().encode(content).length,
    contentSha256,
    exportedAtUnixMs,
    redactions: [],
    policyVersion: "0.1",
  };
}

function validateBatchCaptureIds(captureIds: string[]): void {
  if (captureIds.length === 0) throw new Error("Batch export requires at least one capture.");
  if (captureIds.length > MAX_BATCH_EXPORT_REQUESTS) {
    throw new Error(`Batch export supports at most ${MAX_BATCH_EXPORT_REQUESTS} captures.`);
  }
  const unique = new Set(captureIds);
  if (unique.size !== captureIds.length) {
    throw new Error("Batch export cannot contain duplicate capture IDs.");
  }
  if (captureIds.some((captureId) => captureId.length === 0)) {
    throw new Error("Batch export capture IDs cannot be empty.");
  }
}

function downloadExportPreview(preview: ExportPreview): ExportReceipt {
  return downloadJsonDocument(preview);
}

function downloadJsonDocument(preview: {
  suggestedFilename: string;
  content: string;
  byteCount: number;
  redactions: Array<unknown>;
}): ExportReceipt {
  const url = URL.createObjectURL(new Blob([preview.content], { type: "application/json" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = preview.suggestedFilename;
  anchor.click();
  URL.revokeObjectURL(url);
  return {
    path: preview.suggestedFilename,
    byteCount: preview.byteCount,
    redactionCount: preview.redactions.length,
  };
}

function hexDigest(digest: ArrayBuffer): string {
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fixtureCredentialScan(value: string | null): {
  value: string | null;
  redactions: Array<{ category: string; pointer: string }>;
} {
  if (value == null) return { value, redactions: [] };
  const redactions: Array<{ category: string; pointer: string }> = [];
  const scanned = credentialCorpus.text_patterns.reduce((current, pattern) => {
    const caseInsensitive = pattern.expression.startsWith("(?i)");
    const expression = caseInsensitive ? pattern.expression.slice(4) : pattern.expression;
    return current.replace(
      new RegExp(expression, caseInsensitive ? "gi" : "g"),
      () => {
        redactions.push({ category: pattern.category, pointer: "/diagnostics/runtimeIssue" });
        return `[REDACTED:${pattern.category}]`;
      },
    );
  }, value);
  return { value: scanned, redactions };
}

function fixtureReproductionParameters(request: CapturedRequest): Record<string, unknown> {
  const raw = request.detail.raw;
  if (!raw || Array.isArray(raw) || typeof raw !== "object") return {};
  const requestEnvelope = raw.request;
  if (!requestEnvelope || Array.isArray(requestEnvelope) || typeof requestEnvelope !== "object") {
    return {};
  }
  const body = requestEnvelope.body;
  if (!body || Array.isArray(body) || typeof body !== "object") return {};
  const keys = [
    "model",
    "temperature",
    "top_p",
    "max_tokens",
    "max_output_tokens",
    "stream",
    "tool_choice",
    "parallel_tool_calls",
    "response_format",
    "tools",
  ];
  return Object.fromEntries(keys.filter((key) => key in body).map((key) => [key, body[key]]));
}
