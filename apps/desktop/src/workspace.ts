import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import fixture from "./data/workspace.json";
import type {
  CaptureMode,
  CapturedRequest,
  ExportPreview,
  ExportProfile,
  ExportReceipt,
  WorkspaceBootstrap,
} from "./types";

export interface CaptureUpdated {
  captureId: string;
}

export interface CaptureRuntimeError {
  code: string;
  detail: string;
}

export async function loadWorkspace(): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("bootstrap_workspace");
  }
  return fixture as unknown as WorkspaceBootstrap;
}

export async function setCaptureActive(active: boolean): Promise<boolean> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<boolean>("set_capture_active", { active });
  }
  return active;
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
  const metadata = {
    id: request.id,
    observedAtUnixMs: request.observedAtUnixMs,
    application: request.application,
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
  const content = `${JSON.stringify({
    formatVersion: "0.1",
    policyVersion: "0.1",
    desktopApiVersion: "0.1",
    profile,
    exportedAtUnixMs,
    redactionCount: 0,
    request: payload,
  }, null, 2)}\n`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(content));
  const contentSha256 = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return {
    profile,
    suggestedFilename: `codeischeap-${request.id.replace(/[^a-z0-9_-]/gi, "_")}-${profile}.json`,
    content,
    byteCount: new TextEncoder().encode(content).length,
    contentSha256,
    exportedAtUnixMs,
    redactions: [],
    policyVersion: "0.1",
  };
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
