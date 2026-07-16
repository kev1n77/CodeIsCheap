import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import fixture from "./data/workspace.json";
import type { CaptureMode, WorkspaceBootstrap } from "./types";

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
