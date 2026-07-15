import { invoke } from "@tauri-apps/api/core";
import fixture from "./data/workspace.json";
import type { WorkspaceBootstrap } from "./types";

export async function loadWorkspace(): Promise<WorkspaceBootstrap> {
  if (window.__TAURI_INTERNALS__) {
    return invoke<WorkspaceBootstrap>("bootstrap_workspace");
  }
  return fixture as unknown as WorkspaceBootstrap;
}
