import { beforeEach, describe, expect, it } from "vitest";
import credentialCorpus from "../../../policies/credential-corpus.v0.1.json";
import fixture from "./data/workspace.json";
import type { WorkspaceBootstrap } from "./types";
import {
  loadWorkspace,
  previewBetaMetrics,
  previewSupportBundle,
  searchWorkspace,
} from "./workspace";

describe("shared credential corpus", () => {
  beforeEach(() => {
    delete window.__TAURI_INTERNALS__;
    window.history.replaceState(null, "", "/");
  });

  it("builds a bounded thousand-request browser fixture for performance checks", async () => {
    window.history.replaceState(null, "", "/?fixtureRequests=1000");

    const workspace = await loadWorkspace();
    expect(workspace.capture.requestCount).toBe(1_000);
    expect(workspace.requests).toHaveLength(1_000);
    expect(workspace.requests[999].id).toBe("synthetic-request-999");
    expect(workspace.requests[999].promptPreview).toBe("Synthetic request 999");

    const matches = await searchWorkspace("Synthetic request 999");
    expect(matches.map((request) => request.id)).toEqual(["synthetic-request-999"]);
  });

  it("rejects browser fixture counts above the performance ceiling", async () => {
    window.history.replaceState(null, "", "/?fixtureRequests=1001");

    const workspace = await loadWorkspace();
    expect(workspace.requests).toHaveLength(fixture.requests.length);
  });

  it("redacts every declared browser fallback canary", async () => {
    const runtimeIssue = credentialCorpus.text_patterns
      .flatMap((pattern) => pattern.matches)
      .join("\n");
    const preview = await previewSupportBundle(
      fixture as unknown as WorkspaceBootstrap,
      runtimeIssue,
    );
    const document = JSON.parse(preview.content) as {
      diagnostics: { runtimeIssue: string };
    };

    for (const pattern of credentialCorpus.text_patterns) {
      expect(document.diagnostics.runtimeIssue).toContain(`[REDACTED:${pattern.category}]`);
      for (const secret of pattern.matches) {
        expect(document.diagnostics.runtimeIssue).not.toContain(secret);
      }
    }
    expect(preview.redactions).toHaveLength(
      credentialCorpus.text_patterns.flatMap((pattern) => pattern.matches).length,
    );
  });

  it("preserves every declared near miss", async () => {
    const runtimeIssue = credentialCorpus.text_patterns
      .flatMap((pattern) => pattern.non_matches)
      .join("\n");
    const preview = await previewSupportBundle(
      fixture as unknown as WorkspaceBootstrap,
      runtimeIssue,
    );
    const document = JSON.parse(preview.content) as {
      diagnostics: { runtimeIssue: string };
    };

    expect(document.diagnostics.runtimeIssue).toBe(runtimeIssue);
    expect(preview.redactions).toHaveLength(0);
  });

  it("builds content-free local Beta evidence", async () => {
    const preview = await previewBetaMetrics();
    const document = JSON.parse(preview.content) as {
      privacy: Record<string, boolean>;
      metrics: Record<string, number>;
    };

    expect(preview.parseRateBasisPoints).toBe(9_875);
    expect(preview.crashFreeRateBasisPoints).toBe(9_968);
    expect(document.privacy.requestContentIncluded).toBe(false);
    expect(document.privacy.requestIdentifiersIncluded).toBe(false);
    expect(document.privacy.automaticUpload).toBe(false);
    expect(document).not.toHaveProperty("requests");
    expect(document).not.toHaveProperty("logs");
    expect(preview.content).not.toContain(fixture.requests[0].promptPreview);
  });
});
