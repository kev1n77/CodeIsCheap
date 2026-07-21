import { beforeEach, describe, expect, it } from "vitest";
import credentialCorpus from "../../../policies/credential-corpus.v0.1.json";
import fixture from "./data/workspace.json";
import type { WorkspaceBootstrap } from "./types";
import { loadWorkspace, previewSupportBundle, searchWorkspace } from "./workspace";

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
});
