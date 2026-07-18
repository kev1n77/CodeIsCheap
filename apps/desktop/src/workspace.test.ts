import { beforeEach, describe, expect, it } from "vitest";
import credentialCorpus from "../../../policies/credential-corpus.v0.1.json";
import fixture from "./data/workspace.json";
import type { WorkspaceBootstrap } from "./types";
import { previewSupportBundle } from "./workspace";

describe("shared credential corpus", () => {
  beforeEach(() => {
    delete window.__TAURI_INTERNALS__;
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
