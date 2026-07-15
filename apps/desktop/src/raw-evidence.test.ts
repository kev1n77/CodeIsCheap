import { describe, expect, it } from "vitest";
import fixture from "./data/workspace.json";
import { formatRawJson, resolveEvidencePointer } from "./raw-evidence";
import type { WorkspaceBootstrap } from "./types";

describe("raw evidence", () => {
  it("resolves direct and captured-request JSON pointers", () => {
    expect(resolveEvidencePointer({ messages: [{ content: "hello" }] }, "/messages/0/content"))
      .toBe("/messages/0/content");
    expect(resolveEvidencePointer({ request: { body: { model: "gpt" } } }, "/model"))
      .toBe("/request/body/model");
    expect(resolveEvidencePointer({ model: "gpt" }, "Prompt IR")).toBeNull();
    expect(resolveEvidencePointer({ model: "gpt" }, "/missing")).toBeNull();
  });

  it("assigns stable pointers to formatted JSON lines", () => {
    const lines = formatRawJson({ "a/b": [{ value: true }] });

    expect(lines).toContainEqual(expect.objectContaining({ pointer: "/a~1b/0" }));
    expect(lines).toContainEqual({ pointer: "/a~1b/0/value", text: "      \"value\": true" });
  });

  it("keeps every synthetic Anatomy item connected to raw evidence", () => {
    const workspace = fixture as unknown as WorkspaceBootstrap;

    for (const request of workspace.requests) {
      for (const item of request.detail.anatomy.flatMap((section) => section.items)) {
        expect(resolveEvidencePointer(request.detail.raw, item.source), `${request.id}:${item.id}`)
          .not.toBeNull();
      }
    }
  });
});
