import { describe, expect, it } from "vitest";
import fixture from "./data/workspace.json";
import type { CapturedRequest, WorkspaceBootstrap } from "./types";
import { comparePromptText, compareStructure, requestSearchText } from "./compare";

const workspace = fixture as unknown as WorkspaceBootstrap;

describe("request comparison", () => {
  it("produces stable structural changes for messages, tools, and parameters", () => {
    const left = structuredClone(workspace.requests[0]);
    const right = structuredClone(left);
    right.id = "right";
    right.detail.anatomy.find((section) => section.id === "messages")!.items[0].content = "Changed prompt";
    right.detail.anatomy.find((section) => section.id === "tools")!.items.push({
      id: "new-tool",
      label: "write_file",
      role: null,
      content: "Write a file",
      source: "/tools/1",
    });

    const result = compareStructure(left, right);

    expect(result.counts.changed).toBe(1);
    expect(result.counts.added).toBe(1);
    expect(result.rows.find((row) => row.sectionId === "tools" && row.label === "write_file"))
      .toMatchObject({ status: "added", left: null, right: "Write a file" });
    expect(compareStructure(left, right)).toEqual(result);
  });

  it("uses a proven word diff for prompt text", () => {
    const left = structuredClone(workspace.requests[0]);
    const right = structuredClone(left);
    right.detail.anatomy.find((section) => section.id === "messages")!.items[0].content = "Inspect the fixed parser";

    const segments = comparePromptText(left, right);

    expect(segments.some((segment) => segment.status === "removed")).toBe(true);
    expect(segments.some((segment) => segment.status === "added")).toBe(true);
  });

  it("indexes full structured prompt content for local fixture search", () => {
    const request = workspace.requests[0] as CapturedRequest;
    expect(requestSearchText(request)).toContain(request.detail.anatomy[0].items[0].content.toLowerCase());
  });
});
