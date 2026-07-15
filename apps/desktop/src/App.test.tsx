import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import fixture from "./data/workspace.json";
import type { WorkspaceBootstrap } from "./types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

describe("request workbench", () => {
  beforeEach(() => {
    localStorage.clear();
    delete window.__TAURI_INTERNALS__;
    vi.mocked(invoke).mockReset();
    vi.mocked(listen).mockReset();
    vi.mocked(listen).mockResolvedValue(() => {});
  });

  it("filters requests without losing the inspector workflow", async () => {
    const user = userEvent.setup();
    render(<App />);
    const search = await screen.findByRole("textbox", { name: "Search requests" });
    const listbox = screen.getByRole("listbox", { name: "Request results" });
    expect(within(listbox).getAllByRole("option")).toHaveLength(6);
    expect(screen.getByRole("button", { name: "Pause capture" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Gateway" })).toBeDisabled();

    await user.type(search, "migration plan");
    const results = within(listbox).getAllByRole("option");
    expect(results).toHaveLength(1);
    expect(within(results[0]).getByText("Terminal")).toBeInTheDocument();
    await user.click(results[0]);
    expect(screen.getByRole("heading", { name: "gpt-4.1" })).toBeInTheDocument();
  });

  it("combines tool and error filters", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Requests");

    await user.click(screen.getByRole("checkbox", { name: /Has tools/ }));
    await user.click(screen.getByRole("checkbox", { name: /Errors/ }));

    const listbox = screen.getByRole("listbox", { name: "Request results" });
    const results = within(listbox).getAllByRole("option");
    expect(results).toHaveLength(1);
    expect(within(results[0]).getByText("Google")).toBeInTheDocument();
  });

  it("switches between anatomy, timeline, and scrubbed raw evidence", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });

    await user.click(screen.getByRole("button", { name: /Timeline/ }));
    expect(screen.getByText("Credentials removed")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Raw/ }));
    expect(screen.getByText(/Authorization, cookies/)).toBeInTheDocument();
    expect(screen.getByText(/credentials_persisted/)).toBeInTheDocument();
  });

  it("shows a retryable failure when the encrypted workspace cannot open", async () => {
    window.__TAURI_INTERNALS__ = {};
    vi.mocked(invoke).mockRejectedValueOnce(new Error("OS credential store is locked"));

    render(<App />);

    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("Workspace unavailable")).toBeInTheDocument();
    expect(within(alert).getByText("OS credential store is locked")).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("refreshes live captures and controls gateway recording", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    let workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.capture = {
      ...workspace.capture,
      active: true,
      canControl: true,
      endpoint: "http://127.0.0.1:8787",
    };
    let notifyCaptureUpdated = () => {};
    vi.mocked(listen).mockImplementation(async (event, handler) => {
      if (event === "capture-updated") {
        notifyCaptureUpdated = () => handler({
          event: "capture-updated",
          id: 1,
          payload: { captureId: "live-capture" },
        });
      }
      return () => {};
    });
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "set_capture_active") return Boolean(args?.active);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    const pause = await screen.findByRole("button", { name: "Pause capture" });
    expect(pause).toBeEnabled();
    expect(screen.getByText("http://127.0.0.1:8787")).toBeInTheDocument();

    await user.click(pause);
    expect(invoke).toHaveBeenCalledWith("set_capture_active", { active: false });
    expect(await screen.findByRole("button", { name: "Resume capture" })).toBeEnabled();

    workspace = {
      ...workspace,
      capture: { ...workspace.capture, active: false, requestCount: workspace.requests.length + 1 },
      requests: [
        {
          ...workspace.requests[0],
          id: "live-capture",
          promptPreview: "Live capture arrived",
        },
        ...workspace.requests,
      ],
    };
    await act(async () => notifyCaptureUpdated());

    expect(await screen.findByText("Live capture arrived")).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("bootstrap_workspace");
  });
});
