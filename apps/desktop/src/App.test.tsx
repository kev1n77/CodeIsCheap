import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { save } from "@tauri-apps/plugin-dialog";
import axe from "axe-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import fixture from "./data/workspace.json";
import type {
  ExportPreview,
  ExportProfile,
  SupportBundlePreview,
  WorkspaceBootstrap,
} from "./types";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn() }));

function makeWorkspace(requestCount: number): WorkspaceBootstrap {
  const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
  const template = workspace.requests[0];
  workspace.requests = Array.from({ length: requestCount }, (_, index) => ({
    ...template,
    id: `request-${index}`,
    model: `model-${index}`,
    promptPreview: `Synthetic request ${index}`,
    observedAtUnixMs: template.observedAtUnixMs - index,
  }));
  workspace.capture = { ...workspace.capture, requestCount };
  return workspace;
}

function workspacePrompt(workspace: WorkspaceBootstrap) {
  return workspace.requests[0].promptPreview;
}

describe("request workbench", () => {
  beforeEach(() => {
    localStorage.clear();
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024 });
    delete window.__TAURI_INTERNALS__;
    vi.mocked(invoke).mockReset();
    vi.mocked(listen).mockReset();
    vi.mocked(listen).mockResolvedValue(() => {});
    vi.mocked(save).mockReset();
  });

  it("filters requests without losing the inspector workflow", async () => {
    const user = userEvent.setup();
    render(<App />);
    const search = await screen.findByRole("textbox", { name: "Search requests" });
    const listbox = screen.getByRole("listbox", { name: "Request results" });
    expect(within(listbox).getAllByRole("option")).toHaveLength(6);
    expect(screen.getByRole("button", { name: "Pause capture" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Gateway" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Proxy" })).toBeDisabled();

    await user.type(search, "migration plan");
    const results = within(listbox).getAllByRole("option");
    expect(results).toHaveLength(1);
    expect(within(results[0]).getByText("Terminal")).toBeInTheDocument();
    await user.click(results[0]);
    expect(screen.getByRole("heading", { name: "gpt-4.1" })).toBeInTheDocument();
  });

  it("shows application attribution confidence and evidence source", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.requests[1].applicationProcessId = 4242;
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      throw new Error(`Unexpected command: ${command}`);
    });
    render(<App />);

    const listbox = await screen.findByRole("listbox", { name: "Request results" });
    const requests = within(listbox).getAllByRole("option");
    expect(within(requests[0]).getByText("high")).toBeInTheDocument();
    expect(within(requests[1]).getByText("medium")).toBeInTheDocument();
    expect(within(requests[5]).getByText("low")).toBeInTheDocument();

    await user.click(requests[1]);
    const inspector = screen.getByRole("region", { name: "Request inspector" });
    expect(within(inspector).getByText("Chrome")).toBeInTheDocument();
    expect(within(inspector).getByText("medium")).toBeInTheDocument();
    expect(within(inspector).getByText("user agent")).toBeInTheDocument();
    expect(within(inspector).getByText("PID 4242")).toBeInTheDocument();
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

  it("opens settings, exposes diagnostics, and closes with Escape", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Requests");

    const settingsButton = screen.getByRole("button", { name: "Settings" });
    await user.click(settingsButton);
    const dialog = screen.getByRole("dialog", { name: "Settings & diagnostics" });
    const close = within(dialog).getByRole("button", { name: "Close settings" });
    expect(close).toHaveFocus();
    await user.tab({ shift: true });
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
    await user.tab();
    expect(close).toHaveFocus();
    const connectionTab = within(dialog).getByRole("tab", { name: "Connection" });
    expect(connectionTab)
      .toHaveAttribute("aria-selected", "true");
    connectionTab.focus();
    await user.keyboard("{ArrowRight}");
    expect(within(dialog).getByRole("tab", { name: "Diagnostics" }))
      .toHaveAttribute("aria-selected", "true");
    const preview = within(dialog).getByLabelText("Diagnostic report preview");
    await waitFor(() => expect(preview).toHaveTextContent("requestCount"));
    expect(preview).not.toHaveTextContent(workspacePrompt(fixture as unknown as WorkspaceBootstrap));
    expect(preview).toHaveTextContent('"requestContentIncluded": false');
    await user.click(within(dialog).getByRole("button", { name: "Copy report" }));
    expect(within(dialog).getByRole("button", { name: "Copied" })).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "Settings & diagnostics" })).not.toBeInTheDocument();
    expect(settingsButton).toHaveFocus();
  });

  it("checks and installs only the version returned by the signed update channel", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") {
        return structuredClone(fixture) as unknown as WorkspaceBootstrap;
      }
      if (command === "check_for_update") {
        return {
          configured: true,
          currentVersion: "0.1.0",
          availableVersion: "0.2.0",
          notes: "Security and recovery fixes",
          publishedAt: "2026-07-21T00:00:00Z",
        };
      }
      if (command === "install_update") return undefined;
      throw new Error(`Unexpected command: ${command}`);
    });
    render(<App />);
    await screen.findByText("Requests");
    await user.click(screen.getByRole("button", { name: "Settings" }));
    const dialog = screen.getByRole("dialog", { name: "Settings & diagnostics" });
    await user.click(within(dialog).getByRole("tab", { name: "Updates" }));
    await user.click(within(dialog).getByRole("button", { name: "Check" }));

    expect(await within(dialog).findByText("Version 0.2.0")).toBeInTheDocument();
    expect(within(dialog).getByText("Security and recovery fixes")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Install & restart" }));
    expect(invoke).toHaveBeenCalledWith("install_update", { expectedVersion: "0.2.0" });
    expect(within(dialog).getByText(/managed system proxy settings have been restored/)).toBeInTheDocument();
  });

  it("keeps recovery history searchable and exportable while disabling mutations", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.source = "recovery_backup";
    workspace.capture = {
      ...workspace.capture,
      active: false,
      canControl: false,
      proxyAvailable: false,
      endpoint: "Capture disabled",
      storage: `${workspace.capture.storage} / read-only recovery`,
    };
    const preview: ExportPreview = {
      profile: "minimal",
      suggestedFilename: "codeischeap-recovery-request.json",
      content: "{\"recovery\":true}\n",
      byteCount: 18,
      contentSha256: "d".repeat(64),
      exportedAtUnixMs: 1_700_000_000_200,
      redactions: [],
      policyVersion: "0.1",
    };
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "preview_capture_export") return preview;
      throw new Error(`Unexpected command: ${command}`);
    });

    const { container } = render(<App />);
    expect(await screen.findByRole("status", { name: "Read-only update recovery mode" }))
      .toHaveTextContent("searchable and exportable");
    expect(screen.getByText("Read-only", { selector: ".capture-indicator" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resume capture" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Gateway" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Proxy" })).toBeDisabled();

    await user.click(screen.getByRole("button", { name: "Export request" }));
    expect(await screen.findByRole("dialog", { name: "Export request" })).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("preview_capture_export", {
      captureId: workspace.requests[0].id,
      profile: "minimal",
    });
    await user.click(screen.getByRole("button", { name: "Close export" }));
    await user.click(screen.getByRole("button", { name: "Settings" }));
    const settings = screen.getByRole("dialog", { name: "Settings & diagnostics" });
    await user.click(within(settings).getByRole("tab", { name: "Updates" }));
    expect(within(settings).getByText("Updates are disabled")).toBeInTheDocument();
    expect(within(settings).getByRole("button", { name: "Check" })).toBeDisabled();
    expect((await axe.run(container, { rules: { "color-contrast": { enabled: false } } })).violations)
      .toEqual([]);
  });

  it("passes automated accessibility checks for the workspace and dialogs", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    await screen.findByText("Requests");
    const options = { rules: { "color-contrast": { enabled: false } } };

    const workspaceResults = await axe.run(container, options);
    expect(workspaceResults.violations.map((violation) => violation.id)).toEqual([]);

    await user.click(screen.getByRole("button", { name: "Settings" }));
    const settings = screen.getByRole("dialog", { name: "Settings & diagnostics" });
    const settingsResults = await axe.run(settings, options);
    expect(settingsResults.violations.map((violation) => violation.id)).toEqual([]);
    await user.keyboard("{Escape}");

    await user.click(screen.getByRole("button", { name: "Export request" }));
    const exportDialog = await screen.findByRole("dialog", { name: "Export request" });
    await within(exportDialog).findByText(/credential.*replaced/);
    const exportResults = await axe.run(exportDialog, options);
    expect(exportResults.violations.map((violation) => violation.id)).toEqual([]);
  });

  it("supports keyboard tabs and resizes both workspace panes", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Requests");

    const anatomy = screen.getByRole("tab", { name: "Anatomy" });
    anatomy.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Timeline" })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    const sidebar = screen.getByRole("separator", { name: "Resize capture sidebar" });
    expect(sidebar).toHaveAttribute("aria-valuenow", "218");
    sidebar.focus();
    await user.keyboard("{ArrowRight}");
    expect(sidebar).toHaveAttribute("aria-valuenow", "230");
    await user.keyboard("{End}");
    expect(sidebar).toHaveAttribute("aria-valuenow", "292");

    const requestList = screen.getByRole("separator", { name: "Resize request list" });
    requestList.focus();
    await user.keyboard("{Home}");
    expect(requestList).toHaveAttribute("aria-valuenow", "320");
  });

  it("preserves the inspector width budget at the minimum desktop viewport", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Requests");

    Object.defineProperty(window, "innerWidth", { configurable: true, value: 960 });
    act(() => window.dispatchEvent(new Event("resize")));

    const sidebar = screen.getByRole("separator", { name: "Resize capture sidebar" });
    const requestList = screen.getByRole("separator", { name: "Resize request list" });
    expect(sidebar).toHaveAttribute("aria-valuemax", "240");
    expect(requestList).toHaveAttribute("aria-valuemax", "412");

    sidebar.focus();
    await user.keyboard("{End}");
    expect(sidebar).toHaveAttribute("aria-valuenow", "240");
    expect(requestList).toHaveAttribute("aria-valuemax", "390");
    expect(screen.getByRole("main")).toHaveStyle({
      gridTemplateColumns: "240px 5px 390px 5px minmax(320px, 1fr)",
    });
  });

  it("previews and saves a scanned support bundle", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    const preview: SupportBundlePreview = {
      suggestedFilename: "codeischeap-support-1700000000200.json",
      content: "{\"privacy\":{\"requestContentIncluded\":false},\"redactionCount\":1}\n",
      byteCount: 73,
      contentSha256: "c".repeat(64),
      generatedAtUnixMs: 1_700_000_000_200,
      redactions: [{ category: "bearer_token", pointer: "/diagnostics/runtimeIssue" }],
      policyVersion: "0.1",
      formatVersion: "0.1",
    };
    vi.mocked(save).mockResolvedValue("D:\\exports\\support.json");
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "preview_support_bundle") return preview;
      if (command === "write_support_bundle") {
        return { path: args?.path, byteCount: preview.byteCount, redactionCount: 1 };
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Settings" }));
    const dialog = screen.getByRole("dialog", { name: "Settings & diagnostics" });
    await user.click(within(dialog).getByRole("tab", { name: "Diagnostics" }));
    expect(await within(dialog).findByText(/requestContentIncluded/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save support bundle" }));

    expect(save).toHaveBeenCalledWith({
      defaultPath: preview.suggestedFilename,
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    expect(invoke).toHaveBeenCalledWith("write_support_bundle", {
      runtimeIssue: null,
      generatedAtUnixMs: preview.generatedAtUnixMs,
      expectedSha256: preview.contentSha256,
      path: "D:\\exports\\support.json",
    });
    expect(await within(dialog).findByText("Support bundle saved")).toBeInTheDocument();
  });

  it("opens the connection flow for an empty first-run workspace", async () => {
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.requests = [];
    workspace.capture.requestCount = 0;
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);

    const dialog = await screen.findByRole("dialog", { name: "Settings & diagnostics" });
    expect(within(dialog).getByText("Waiting for the first request")).toBeInTheDocument();
    expect(within(dialog).getByRole("tab", { name: "Connection" }))
      .toHaveAttribute("aria-selected", "true");
  });

  it("returns an active proxy workspace to the safe Gateway from settings", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const proxy = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    proxy.capture = {
      ...proxy.capture,
      active: true,
      canControl: true,
      proxyAvailable: true,
      mode: "proxy",
      profile: "System-managed explicit TLS proxy",
      endpoint: "http://127.0.0.1:43125",
    };
    const gateway = structuredClone(proxy);
    gateway.capture.mode = "gateway";
    gateway.capture.profile = "OpenAI-compatible local gateway";
    gateway.capture.endpoint = "http://127.0.0.1:8787";
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(proxy);
      if (command === "set_capture_mode" && args?.mode === "gateway") return structuredClone(gateway);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Settings" }));
    await user.click(screen.getByRole("button", { name: "Return to Gateway" }));

    expect(invoke).toHaveBeenCalledWith("set_capture_mode", { mode: "gateway" });
    expect(await screen.findByText("OpenAI-compatible local gateway")).toBeInTheDocument();
  });

  it("compares two requests with structure and text views", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });

    await user.click(screen.getByRole("button", { name: "Compare request" }));
    expect(screen.getByRole("status")).toHaveTextContent("Select another request to compare");
    const options = within(screen.getByRole("listbox", { name: "Request results" }))
      .getAllByRole("option");
    await user.click(options[1]);

    const comparison = screen.getByRole("region", { name: "Request comparison" });
    expect(within(comparison).getAllByText("Baseline")).not.toHaveLength(0);
    expect(within(comparison).getAllByText("Target")).not.toHaveLength(0);
    expect(within(comparison).getByRole("tab", { name: "Structure" }))
      .toHaveAttribute("aria-selected", "true");
    await user.click(within(comparison).getByRole("tab", { name: "Text" }));
    expect(within(comparison).getByLabelText("Prompt text difference")).toBeInTheDocument();
    await user.click(within(comparison).getByRole("button", { name: "Close comparison" }));
    expect(screen.queryByRole("region", { name: "Request comparison" })).not.toBeInTheDocument();
  });

  it("supports keyboard comparison selection and cancellation", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });

    await user.keyboard("c");
    expect(screen.getByRole("status")).toHaveTextContent("Select another request to compare");
    await user.keyboard("{Escape}");
    expect(screen.queryByText("Select another request to compare")).not.toBeInTheDocument();
  });

  it("uses the encrypted full-text search command for native workspaces", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    const initial = { ...workspace, requests: [workspace.requests[0]] };
    const historical = { ...workspace.requests[5], id: "historical-result" };
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(initial);
      if (command === "search_workspace") return [structuredClone(historical)];
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.type(await screen.findByRole("textbox", { name: "Search requests" }), "historical prompt");

    expect(await screen.findByRole("heading", { name: historical.model })).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("search_workspace", { query: "historical prompt" });
  });

  it("keeps full-text search failures visible and retryable", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "search_workspace") throw new Error("FTS index is unavailable");
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.type(await screen.findByRole("textbox", { name: "Search requests" }), "parser");

    expect(await screen.findByRole("alert")).toHaveTextContent("FTS index is unavailable");
  });

  it("switches between anatomy, timeline, and scrubbed raw evidence", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });

    await user.click(screen.getByRole("tab", { name: /Timeline/ }));
    expect(screen.getByText("Credentials removed")).toBeInTheDocument();
    expect(screen.getByText("#0")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: /Raw/ }));
    expect(screen.getByText(/Authorization, cookies/)).toBeInTheDocument();
    expect(screen.getByText(/credentials_persisted/)).toBeInTheDocument();
  });

  it("locates an Anatomy item in highlighted raw JSON", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });

    await user.click(screen.getByRole("button", { name: "Show raw evidence for User" }));

    expect(screen.getByRole("tab", { name: "Raw" })).toHaveAttribute("aria-selected", "true");
    expect(within(screen.getByRole("status")).getByText("/request/body/messages/0/content")).toBeInTheDocument();
    const highlighted = container.querySelector('.raw-line.is-highlighted');
    expect(highlighted).toHaveAttribute("data-pointer", "/request/body/messages/0/content");
    expect(highlighted).toHaveTextContent("Inspect the failing authentication flow");
  });

  it("locates a Timeline stream event in the exact raw SSE frame", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });
    await user.click(screen.getByRole("tab", { name: "Timeline" }));

    await user.click(screen.getByRole("button", { name: "Show raw evidence for First response event" }));

    expect(screen.getByRole("tab", { name: "Raw" })).toHaveAttribute("aria-selected", "true");
    const status = screen.getByRole("status");
    expect(within(status).getByText("/outcome/result/body/content")).toBeInTheDocument();
    expect(within(status).getByText("bytes 0..52")).toBeInTheDocument();
    expect(screen.getByLabelText("Selected raw response frame")).toHaveTextContent("event: message_start");
    expect(container.querySelector('.raw-line.is-highlighted')).toHaveAttribute("data-pointer", "/outcome/result/body/content");
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
      proxyAvailable: true,
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
      if (command === "set_capture_active") {
        const next = structuredClone(workspace);
        next.capture.active = Boolean(args?.active);
        next.compatibility = {
          ...next.compatibility,
          code: "capture_paused",
          status: "attention",
          title: "Gateway capture paused",
          action: "resume_capture",
        };
        return next;
      }
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

  it("switches capture modes through the desktop runtime", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const gateway = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    gateway.capture = {
      ...gateway.capture,
      active: true,
      canControl: true,
      proxyAvailable: true,
      mode: "gateway",
      profile: "OpenAI-compatible local gateway",
      endpoint: "http://127.0.0.1:8787",
    };
    const proxy: WorkspaceBootstrap = {
      ...gateway,
      capture: {
        ...gateway.capture,
        mode: "proxy",
        profile: "Explicit TLS proxy",
        endpoint: "http://127.0.0.1:43125",
        certificateAuthority: {
          state: "ready",
          canManageTrust: true,
          fingerprintSha256: "AA:BB:CC:DD",
          subject: "mitmproxy",
          validFromUnixMs: 1_577_836_800_000,
          validUntilUnixMs: 4_070_908_800_000,
          privateMaterial: "unchecked",
          trust: "unchecked",
          detail: null,
        },
      },
    };
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(gateway);
      if (command === "set_capture_mode" && args?.mode === "proxy") {
        return structuredClone(proxy);
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    const proxyButton = await screen.findByRole("button", { name: "Proxy" });
    expect(proxyButton).toBeEnabled();
    await user.click(proxyButton);

    expect(invoke).toHaveBeenCalledWith("set_capture_mode", { mode: "proxy" });
    expect(await screen.findByText("Explicit TLS proxy")).toBeInTheDocument();
    expect(screen.getByText("http://127.0.0.1:43125")).toBeInTheDocument();
    expect(screen.getByText("Ready · trust unchecked")).toBeInTheDocument();
    expect(screen.getByText("AA:BB:CC:DD")).toBeInTheDocument();
    expect(proxyButton).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("Healthy").parentElement).toHaveTextContent("Proxy");
  });

  it("diagnoses an unobserved proxy session without claiming certificate pinning", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const proxy = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    proxy.capture = {
      ...proxy.capture,
      active: true,
      canControl: true,
      proxyAvailable: true,
      mode: "proxy",
      profile: "System-managed explicit TLS proxy",
      endpoint: "http://127.0.0.1:43125",
      certificateAuthority: {
        state: "ready",
        canManageTrust: true,
        fingerprintSha256: "AA:BB:CC:DD",
        subject: "mitmproxy",
        validFromUnixMs: 1_577_836_800_000,
        validUntilUnixMs: 4_070_908_800_000,
        privateMaterial: "restricted",
        trust: "trusted",
        detail: null,
      },
    };
    proxy.compatibility = {
      code: "proxy_capture_unobserved",
      status: "attention",
      confidence: "low",
      title: "No Proxy capture observed yet",
      summary: "Send one request from the target application. If it succeeds there but remains absent here, the application may bypass the proxy or pin certificates; use Gateway capture instead.",
      recommendedMode: "gateway",
      action: "use_gateway",
      steps: [
        { id: "proxy_bundle", status: "pass", label: "Verified Proxy bundle", detail: "Available" },
        { id: "proxy_runtime", status: "pass", label: "Proxy runtime", detail: "http://127.0.0.1:43125" },
        { id: "local_ca", status: "pass", label: "Local certificate authority", detail: "Ready · restricted private material" },
        { id: "system_trust", status: "pass", label: "System trust", detail: "trusted" },
        { id: "session_capture", status: "pending", label: "Current Proxy session", detail: "No capture event observed yet" },
      ],
    };
    const gateway = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    gateway.capture = {
      ...gateway.capture,
      active: true,
      canControl: true,
      proxyAvailable: true,
      mode: "gateway",
      profile: "OpenAI-compatible local gateway",
      endpoint: "http://127.0.0.1:8787",
    };
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(proxy);
      if (command === "set_capture_mode" && args?.mode === "gateway") {
        return structuredClone(gateway);
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Settings" }));
    const dialog = screen.getByRole("dialog", { name: "Settings & diagnostics" });
    expect(within(dialog).getByText("No Proxy capture observed yet")).toBeInTheDocument();
    expect(within(dialog).getByText("low confidence")).toBeInTheDocument();
    expect(within(dialog).getByText(/may bypass the proxy or pin certificates/)).toBeInTheDocument();
    expect(within(dialog).getByText("No capture event observed yet")).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Use Gateway" }));
    expect(invoke).toHaveBeenCalledWith("set_capture_mode", { mode: "gateway" });
    expect(await screen.findByText("OpenAI-compatible local gateway")).toBeInTheDocument();
  });

  it("keeps residual certificate details visible when the proxy bundle is unavailable", async () => {
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.capture = {
      ...workspace.capture,
      proxyAvailable: false,
      certificateAuthority: {
        state: "invalid",
        canManageTrust: true,
        fingerprintSha256: "11:22:33:44",
        subject: "mitmproxy",
        validFromUnixMs: 1_577_836_800_000,
        validUntilUnixMs: 4_070_908_800_000,
        privateMaterial: "missing",
        trust: "trusted",
        detail: "certificate authority files are incomplete",
      },
    };
    vi.mocked(invoke).mockResolvedValue(structuredClone(workspace));

    render(<App />);

    expect(await screen.findByText("Invalid · trusted")).toBeInTheDocument();
    expect(screen.getByText("11:22:33:44")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Proxy" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove trust" })).toBeInTheDocument();
  });

  it("does not offer to trust an invalid certificate authority", async () => {
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.capture.certificateAuthority = {
      state: "invalid",
      canManageTrust: true,
      fingerprintSha256: "11:22:33:44",
      subject: "mitmproxy",
      validFromUnixMs: 1_577_836_800_000,
      validUntilUnixMs: 1_609_459_200_000,
      privateMaterial: "restricted",
      trust: "not_trusted",
      detail: "certificate authority is outside its validity period",
    };
    vi.mocked(invoke).mockResolvedValue(structuredClone(workspace));

    render(<App />);

    expect(await screen.findByText("Invalid · not trusted")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Trust CA" })).not.toBeInTheDocument();
  });

  it("installs certificate trust and refreshes the workspace state", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const untrusted = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    untrusted.capture.certificateAuthority = {
      state: "ready",
      canManageTrust: true,
      fingerprintSha256: "AA:BB:CC:DD",
      subject: "mitmproxy",
      validFromUnixMs: 1_577_836_800_000,
      validUntilUnixMs: 4_070_908_800_000,
      privateMaterial: "restricted",
      trust: "not_trusted",
      detail: null,
    };
    const trusted = structuredClone(untrusted);
    trusted.capture.certificateAuthority.trust = "trusted";
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(untrusted);
      if (command === "install_certificate_authority_trust") return structuredClone(trusted);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Trust CA" }));

    expect(invoke).toHaveBeenCalledWith("install_certificate_authority_trust");
    expect(await screen.findByText("Ready · trusted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove trust" })).toBeInTheDocument();
  });

  it("keeps CA trust retryable after the user rejects the system prompt", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const untrusted = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    untrusted.capture.mode = "proxy";
    untrusted.capture.profile = "Explicit TLS proxy";
    untrusted.capture.endpoint = "http://127.0.0.1:43125";
    untrusted.capture.certificateAuthority = {
      state: "ready",
      canManageTrust: true,
      fingerprintSha256: "AA:BB:CC:DD",
      subject: "mitmproxy",
      validFromUnixMs: 1_577_836_800_000,
      validUntilUnixMs: 4_070_908_800_000,
      privateMaterial: "restricted",
      trust: "not_trusted",
      detail: null,
    };
    const trusted = structuredClone(untrusted);
    trusted.capture.certificateAuthority.trust = "trusted";
    let installAttempts = 0;
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(untrusted);
      if (command === "install_certificate_authority_trust") {
        installAttempts += 1;
        if (installAttempts === 1) {
          throw new Error("certificate trust update failed: the user cancelled the security prompt");
        }
        return structuredClone(trusted);
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Trust CA" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("user cancelled");
    expect(screen.getByText("Ready · not trusted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Proxy" })).toHaveAttribute("aria-pressed", "true");
    const retry = screen.getByRole("button", { name: "Trust CA" });
    expect(retry).toBeEnabled();

    await user.click(retry);
    expect(await screen.findByText("Ready · trusted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove trust" })).toBeInTheDocument();
    expect(installAttempts).toBe(2);
  });

  it("removes certificate trust and accepts the safe gateway fallback", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const trusted = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    trusted.capture = {
      ...trusted.capture,
      active: true,
      canControl: true,
      proxyAvailable: true,
      mode: "proxy",
      certificateAuthority: {
        state: "ready",
        canManageTrust: true,
        fingerprintSha256: "AA:BB:CC:DD",
        subject: "mitmproxy",
        validFromUnixMs: 1_577_836_800_000,
        validUntilUnixMs: 4_070_908_800_000,
        privateMaterial: "restricted",
        trust: "trusted",
        detail: null,
      },
    };
    const untrusted = structuredClone(trusted);
    untrusted.capture.mode = "gateway";
    untrusted.capture.profile = "OpenAI-compatible local gateway";
    untrusted.capture.endpoint = "http://127.0.0.1:8787";
    untrusted.capture.certificateAuthority.trust = "not_trusted";
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(trusted);
      if (command === "uninstall_certificate_authority_trust") return structuredClone(untrusted);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Remove trust" }));

    expect(invoke).toHaveBeenCalledWith("uninstall_certificate_authority_trust");
    expect(await screen.findByText("Ready · not trusted")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Gateway" })).toHaveAttribute("aria-pressed", "true");
  });

  it("shows disk pressure as a paused capture state", async () => {
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    workspace.capture = { ...workspace.capture, active: true, canControl: true };
    let notifyRuntimeError = () => {};
    vi.mocked(listen).mockImplementation(async (event, handler) => {
      if (event === "capture-runtime-error") {
        notifyRuntimeError = () => handler({
          event: "capture-runtime-error",
          id: 2,
          payload: {
            code: "capture_disk_pressure",
            detail: "Capture storage paused: disk headroom is below 256 MiB",
          },
        });
      }
      return () => {};
    });
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await screen.findByRole("button", { name: "Pause capture" });
    await act(async () => notifyRuntimeError());

    expect(await screen.findByRole("button", { name: "Resume capture" })).toBeEnabled();
    expect(screen.getByText("Issue").parentElement).toHaveAttribute(
      "title",
      "Capture storage paused: disk headroom is below 256 MiB",
    );
  });

  it("reloads the safe gateway state after the proxy sidecar exits", async () => {
    window.__TAURI_INTERNALS__ = {};
    const proxy = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    proxy.capture = {
      ...proxy.capture,
      active: true,
      canControl: true,
      proxyAvailable: true,
      mode: "proxy",
      profile: "System-managed explicit TLS proxy",
      endpoint: "http://127.0.0.1:43125",
    };
    const recovered = structuredClone(proxy);
    recovered.capture.mode = "gateway";
    recovered.capture.profile = "OpenAI-compatible local gateway";
    recovered.capture.endpoint = "http://127.0.0.1:8787";
    let notifyRuntimeError = () => {};
    vi.mocked(listen).mockImplementation(async (event, handler) => {
      if (event === "capture-runtime-error") {
        notifyRuntimeError = () => handler({
          event: "capture-runtime-error",
          id: 3,
          payload: {
            code: "sidecar_process_exited",
            detail: "The explicit proxy process exited unexpectedly (exit code: 1).",
          },
        });
      }
      return () => {};
    });
    let bootstrapCount = 0;
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") {
        bootstrapCount += 1;
        return structuredClone(bootstrapCount === 1 ? proxy : recovered);
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    expect(await screen.findByRole("button", { name: "Proxy" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await act(async () => notifyRuntimeError());

    expect(await screen.findByRole("button", { name: "Gateway" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(bootstrapCount).toBe(2);
    expect(screen.getByText("Issue").parentElement).toHaveAttribute(
      "title",
      "The explicit proxy process exited unexpectedly (exit code: 1).",
    );
  });

  it("previews and saves a scanned request export", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    const preview = (profile: ExportProfile): ExportPreview => ({
      profile,
      suggestedFilename: `codeischeap-request-${profile}.json`,
      content: `{"profile":"${profile}","secret":"[REDACTED:bearer_token]"}\n`,
      byteCount: 68,
      contentSha256: "a".repeat(64),
      exportedAtUnixMs: 1_700_000_000_000,
      redactions: [{ category: "bearer_token", pointer: "/request/promptPreview" }],
      policyVersion: "0.1",
    });
    vi.mocked(save).mockResolvedValue("D:\\exports\\request.json");
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "preview_capture_export") {
        return preview((args?.profile as ExportProfile) ?? "minimal");
      }
      if (command === "write_capture_export") {
        return { path: args?.path, byteCount: 68, redactionCount: 1 };
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Export request" }));
    const dialog = await screen.findByRole("dialog", { name: "Export request" });
    expect(within(dialog).getByRole("button", { name: "Close export" })).toHaveFocus();
    expect(within(dialog).getByRole("button", { name: "minimal" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(await within(dialog).findByText("1 credential replaced")).toBeInTheDocument();
    expect(within(dialog).getByLabelText("Export JSON preview")).toHaveTextContent(
      "[REDACTED:bearer_token]",
    );

    await user.click(within(dialog).getByRole("button", { name: "forensic" }));
    expect(await within(dialog).findByText(/"profile":"forensic"/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save JSON" }));

    expect(save).toHaveBeenCalledWith({
      defaultPath: "codeischeap-request-forensic.json",
      filters: [{ name: "JSON", extensions: ["json"] }],
    });
    expect(invoke).toHaveBeenCalledWith("write_capture_export", {
      captureId: workspace.requests[0].id,
      profile: "forensic",
      exportedAtUnixMs: 1_700_000_000_000,
      expectedSha256: "a".repeat(64),
      path: "D:\\exports\\request.json",
    });
    expect(await within(dialog).findByText("Saved")).toBeInTheDocument();
  });

  it("exports the current visible request set in stable order", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    const captureIds = workspace.requests
      .filter((request) => request.provider === "OpenAI")
      .map((request) => request.id);
    const preview = (profile: ExportProfile): ExportPreview => ({
      profile,
      suggestedFilename: `codeischeap-batch-${captureIds.length}-${profile}.json`,
      content: `{"profile":"${profile}","requestCount":${captureIds.length}}\n`,
      byteCount: 48,
      contentSha256: "b".repeat(64),
      exportedAtUnixMs: 1_700_000_000_100,
      redactions: [],
      policyVersion: "0.1",
    });
    vi.mocked(save).mockResolvedValue("D:\\exports\\visible-requests.json");
    vi.mocked(invoke).mockImplementation(async (command, args) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "preview_batch_capture_export") {
        return preview((args?.profile as ExportProfile) ?? "minimal");
      }
      if (command === "write_batch_capture_export") {
        return { path: args?.path, byteCount: 48, redactionCount: 0 };
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.selectOptions(
      await screen.findByRole("combobox", { name: "Provider filter" }),
      "OpenAI",
    );
    expect(await screen.findByText(`${captureIds.length} visible`)).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Export visible requests" }));
    const dialog = await screen.findByRole("dialog", { name: "Export visible requests" });
    expect(
      await within(dialog).findByText(new RegExp(`${captureIds.length} requests$`)),
    ).toBeInTheDocument();
    expect(invoke).toHaveBeenCalledWith("preview_batch_capture_export", {
      captureIds,
      profile: "minimal",
    });

    await user.click(within(dialog).getByRole("button", { name: "reproducible" }));
    expect(await within(dialog).findByText(/"profile":"reproducible"/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save JSON" }));

    expect(invoke).toHaveBeenCalledWith("write_batch_capture_export", {
      captureIds,
      profile: "reproducible",
      exportedAtUnixMs: 1_700_000_000_100,
      expectedSha256: "b".repeat(64),
      path: "D:\\exports\\visible-requests.json",
    });
    expect(await within(dialog).findByText("Saved")).toBeInTheDocument();
  });

  it("keeps batch export preview failures visible", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = structuredClone(fixture) as unknown as WorkspaceBootstrap;
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      if (command === "preview_batch_capture_export") {
        throw new Error("A request disappeared before export.");
      }
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    await user.click(await screen.findByRole("button", { name: "Export visible requests" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "A request disappeared before export.",
    );
  });

  it("virtualizes one thousand requests and keeps filtered selection coherent", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    const workspace = makeWorkspace(1_000);
    vi.mocked(invoke).mockResolvedValue(structuredClone(workspace));

    render(<App />);

    await screen.findByText("1000 visible");
    const listbox = screen.getByRole("listbox", { name: "Request results" });
    const rendered = within(listbox).getAllByRole("option");
    expect(rendered.length).toBeGreaterThan(0);
    expect(rendered.length).toBeLessThan(25);
    expect(rendered[0]).toHaveAttribute("aria-setsize", "1000");

    await user.type(screen.getByRole("textbox", { name: "Search requests" }), "Synthetic request 999");

    const filtered = within(listbox).getAllByRole("option");
    expect(filtered).toHaveLength(1);
    expect(filtered[0]).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("heading", { name: "model-999" })).toBeInTheDocument();
  });

  it("scrolls keyboard selection into view without live refresh stealing search focus", async () => {
    const user = userEvent.setup();
    window.__TAURI_INTERNALS__ = {};
    let workspace = makeWorkspace(1_000);
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
    vi.mocked(invoke).mockImplementation(async (command) => {
      if (command === "bootstrap_workspace") return structuredClone(workspace);
      throw new Error(`Unexpected command: ${command}`);
    });

    render(<App />);
    const listbox = await screen.findByRole("listbox", { name: "Request results" });
    const first = within(listbox).getAllByRole("option")[0];
    await user.click(first);
    for (let index = 0; index < 12; index += 1) {
      await user.keyboard("{ArrowDown}");
    }

    expect(await screen.findByRole("heading", { name: "model-12" })).toBeInTheDocument();
    expect(listbox.scrollTop).toBeGreaterThan(0);

    const search = screen.getByRole("textbox", { name: "Search requests" });
    await user.click(search);
    expect(search).toHaveFocus();
    workspace = {
      ...workspace,
      capture: { ...workspace.capture, requestCount: 1_001 },
      requests: [
        { ...workspace.requests[0], id: "live-capture", promptPreview: "Live capture arrived" },
        ...workspace.requests,
      ],
    };
    await act(async () => notifyCaptureUpdated());

    await screen.findByText("1001 visible");
    expect(search).toHaveFocus();
    expect(screen.getByRole("heading", { name: "model-12" })).toBeInTheDocument();
  });
});
