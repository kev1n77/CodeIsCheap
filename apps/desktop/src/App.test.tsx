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
    expect(screen.getByRole("button", { name: "Proxy" })).toBeDisabled();

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
    expect(screen.getByText("#0")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /Raw/ }));
    expect(screen.getByText(/Authorization, cookies/)).toBeInTheDocument();
    expect(screen.getByText(/credentials_persisted/)).toBeInTheDocument();
  });

  it("locates an Anatomy item in highlighted raw JSON", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });

    await user.click(screen.getByRole("button", { name: "Show raw evidence for User" }));

    expect(screen.getByRole("button", { name: "Raw" })).toHaveAttribute("aria-selected", "true");
    expect(within(screen.getByRole("status")).getByText("/request/body/messages/0/content")).toBeInTheDocument();
    const highlighted = container.querySelector('.raw-line.is-highlighted');
    expect(highlighted).toHaveAttribute("data-pointer", "/request/body/messages/0/content");
    expect(highlighted).toHaveTextContent("Inspect the failing authentication flow");
  });

  it("locates a Timeline stream event in the exact raw SSE frame", async () => {
    const user = userEvent.setup();
    const { container } = render(<App />);
    await screen.findByRole("heading", { name: "claude-sonnet" });
    await user.click(screen.getByRole("button", { name: "Timeline" }));

    await user.click(screen.getByRole("button", { name: "Show raw evidence for First response event" }));

    expect(screen.getByRole("button", { name: "Raw" })).toHaveAttribute("aria-selected", "true");
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
