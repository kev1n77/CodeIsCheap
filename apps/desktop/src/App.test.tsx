import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

describe("request workbench", () => {
  beforeEach(() => {
    localStorage.clear();
    delete window.__TAURI_INTERNALS__;
    vi.mocked(invoke).mockReset();
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
});
