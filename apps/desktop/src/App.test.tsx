import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { App } from "./App";

describe("request workbench", () => {
  beforeEach(() => {
    localStorage.clear();
    delete window.__TAURI_INTERNALS__;
  });

  it("filters requests without losing the inspector workflow", async () => {
    const user = userEvent.setup();
    render(<App />);
    const search = await screen.findByRole("textbox", { name: "Search requests" });
    const listbox = screen.getByRole("listbox", { name: "Request results" });
    expect(within(listbox).getAllByRole("option")).toHaveLength(6);

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
});
