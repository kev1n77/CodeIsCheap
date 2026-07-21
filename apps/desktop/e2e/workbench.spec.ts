import { expect, test } from "@playwright/test";

const MINIMUM_VIEWPORT = { width: 960, height: 620 };
const WIDE_VIEWPORT = { width: 1440, height: 900 };
const REQUEST_COUNT = 1_000;
const MAX_BOOTSTRAP_MS = 2_000;
const MAX_SCROLL_SETTLE_MS = 2_000;
const MAX_FILTER_SETTLE_MS = 750;
const MAX_RENDERED_ROWS = 40;

test.describe("desktop workbench quality baseline", () => {
  test("keeps the thousand-request workspace responsive at minimum size", async ({ page }, testInfo) => {
    await page.setViewportSize(MINIMUM_VIEWPORT);
    await page.goto(`/?fixtureRequests=${REQUEST_COUNT}`);

    await expect(page.getByText(`${REQUEST_COUNT} visible`)).toBeVisible();
    const bootstrapMs = await page.evaluate(() => performance.now());
    expect(bootstrapMs).toBeLessThan(MAX_BOOTSTRAP_MS);

    const requestList = page.getByRole("listbox", { name: "Request results" });
    await expect(requestList).toBeVisible();
    const initialRenderedRows = await requestList.getByRole("option").count();
    expect(initialRenderedRows).toBeLessThan(MAX_RENDERED_ROWS);

    if (process.platform === "linux") {
      await expect(page).toHaveScreenshot("workspace-minimum-light.png", {
        animations: "disabled",
      });
    }

    const scrollStarted = Date.now();
    await requestList.hover();
    await page.mouse.wheel(0, 1_000_000);
    await expect.poll(() => requestList.evaluate((element) => element.scrollTop))
      .toBeGreaterThan(0);
    await expect(requestList.locator('[role="option"][aria-posinset="1000"]')).toBeVisible();
    const scrollSettleMs = Date.now() - scrollStarted;
    expect(scrollSettleMs).toBeLessThan(MAX_SCROLL_SETTLE_MS);
    expect(await requestList.getByRole("option").count()).toBeLessThan(MAX_RENDERED_ROWS);

    const filterStarted = Date.now();
    await page.getByRole("textbox", { name: "Search requests" }).fill("Synthetic request 999");
    await expect(page.getByText("1 visible")).toBeVisible();
    const filterSettleMs = Date.now() - filterStarted;
    expect(filterSettleMs).toBeLessThan(MAX_FILTER_SETTLE_MS);
    await expect(requestList.getByRole("option")).toHaveCount(1);

    const layout = await page.evaluate(() => {
      const workspace = document.querySelector<HTMLElement>(".workspace");
      const inspector = document.querySelector<HTMLElement>(".inspector");
      return {
        documentClientWidth: document.documentElement.clientWidth,
        documentScrollWidth: document.documentElement.scrollWidth,
        workspaceClientWidth: workspace?.clientWidth ?? 0,
        workspaceScrollWidth: workspace?.scrollWidth ?? 0,
        inspectorClientWidth: inspector?.clientWidth ?? 0,
        inspectorScrollWidth: inspector?.scrollWidth ?? 0,
      };
    });
    expect(layout.documentScrollWidth).toBe(layout.documentClientWidth);
    expect(layout.workspaceScrollWidth).toBe(layout.workspaceClientWidth);
    expect(layout.inspectorScrollWidth).toBe(layout.inspectorClientWidth);

    const metrics = {
      requestCount: REQUEST_COUNT,
      bootstrapMs: Math.round(bootstrapMs),
      scrollSettleMs,
      filterSettleMs,
      initialRenderedRows,
    };
    console.log(`workbench_performance ${JSON.stringify(metrics)}`);
    await testInfo.attach("workbench-performance.json", {
      body: Buffer.from(`${JSON.stringify(metrics, null, 2)}\n`),
      contentType: "application/json",
    });
  });

  test("keeps the wide dark workspace visually stable", async ({ page }) => {
    await page.setViewportSize(WIDE_VIEWPORT);
    await page.addInitScript(() => {
      localStorage.setItem("codeischeap.theme", "dark");
    });
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Requests" })).toBeVisible();

    const layout = await page.evaluate(() => ({
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
      theme: document.documentElement.dataset.theme,
    }));
    expect(layout.scrollWidth).toBe(layout.clientWidth);
    expect(layout.theme).toBe("dark");

    if (process.platform === "linux") {
      await expect(page).toHaveScreenshot("workspace-wide-dark.png", {
        animations: "disabled",
      });
    }
  });
});
