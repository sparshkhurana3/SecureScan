import { expect, test } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

test.describe("historical data", () => {
  test.beforeEach(async ({ page }) => {
    await signInAs(page, "Analyst");
    await page.getByRole("link", { name: "Historical data" }).click();
    await expect(page.getByRole("heading", { name: "Historical data", level: 1 })).toBeVisible();
  });

  test("shows the scans tab first, with filters, and passes the accessibility check", async ({ page }) => {
    await expect(page.getByRole("tab", { name: "Scans", selected: true })).toBeVisible();
    await expect(page.getByRole("tab", { name: "Findings" })).toBeVisible();
    await expect(page.getByRole("form", { name: "Filters" })).toBeVisible();
    // Either rows or the empty-state sentence; never a blank page.
    await expect(page.getByRole("table", { name: "Scans" }).or(page.getByText("No scans match these filters."))).toBeVisible();
    await expectNoSeriousA11yViolations(page);
  });

  test("keeps every filter in the address and restores it on reload", async ({ page }) => {
    await page.getByRole("tab", { name: "Findings" }).click();
    await expect(page).toHaveURL(/tab=findings/);

    const severity = page.getByRole("group", { name: "Severity" });
    await severity.getByRole("checkbox", { name: "Critical" }).click();
    await severity.getByRole("checkbox", { name: "High" }).click();
    await page.getByLabel("Tools").fill("semgrep, gitleaks");
    await page.getByLabel("From date").fill("2026-01-01");
    await page.getByRole("button", { name: "Apply filters" }).click();

    await expect(page).toHaveURL(/severity=critical/);
    await expect(page).toHaveURL(/severity=high/);
    await expect(page).toHaveURL(/tool=semgrep/);
    await expect(page).toHaveURL(/tool=gitleaks/);
    await expect(page).toHaveURL(/from=2026-01-01/);

    await page.reload();
    await expect(page.getByRole("tab", { name: "Findings", selected: true })).toBeVisible();
    const again = page.getByRole("group", { name: "Severity" });
    await expect(again.getByRole("checkbox", { name: "Critical" })).toBeChecked();
    await expect(again.getByRole("checkbox", { name: "High" })).toBeChecked();
    await expect(again.getByRole("checkbox", { name: "Medium" })).not.toBeChecked();
    await expect(page.getByLabel("Tools")).toHaveValue("semgrep, gitleaks");

    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(page).not.toHaveURL(/severity=/);
    await expect(page).not.toHaveURL(/tool=/);
  });

  test("exports the filtered findings as CSV", async ({ page }) => {
    await page.getByRole("tab", { name: "Findings" }).click();
    await page.getByRole("group", { name: "Severity" }).getByRole("checkbox", { name: "Critical" }).click();
    await page.getByRole("button", { name: "Apply filters" }).click();
    await expect(page).toHaveURL(/severity=critical/);

    const exportLink = page.getByRole("link", { name: "Export CSV" });
    await expect(exportLink).toHaveAttribute("href", /\/api\/v1\/history\/findings\.csv\?.*severity=critical/);

    const downloadPromise = page.waitForEvent("download");
    await exportLink.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^securescan-findings-\d{8}-\d{6}\.csv$/);

    // The same address, fetched with the page's session, is a CSV with the documented header.
    const href = await exportLink.getAttribute("href");
    const response = await page.request.get(href ?? "");
    expect(response.ok()).toBe(true);
    expect(response.headers()["content-type"]).toContain("text/csv");
    expect((await response.text()).replace(/^﻿/, "")).toMatch(/^scanned_at,application,/);
  });

  test("links a scan row to its detail page and starts on the first page", async ({ page }) => {
    const rows = page.getByRole("table", { name: "Scans" }).getByRole("row");
    test.skip((await rows.count()) < 2, "needs at least one scan in the history");

    const open = page.getByRole("link", { name: /^Open scan of / }).first();
    await expect(page.getByRole("button", { name: "Previous page" })).toBeDisabled();
    await open.click();
    await expect(page).toHaveURL(/\/scans\/[0-9a-f-]{36}/);
  });
});
