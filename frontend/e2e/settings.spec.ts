import { expect, test } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

const PAGES: { path: string; heading: string }[] = [
  { path: "/settings/templates", heading: "Report templates" },
  { path: "/settings/policies", heading: "Verdict policies" },
  { path: "/settings/profiles", heading: "Scan profiles" },
  { path: "/settings/defectdojo", heading: "DefectDojo and imports" },
  { path: "/settings/accounts", heading: "DefectDojo accounts" },
  { path: "/settings/github", heading: "GitHub connection" },
  { path: "/settings/repositories", heading: "Repositories" },
  { path: "/settings/schedules", heading: "Schedules" },
  { path: "/settings/audit", heading: "Audit log" },
  { path: "/settings/health", heading: "System health" },
  { path: "/settings/scanner-health", heading: "Scanner health" },
  { path: "/settings/content", heading: "Scanner content" },
  { path: "/settings/images", heading: "Scanner images" },
];

test.describe("settings as an Admin", () => {
  test.beforeEach(async ({ page }) => {
    await signInAs(page, "Admin");
  });

  for (const { path, heading } of PAGES) {
    test(`${heading} loads and passes the accessibility check`, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible();
      await expect(page.getByRole("navigation", { name: "Settings" })).toBeVisible();
      await expectNoSeriousA11yViolations(page);
    });
  }

  test("/settings opens the first page", async ({ page }) => {
    await page.goto("/settings");
    await expect(page).toHaveURL(/\/settings\/templates/);
  });

  test("report templates: download the default, preview it, and reject a bad upload", async ({ page }) => {
    await page.goto("/settings/templates");
    await expect(page.getByRole("table", { name: "Report templates" })).toBeVisible();

    const download = page.waitForEvent("download");
    await page.getByRole("link", { name: "Download default template" }).click();
    expect((await download).suggestedFilename()).toMatch(/\.zip$/);

    await page.getByRole("button", { name: /^Preview/ }).first().click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: "Render preview" }).click();
    await expect(dialog.locator("iframe[sandbox]")).toBeVisible({ timeout: 60_000 });
    await dialog.getByRole("button", { name: "Close", exact: true }).first().click();

    await page.getByLabel("Template name").fill("e2e broken template");
    await page.getByLabel("Template zip file").setInputFiles({
      name: "broken.zip",
      mimeType: "application/zip",
      buffer: Buffer.from("this is not a zip file"),
    });
    await page.getByRole("button", { name: "Upload template" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "The template was not accepted" })).toBeVisible();
  });

  test("policies: create, edit and switch off a policy", async ({ page }) => {
    await page.goto("/settings/policies");
    await page.getByRole("button", { name: "New policy" }).click();
    const dialog = page.getByRole("dialog");
    const name = `e2e public policy ${Date.now()}`;
    await dialog.getByLabel("Name").fill(name);
    await dialog.getByLabel("Data classification").selectOption("public");
    await dialog.getByRole("group", { name: "Fail at" }).getByLabel("Critical").fill("1");
    await dialog.getByRole("button", { name: "Create policy" }).click();

    const row = page.getByRole("row", { name: new RegExp(name) });
    await expect(row).toBeVisible();

    await row.getByRole("button", { name: /^Edit/ }).click();
    await page.getByRole("dialog").getByRole("group", { name: "Conditional at" }).getByLabel("Medium").fill("3");
    await page.getByRole("dialog").getByRole("button", { name: "Save changes" }).click();
    await expect(row).toContainText("3 medium");

    // Switch it off again so the test can run twice (one active policy per classification).
    await row.getByRole("button", { name: /^Switch off/ }).click();
    await expect(row).toContainText("Switched off");
  });

  test("a policy needs a number for Fail", async ({ page }) => {
    await page.goto("/settings/policies");
    await page.getByRole("button", { name: "New policy" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Name").fill("empty thresholds");
    await dialog.getByRole("group", { name: "Fail at" }).getByLabel("Critical").fill("");
    await dialog.getByRole("group", { name: "Fail at" }).getByLabel("High").fill("");
    await dialog.getByRole("button", { name: "Create policy" }).click();
    await expect(dialog.getByRole("alert")).toContainText("at least one number under Fail");
  });

  test("DefectDojo: status card and import queue are shown", async ({ page }) => {
    await page.goto("/settings/defectdojo");
    await expect(page.getByRole("heading", { name: "DefectDojo status" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Import queue" })).toBeVisible();
    await page.getByLabel("Show").selectOption("dead_letter");
    // Either failed imports with a Replay button, or the empty-state sentence.
    await expect(
      page.getByRole("button", { name: /^Replay/ }).first().or(page.getByText("Nothing in the import queue for this filter.")),
    ).toBeVisible();
  });

  test("audit log: filter by action and page through entries", async ({ page }) => {
    await page.goto("/settings/audit");
    await expect(page.getByRole("table", { name: "Audit log" })).toBeVisible();
    await page.getByLabel("Action starts with").fill("auth");
    await page.getByRole("button", { name: "Apply filters" }).click();
    const rows = page.getByRole("table", { name: "Audit log" }).getByRole("row");
    await expect(rows.nth(1)).toContainText("auth.");
    const more = page.getByRole("button", { name: "Load more" });
    if (await more.isVisible()) {
      const before = await rows.count();
      await more.click();
      await expect.poll(async () => rows.count()).toBeGreaterThan(before);
    }
  });

  test("system health shows the overall status", async ({ page }) => {
    await page.goto("/settings/health");
    await expect(page.getByText("Reachable")).toBeVisible();
    await expect(page.getByRole("table", { name: "Current values" })).toBeVisible();
  });

  test("GitHub: the connection form is empty and never shows a stored key", async ({ page }) => {
    await page.goto("/settings/github");
    await expect(page.getByLabel("App ID")).toBeVisible();
    await expect(page.getByLabel("Private key 1 (.pem)")).toHaveValue("");
  });
});

test.describe("settings as an Analyst", () => {
  test("every settings address leads back to Home", async ({ page }) => {
    await signInAs(page, "Analyst");
    for (const { path } of PAGES) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/$/);
      await expect(page.getByRole("heading", { name: "Home", level: 1 })).toBeVisible();
    }
    await expect(page.getByRole("link", { name: "Settings" })).toHaveCount(0);
  });

  test("the admin API refuses an Analyst", async ({ page }) => {
    await signInAs(page, "Analyst");
    const response = await page.request.get("/api/v1/audit-events");
    expect(response.status()).toBe(403);
  });
});
