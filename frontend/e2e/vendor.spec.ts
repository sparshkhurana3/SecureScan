import { expect, test } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

test.describe("vendor assessments", () => {
  test("the page opens from the main navigation and passes the accessibility check", async ({ page }) => {
    await signInAs(page, "Analyst");
    await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Vendor assessments" }).click();
    await expect(page.getByRole("heading", { name: "Vendor assessments", level: 1 })).toBeVisible();
    await expect(page.getByRole("form", { name: "Register a vendor product" })).toBeVisible();
    await expect(page.getByRole("form", { name: "Create an assessment" })).toBeVisible();
    await expect(page.getByRole("form", { name: "Compare with an earlier version" })).toBeVisible();
    await expectNoSeriousA11yViolations(page);
  });

  test("registering a product names the next steps", async ({ page }) => {
    await signInAs(page, "Analyst");
    await page.goto("/vendor-assessments");
    const form = page.getByRole("form", { name: "Register a vendor product" });
    const stamp = Date.now().toString();
    await form.getByLabel("Vendor").fill(`E2E Vendor ${stamp}`);
    await form.getByLabel("Product").fill(`E2E Product ${stamp}`);
    await form.getByLabel("Version").fill("1.0");
    await form.getByLabel("Hosting").selectOption("deployable");
    await form.getByRole("button", { name: "Register" }).click();
    await expect(page.getByRole("status").filter({ hasText: "is ready." })).toBeVisible({ timeout: 30_000 });
  });

  test("an Analyst cannot open the Admin settings pages for scanner images and content", async ({ page }) => {
    await signInAs(page, "Analyst");
    await page.goto("/settings/images");
    await expect(page).not.toHaveURL(/\/settings\/images/);
  });
});

test.describe("scanner operations as an Admin", () => {
  test.beforeEach(async ({ page }) => {
    await signInAs(page, "Admin");
  });

  for (const { path, heading } of [
    { path: "/settings/scanner-health", heading: "Scanner health" },
    { path: "/settings/content", heading: "Scanner content" },
    { path: "/settings/images", heading: "Scanner images" },
  ]) {
    test(`${heading} loads and passes the accessibility check`, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole("heading", { name: heading, level: 1 })).toBeVisible();
      await expectNoSeriousA11yViolations(page);
    });
  }
});
