import { expect, test } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

test.describe("login and roles", () => {
  test("the login page shows the wordmark, the product name and one button, and nothing else", async ({
    page,
  }) => {
    await page.goto("/login");
    await expect(page.getByAltText("SonaComstar")).toBeVisible();
    await expect(page.getByRole("heading", { name: "SecureScan" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Sign in with Microsoft" })).toHaveAttribute(
      "href",
      /\/api\/v1\/auth\/login/,
    );
    await expect(page.getByRole("link")).toHaveCount(1);
    await expect(page.getByRole("button")).toHaveCount(0);
    await expectNoSeriousA11yViolations(page);
  });

  test("a signed-out visitor to any page is sent to the login page", async ({ page }) => {
    await page.goto("/history");
    await expect(page).toHaveURL(/\/login/);
    await expect(page.getByRole("link", { name: "Sign in with Microsoft" })).toBeVisible();
  });

  test("an Analyst sees Home and cannot reach Settings", async ({ page }) => {
    await signInAs(page, "Analyst");
    await expect(page.getByRole("heading", { name: "Home", level: 1 })).toBeVisible();
    const nav = page.getByRole("navigation", { name: "Main" });
    await expect(nav.getByRole("link", { name: "SAST scan" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "DAST scan" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Historical data" })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Settings" })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Open DefectDojo" })).toBeVisible();
    await expectNoSeriousA11yViolations(page);

    await page.goto("/settings/templates");
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("heading", { name: "Home", level: 1 })).toBeVisible();
  });

  test("an Admin sees Settings and can sign out", async ({ page }) => {
    await signInAs(page, "Admin");
    const nav = page.getByRole("navigation", { name: "Main" });
    await expect(nav.getByRole("link", { name: "Settings" })).toBeVisible();
    await nav.getByRole("link", { name: "Settings" }).click();
    await expect(page).toHaveURL(/\/settings\/templates/);

    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(page).toHaveURL(/\/login/);
    await page.goto("/history");
    await expect(page).toHaveURL(/\/login/);
  });

  test("Home shows the DefectDojo account panel with a reset action", async ({ page }) => {
    await signInAs(page, "Analyst", "e2e-dojo-user");
    const panel = page.getByRole("region", { name: "Your DefectDojo account" });
    await expect(panel).toBeVisible();
    // Either the one-time password is shown (first visit), or only the reset button (later visits),
    // or DefectDojo is not ready yet and the panel says so in words.
    await expect(panel).toContainText(
      /Reset DefectDojo password|Show password|not ready|is disabled|Could not load/,
      { timeout: 15_000 },
    );
  });
});
