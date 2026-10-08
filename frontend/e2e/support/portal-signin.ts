import AxeBuilder from "@axe-core/playwright";
import { expect, type Page } from "@playwright/test";

export type PortalRole = "Admin" | "Analyst";

/**
 * Sign in through the development identity provider (the mock OpenID Connect server of the `dev`
 * Compose profile). Its login form takes a user name and a "claims" JSON box; the portal reads the
 * role from the `roles` claim, so typing `{"roles": ["Admin"]}` makes the person an Admin.
 */
export async function signInAs(page: Page, role: PortalRole, userName?: string): Promise<void> {
  const name = userName ?? `e2e-${role.toLowerCase()}`;
  await page.goto("/login");
  await page.getByRole("link", { name: "Sign in with Microsoft" }).click();
  await page.locator('input[name="username"]').fill(name);
  await page.locator('textarea[name="claims"]').fill(JSON.stringify({ roles: [role] }));
  await page.locator('input[type="submit"], button[type="submit"]').first().click();
  // Back in the portal: the header shows the signed-in person.
  await expect(page.getByRole("link", { name: "SecureScan home" })).toBeVisible();
  await expect(page.getByRole("banner")).toContainText(role);
}

/** Fails on any serious or critical WCAG 2.1 A/AA violation on the current page. */
export async function expectNoSeriousA11yViolations(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const serious = results.violations.filter(
    (violation) => violation.impact === "serious" || violation.impact === "critical",
  );
  expect(
    serious.map((violation) => `${violation.id}: ${violation.help} (${violation.nodes.length} elements)`),
  ).toEqual([]);
}
