import { expect, test, type Page } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

type Environment = "production" | "uat";

async function openDastPage(page: Page) {
  await signInAs(page, "Analyst");
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "DAST scan" }).click();
  await expect(page.getByRole("heading", { name: "DAST scan", level: 1 })).toBeVisible();
}

/** Registers a web address under a new application and returns its address. */
async function registerTarget(page: Page, options: { app: string; version: string; url: string; environment: Environment }) {
  await page.getByRole("button", { name: "Register a web address" }).click();
  const form = page.getByRole("form", { name: "Register a web address" });
  await form.getByLabel("New application name").fill(options.app);
  await form.getByLabel("Version label").fill(options.version);
  await form.getByLabel("Address (URL)").fill(options.url);
  await form.getByLabel("Environment tag").selectOption(options.environment);
  await form.getByRole("button", { name: "Register address" }).click();
  await expect(form).toBeHidden({ timeout: 30_000 });
  await expect(page.getByRole("table", { name: "Registered web addresses" }).getByRole("row").filter({ hasText: options.url })).toBeVisible();
}

function targetRow(page: Page, url: string) {
  return page.getByRole("table", { name: "Registered web addresses" }).getByRole("row").filter({ hasText: url });
}

test.describe("DAST scan page", () => {
  test("passes the accessibility check and lists the registered addresses", async ({ page }) => {
    await openDastPage(page);
    await expect(
      page.getByRole("table", { name: "Registered web addresses" }).or(page.getByText(/No web addresses are registered yet/)),
    ).toBeVisible();
    await expect(page.getByRole("form", { name: "Start a web scan" })).toBeVisible();
    await expectNoSeriousA11yViolations(page);
  });

  test("a production address offers the baseline only and a UAT address offers all four modes", async ({ page }) => {
    const stamp = String(Date.now());
    const prod = `https://prod-${stamp}.example.test`;
    const uat = `https://uat-${stamp}.example.test`;
    await openDastPage(page);
    await registerTarget(page, { app: `E2E shop ${stamp}`, version: "prod", url: prod, environment: "production" });
    await registerTarget(page, { app: `E2E shop UAT ${stamp}`, version: "uat", url: uat, environment: "uat" });

    const form = page.getByRole("form", { name: "Start a web scan" });
    await targetRow(page, prod).getByRole("button", { name: `Scan ${prod}` }).click();
    await expect(form.getByLabel(/Baseline/)).toBeVisible();
    await expect(form.getByLabel(/Full active scan/)).toHaveCount(0);
    await expect(form.getByLabel(/API scan/)).toHaveCount(0);
    await expect(form.getByLabel(/Nuclei/)).toHaveCount(0);
    await expect(form.getByText(/accept the unauthenticated baseline scan only/)).toBeVisible();

    await targetRow(page, uat).getByRole("button", { name: `Scan ${uat}` }).click();
    for (const mode of [/Baseline/, /Full active scan/, /API scan/, /Nuclei/]) {
      await expect(form.getByLabel(mode)).toBeVisible();
    }
  });

  test("login profiles are for UAT addresses only", async ({ page }) => {
    await openDastPage(page);
    await page.getByRole("button", { name: "Register a web address" }).click();
    const form = page.getByRole("form", { name: "Register a web address" });
    const login = form.getByLabel("Login profile (UAT only)");
    await expect(login).toBeDisabled();
    await form.getByLabel("Environment tag").selectOption("production");
    await expect(login).toBeDisabled();
    await form.getByLabel("Environment tag").selectOption("uat");
    await expect(login).toBeEnabled();
  });

  test("the environment tag can be changed by an analyst, and the modes follow", async ({ page }) => {
    const stamp = String(Date.now());
    const url = `https://retag-${stamp}.example.test`;
    await openDastPage(page);
    await registerTarget(page, { app: `E2E retag ${stamp}`, version: "1", url, environment: "production" });
    await expect(targetRow(page, url)).toContainText("Production");

    await targetRow(page, url).getByRole("button", { name: `Edit ${url}` }).click();
    const form = page.getByRole("form", { name: "Edit the web address" });
    await form.getByLabel("Environment tag").selectOption("uat");
    await form.getByRole("button", { name: "Save changes" }).click();
    await expect(form).toBeHidden({ timeout: 30_000 });
    await expect(targetRow(page, url)).toContainText("UAT");

    await targetRow(page, url).getByRole("button", { name: `Scan ${url}` }).click();
    await expect(page.getByRole("form", { name: "Start a web scan" }).getByLabel(/Full active scan/)).toBeVisible();
  });

  test("a vendor SaaS product needs the vendor's authorization before it can be registered", async ({ page }) => {
    const stamp = String(Date.now());
    const url = `https://saas-${stamp}.example.test`;
    await openDastPage(page);
    await page.getByRole("button", { name: "Register a web address" }).click();
    const form = page.getByRole("form", { name: "Register a web address" });
    await form.getByLabel("New application name").fill(`E2E SaaS ${stamp}`);
    await form.getByLabel("Vendor (a supplier develops it)").check();
    await form.getByLabel("Vendor", { exact: true }).selectOption("new");
    await form.getByLabel("New vendor name").fill(`E2E vendor ${stamp}`);
    await form.getByLabel(/SaaS \(the vendor hosts it\)/).check();
    await form.getByLabel("Version label").fill("saas");
    await form.getByLabel("Address (URL)").fill(url);
    await form.getByLabel("Environment tag").selectOption("production");

    await form.getByRole("button", { name: "Register address" }).click();
    await expect(form.getByText(/Upload the vendor's written authorization/)).toBeVisible();

    await form.getByLabel("Authorization document").setInputFiles({
      name: "authorization.txt",
      mimeType: "text/plain",
      buffer: Buffer.from("The vendor authorizes scanning of the application during the agreed window."),
    });
    await expect(form.getByTestId("upload-done")).toBeVisible({ timeout: 30_000 });
    await form.getByLabel("Scan window starts").fill("2026-01-01");
    await form.getByLabel("Scan window ends").fill("2099-12-31");
    await form.getByLabel("Vendor contact").fill("security@vendor.example");
    await form.getByRole("button", { name: "Register address" }).click();
    await expect(form).toBeHidden({ timeout: 30_000 });
    await expect(targetRow(page, url)).toContainText("On file until 2099-12-31");
  });

  test("the API refuses a full scan of a production address and the portal shows its words", async ({ page }) => {
    const stamp = String(Date.now());
    const url = `https://rule-${stamp}.example.test`;
    await openDastPage(page);
    await registerTarget(page, { app: `E2E rule ${stamp}`, version: "prod", url, environment: "production" });

    const me = (await (await page.request.get("/api/v1/me")).json()) as { csrf_token: string };
    const targets = (await (await page.request.get("/api/v1/targets", { params: { kind: "url", limit: 200 } })).json()) as {
      items: { id: string; version_id: string; locator: string }[];
    };
    const target = targets.items.find((item) => item.locator === url);
    expect(target).toBeDefined();
    const profiles = (await (await page.request.get("/api/v1/profiles", { params: { kind: "dast" } })).json()) as {
      items: { name: string }[];
    };
    test.skip(!profiles.items.some((profile) => profile.name === "dast-full"), "The DAST profiles are not installed yet.");

    const response = await page.request.post("/api/v1/scans", {
      headers: { "X-CSRF-Token": me.csrf_token },
      data: { version_id: target?.version_id, target_id: target?.id, profile: "dast-full" },
    });
    expect(response.status()).toBe(422);
    const problem = (await response.json()) as { detail: string; code: string };
    expect(problem.code).toBe("dast.production_baseline_only");
    expect(problem.detail).toMatch(/baseline/i);
  });
});
