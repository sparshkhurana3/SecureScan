import { expect, test, type Page } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

type ReportSummary = {
  id: string;
  title: string | null;
  ref: string | null;
  status: string;
  proposed_verdict: string | null;
  pdf_ready: boolean;
};

/** The newest finished report (made by an earlier scan of the e2e run or of the dev stack), or null. */
async function newestReadyReport(page: Page): Promise<ReportSummary | null> {
  const response = await page.request.get("/api/v1/reports", { params: { status: "ready", limit: 1 } });
  if (!response.ok()) return null;
  const body = (await response.json()) as { items: ReportSummary[] };
  return body.items[0] ?? null;
}

test.describe("report view", () => {
  let report: ReportSummary | null = null;

  test.beforeEach(async ({ page }) => {
    await signInAs(page, "Analyst");
    report = await newestReadyReport(page);
    test.skip(report === null, "There is no finished report yet. Run a scan first (see sast.spec.ts).");
    await page.goto(`/reports/${report?.id ?? ""}`);
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  });

  test("shows the report in a sandboxed frame, with the verdict and the downloads", async ({ page }) => {
    const frame = page.locator('iframe[title="Report"]');
    await expect(frame).toBeVisible();
    await expect(frame).toHaveAttribute("sandbox", "");
    await expect(frame).toHaveAttribute("src", new RegExp(`/api/v1/reports/${report?.id ?? ""}/html$`));
    // The report itself is readable inside the frame (the frame cannot run scripts or leave the page).
    await expect(page.frameLocator('iframe[title="Report"]').locator("body")).not.toBeEmpty();
    await expect(page.getByTestId("report-verdict")).toBeVisible();
    await expect(page.getByRole("link", { name: "Download PDF" })).toHaveAttribute("href", /\/api\/v1\/reports\/.+\/pdf$/);
    await expect(page.getByRole("link", { name: "Download findings (CSV)" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Back to the scan" })).toBeVisible();
    await expectNoSeriousA11yViolations(page);
  });

  test("downloads the PDF", async ({ page }) => {
    test.skip(!report?.pdf_ready, "This report has no PDF.");
    const download = page.waitForEvent("download");
    await page.getByRole("link", { name: "Download PDF" }).click();
    expect((await download).suggestedFilename()).toMatch(/\.pdf$/i);
  });

  test("an analyst sees the review controls and must give a reason to override", async ({ page }) => {
    const form = page.getByRole("form", { name: "Review the report" });
    await expect(form).toBeVisible();
    await form.getByLabel("Set a verdict myself").check();
    await form.getByRole("button", { name: /Save the review/ }).click();
    await expect(form.getByText("Choose pass, conditional pass or fail.")).toBeVisible();
    await expect(form.getByText(/Overriding the verdict needs a reason/)).toBeVisible();
  });

  test("a passing verdict has no conditions", async ({ page }) => {
    const form = page.getByRole("form", { name: "Review the report" });
    await form.getByLabel("Set a verdict myself").check();
    await form.getByLabel("Verdict", { exact: true }).selectOption("pass");
    await expect(form.getByText("A passing verdict has no conditions.")).toBeVisible();
    await expect(form.getByRole("button", { name: "Add a condition" })).toHaveCount(0);
  });

  test("confirms the proposed verdict and shows the review", async ({ page }) => {
    test.skip(!["pass", "conditional", "fail"].includes(report?.proposed_verdict ?? ""), "The policy proposed no verdict.");
    const form = page.getByRole("form", { name: "Review the report" });
    await form.getByLabel(/Confirm the proposed verdict/).check();
    await form.getByRole("button", { name: /Save the review/ }).click();
    await expect(page.getByText(/Review saved/)).toBeVisible({ timeout: 60_000 });
    await expect(page.getByText(/Reviewed .*/).first()).toBeVisible();
  });
});
