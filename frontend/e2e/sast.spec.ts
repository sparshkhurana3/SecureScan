import { expect, test, type Page } from "@playwright/test";

import { expectNoSeriousA11yViolations, signInAs } from "./support/portal-signin";

/** A zip file made in memory (stored entries, no compression), so the test needs no fixture on disk. */
function makeZip(files: Record<string, string>): Buffer {
  const crc32 = (data: Buffer): number => {
    let crc = 0xffffffff;
    for (const byte of data) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    return (crc ^ 0xffffffff) >>> 0;
  };
  const parts: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of Object.entries(files)) {
    const nameBytes = Buffer.from(name, "utf8");
    const data = Buffer.from(text, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    parts.push(local, nameBytes, data);
    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4);
    entry.writeUInt16LE(20, 6);
    entry.writeUInt16LE(0, 8);
    entry.writeUInt16LE(0, 10);
    entry.writeUInt16LE(0, 12);
    entry.writeUInt16LE(0x21, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);
    offset += local.length + nameBytes.length + data.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, directory, end]);
}

const PLANTED = {
  "app.py": [
    "import os, pickle",
    "",
    'API_KEY = "AKIAIOSFODNN7EXAMPLE"',
    "",
    "def run(request):",
    '    os.system("ping " + request.args["host"])',
    '    return pickle.loads(request.data)',
    "",
  ].join("\n"),
  "requirements.txt": "flask==0.12\n",
};

async function openSastPage(page: Page) {
  await signInAs(page, "Analyst");
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "SAST scan" }).click();
  await expect(page.getByRole("heading", { name: "SAST scan", level: 1 })).toBeVisible();
}

test.describe("SAST scan page", () => {
  test("shows the source choices, the tools of the profile and passes the accessibility check", async ({ page }) => {
    await openSastPage(page);
    const form = page.getByRole("form", { name: "Start a code scan" });
    await expect(form.getByLabel("A connected GitHub repository")).toBeVisible();
    await expect(form.getByLabel("A repository address")).toBeChecked();
    await expect(form.getByLabel("A zip file of the source code")).toBeVisible();
    await expect(form.getByLabel("A Docker image")).toBeVisible();
    await expect(form.getByRole("checkbox", { name: "Semgrep" })).toBeChecked();
    await expect(form.getByRole("checkbox", { name: "Gitleaks" })).toBeChecked();
    await expect(page.getByRole("table", { name: "Running and recent code scans" }).or(page.getByText("No code scans yet"))).toBeVisible();
    await expectNoSeriousA11yViolations(page);
  });

  test("names what is missing instead of sending an incomplete form", async ({ page }) => {
    await openSastPage(page);
    await page.getByRole("button", { name: "Start scan" }).click();
    await expect(page.getByText("Enter the repository address.")).toBeVisible();
    await expect(page.getByText("Enter the application name.")).toBeVisible();
    await expect(page.getByText(/Enter a version label/)).toBeVisible();
    await expect(page).toHaveURL(/\/sast/);
  });

  test("a vendor application asks for the vendor, the hosting and a way into the repository", async ({ page }) => {
    await openSastPage(page);
    await page.getByLabel("Vendor (a supplier develops it)").check();
    await expect(page.getByLabel("Vendor", { exact: true })).toBeVisible();
    await expect(page.getByLabel(/Deployable/)).toBeVisible();
    await expect(page.getByLabel(/SaaS \(the vendor hosts it\)/)).toBeVisible();
    await expect(page.getByLabel("Generate a read-only deploy key")).toBeVisible();
    await page.getByLabel("Enter a token the vendor issued").check();
    await expect(page.getByLabel("Vendor token")).toHaveAttribute("type", "password");
  });

  test("uploads a zip, starts the scan, follows it live and finds the report", async ({ page }) => {
    test.setTimeout(10 * 60_000);
    const name = `E2E planted ${String(Date.now())}`;
    await openSastPage(page);

    await page.getByLabel("A zip file of the source code").check();
    await page.getByLabel("Zip file", { exact: true }).setInputFiles({
      name: "planted.zip",
      mimeType: "application/zip",
      buffer: makeZip(PLANTED),
    });
    await expect(page.getByTestId("upload-done")).toContainText("planted.zip", { timeout: 60_000 });

    await page.getByLabel("New application name").fill(name);
    await page.getByLabel("Version label").fill("e2e-1");
    await page.getByRole("button", { name: "Start scan" }).click();

    // The scan page: per-tool status, the live log and the connection state.
    await expect(page).toHaveURL(/\/scans\/[0-9a-f-]{36}/, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name, level: 1 })).toBeVisible();
    await expect(page.getByRole("table", { name: "Status of each tool" })).toBeVisible();
    await expect(page.getByRole("log", { name: "Scan log" })).toBeVisible();
    await expect(page.getByTestId("log-connection")).toHaveText(/Live|Stream ended/, { timeout: 30_000 });

    // The scan ends and the report appears.
    await expect(page.getByRole("link", { name: "Open the report" })).toBeVisible({ timeout: 8 * 60_000 });
    await expect(page.getByTestId("severity-counts")).toBeVisible();
    await expectNoSeriousA11yViolations(page);

    // The same scan is in the list of the SAST page, with a link to its report.
    await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "SAST scan" }).click();
    const row = page.getByRole("table", { name: "Running and recent code scans" }).getByRole("row").filter({ hasText: name });
    await expect(row).toBeVisible();
    await expect(row.getByRole("link", { name: /Report of the scan/ })).toBeVisible();
  });

  test("a scan can be cancelled from its page", async ({ page }) => {
    test.setTimeout(3 * 60_000);
    const name = `E2E cancel ${String(Date.now())}`;
    await openSastPage(page);
    await page.getByLabel("A zip file of the source code").check();
    await page.getByLabel("Zip file", { exact: true }).setInputFiles({
      name: "planted.zip",
      mimeType: "application/zip",
      buffer: makeZip(PLANTED),
    });
    await expect(page.getByTestId("upload-done")).toBeVisible({ timeout: 60_000 });
    await page.getByLabel("New application name").fill(name);
    await page.getByLabel("Version label").fill("e2e-cancel");
    await page.getByRole("button", { name: "Start scan" }).click();
    await expect(page).toHaveURL(/\/scans\//, { timeout: 30_000 });

    const cancel = page.getByRole("button", { name: "Cancel scan" });
    // A very fast scan may already be over; then there is nothing to cancel.
    test.skip(!(await cancel.isVisible()), "The scan finished before it could be cancelled.");
    await cancel.click();
    await page.getByRole("button", { name: "Yes, cancel the scan" }).click();
    await expect(page.getByText("Cancelled", { exact: true }).first()).toBeVisible({ timeout: 60_000 });
  });
});
