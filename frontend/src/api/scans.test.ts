import type { Application, ApplicationChoice } from "./applications";
import { apiFetch, type ApiInit } from "./client";
import {
  buildReviewBody,
  effectiveVerdict,
  emptySourceState,
  initialReview,
  isValidImageReference,
  isValidRepositoryAddress,
  newestProfiles,
  prepareSast,
  profileForMode,
  severityCounts,
  sourceToRequest,
  startPreparedScan,
  validateReview,
  validateSastRequest,
  type ReviewValues,
  type SastRequest,
  type ScanProfile,
} from "./scans";

vi.mock("./client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./client")>();
  return { ...actual, apiFetch: vi.fn() };
});

const TODAY = "2026-10-07";

type ReportDetailLike = {
  proposed_verdict: string;
  conditions: { finding_hash: string; deadline: string }[];
  internal_notes: string;
  vendor_copy: boolean;
};

function profile(patch: Partial<ScanProfile>): ScanProfile {
  return {
    id: "p",
    name: "code-standard",
    version: 1,
    kind: "sast",
    mode: null,
    description: null,
    tools: ["semgrep", "gitleaks"],
    active: true,
    sha256: "x",
    created_at: "2026-10-01T00:00:00Z",
    ...patch,
  };
}

const existingApp = (patch: Partial<Application> = {}): ApplicationChoice => ({
  kind: "existing",
  application: { id: "app-1", name: "Payroll", type: "internal", hosting: null, ...patch } as Application,
});

function request(patch: Partial<SastRequest> = {}): SastRequest {
  return {
    source: { kind: "url", url: "sona/payroll", credential: { mode: "existing" } },
    application: existingApp(),
    versionLabel: "main",
    ref: "",
    profile: "code-standard",
    tools: ["semgrep", "gitleaks"],
    profileTools: ["semgrep", "gitleaks"],
    ...patch,
  };
}

describe("repository and image addresses", () => {
  it("accepts owner/name, https and ssh addresses", () => {
    for (const ok of [
      "sona/payroll",
      "https://github.com/sona/payroll.git",
      "http://git.internal/sona/payroll",
      "git@github.com:sona/payroll.git",
      "ssh://git@github.com/sona/payroll.git",
    ]) {
      expect(isValidRepositoryAddress(ok)).toBe(true);
    }
  });

  it("refuses spaces, passwords in the address and anything else", () => {
    for (const bad of ["", "payroll", "sona payroll", "https://user:pw@github.com/sona/payroll", "ftp://x/y", "https://x"]) {
      expect(isValidRepositoryAddress(bad)).toBe(false);
    }
  });

  it("accepts image references without a scheme or spaces", () => {
    expect(isValidImageReference("registry.example.com/team/app:1.4.2")).toBe(true);
    expect(isValidImageReference("app@sha256:" + "a".repeat(64))).toBe(true);
    expect(isValidImageReference("docker://app")).toBe(false);
    expect(isValidImageReference("my app")).toBe(false);
    expect(isValidImageReference(" ")).toBe(false);
  });
});

describe("validateSastRequest", () => {
  it("accepts a complete repository request", () => {
    expect(validateSastRequest(request(), TODAY)).toEqual({});
  });

  it("asks for the source, the version label and a tool", () => {
    const errors = validateSastRequest(
      request({ source: { kind: "url", url: "", credential: { mode: "existing" } }, versionLabel: " ", tools: [] }),
      TODAY,
    );
    expect(Object.keys(errors).sort()).toEqual(["source", "tools", "versionLabel"]);
  });

  it("needs a finished upload for a zip or an image file", () => {
    expect(validateSastRequest(request({ source: { kind: "zip", artifactId: null, filename: "" } }), TODAY).source).toMatch(
      /Upload the file/,
    );
    expect(
      validateSastRequest(request({ source: { kind: "zip", artifactId: "art-1", filename: "a.zip" } }), TODAY),
    ).toEqual({});
    expect(
      validateSastRequest(request({ source: { kind: "image_tar", artifactId: null, filename: "" } }), TODAY).source,
    ).toBeDefined();
  });

  it("checks an image reference", () => {
    expect(validateSastRequest(request({ source: { kind: "image", reference: "" } }), TODAY).source).toBeDefined();
    expect(validateSastRequest(request({ source: { kind: "image", reference: "my app" } }), TODAY).source).toBeDefined();
    expect(validateSastRequest(request({ source: { kind: "image", reference: "reg/app:1" } }), TODAY)).toEqual({});
  });

  it("needs a token of 20 characters and a future expiry date", () => {
    const withToken = (token: string, expiresOn: string) =>
      request({ source: { kind: "url", url: "sona/payroll", credential: { mode: "token", token, expiresOn } } });
    const errors = validateSastRequest(withToken("short", ""), TODAY);
    expect(errors.token).toBeDefined();
    expect(errors.tokenExpires).toBeDefined();
    expect(validateSastRequest(withToken("x".repeat(30), TODAY), TODAY).tokenExpires).toMatch(/past/);
    expect(validateSastRequest(withToken("x".repeat(30), "2026-12-31"), TODAY)).toEqual({});
  });

  it("prefixes the errors of the application part", () => {
    const errors = validateSastRequest(
      request({
        application: {
          kind: "new",
          name: "",
          type: "vendor",
          vendorId: "",
          newVendorName: "",
          vendorProduct: "",
          hosting: "",
        },
      }),
      TODAY,
    );
    expect(Object.keys(errors).sort()).toEqual(["application.hosting", "application.name", "application.vendor"]);
  });

  it("refuses a reference with spaces", () => {
    expect(validateSastRequest(request({ ref: "my branch" }), TODAY).ref).toBeDefined();
    expect(validateSastRequest(request({ ref: "release/1.2" }), TODAY)).toEqual({});
  });
});

describe("source state", () => {
  it("turns the form state into a source", () => {
    const base = emptySourceState();
    expect(sourceToRequest({ ...base, kind: "url", url: "a/b", credentialMode: "deploy_key" })).toEqual({
      kind: "url",
      url: "a/b",
      credential: { mode: "deploy_key" },
    });
    expect(sourceToRequest({ ...base, kind: "url", url: "a/b", credentialMode: "token", token: "t", tokenExpires: "2027-01-01" })).toEqual({
      kind: "url",
      url: "a/b",
      credential: { mode: "token", token: "t", expiresOn: "2027-01-01" },
    });
    expect(sourceToRequest({ ...base, kind: "image", imageMode: "reference", imageRef: "r/a:1" })).toEqual({
      kind: "image",
      reference: "r/a:1",
    });
    expect(
      sourceToRequest({
        ...base,
        kind: "image",
        imageMode: "tar",
        imageTar: { uploadId: "u", artifactId: "art", sha256: null, sizeBytes: 5, filename: "i.tar" },
      }),
    ).toEqual({ kind: "image_tar", artifactId: "art", filename: "i.tar" });
    expect(sourceToRequest({ ...base, kind: "zip" })).toEqual({ kind: "zip", artifactId: null, filename: "" });
  });
});

describe("profiles and counts", () => {
  it("keeps the newest active version of each profile", () => {
    const list = newestProfiles([
      profile({ name: "b", version: 1 }),
      profile({ name: "a", version: 1 }),
      profile({ name: "a", version: 3 }),
      profile({ name: "a", version: 4, active: false }),
    ]);
    expect(list.map((item) => `${item.name}@${String(item.version)}`)).toEqual(["a@3", "b@1"]);
  });

  it("finds the profile of a DAST mode by its mode or by its conventional name", () => {
    const list = [
      profile({ name: "zap-x", kind: "dast", mode: "full" }),
      profile({ name: "dast-baseline", kind: "dast", mode: null }),
    ];
    expect(profileForMode(list, "full")?.name).toBe("zap-x");
    expect(profileForMode(list, "baseline")?.name).toBe("dast-baseline");
    expect(profileForMode(list, "nuclei")).toBeUndefined();
  });

  it("reads counts from a loose object", () => {
    expect(severityCounts({ critical: 1, high: 2, medium: "x", low: 3 })).toEqual({
      critical: 1,
      high: 2,
      medium: 0,
      low: 3,
      info: 0,
      total: 6,
    });
    expect(severityCounts({ high: 1, total: 9 }).total).toBe(9);
    expect(severityCounts(undefined).total).toBe(0);
  });
});

describe("validateReview", () => {
  const confirm: ReviewValues = {
    decision: "confirm",
    verdict: "",
    reason: "",
    conditions: [],
    internalNotes: "",
    vendorCopy: false,
  };
  const override = (patch: Partial<ReviewValues>): ReviewValues => ({ ...confirm, decision: "override", ...patch });

  it("confirms a proposed verdict", () => {
    expect(validateReview(confirm, "conditional", TODAY)).toEqual({});
    expect(effectiveVerdict(confirm, "conditional")).toBe("conditional");
  });

  it("cannot confirm when nothing was proposed", () => {
    expect(validateReview(confirm, "pending", TODAY).decision).toBeDefined();
    expect(validateReview(confirm, null, TODAY).decision).toBeDefined();
  });

  it("needs a verdict and a reason to override, and the verdict must differ", () => {
    expect(Object.keys(validateReview(override({}), "fail", TODAY)).sort()).toEqual(["reason", "verdict"]);
    expect(validateReview(override({ verdict: "fail", reason: "because of x" }), "fail", TODAY).verdict).toMatch(
      /proposed verdict/,
    );
    expect(validateReview(override({ verdict: "pass", reason: "four" }), "fail", TODAY).reason).toBeDefined();
    expect(validateReview(override({ verdict: "pass", reason: "False positives, checked" }), "fail", TODAY)).toEqual({});
    expect(validateReview(override({ verdict: "conditional", reason: "agreed with the vendor" }), "pending", TODAY)).toEqual(
      {},
    );
  });

  it("refuses conditions on a passing verdict", () => {
    const withCondition = { findingKey: "k1", deadline: "2026-11-01" };
    expect(validateReview({ ...confirm, conditions: [withCondition] }, "pass", TODAY).conditions).toBeDefined();
    expect(validateReview({ ...confirm, conditions: [withCondition] }, "conditional", TODAY)).toEqual({});
  });

  it("checks each condition: a finding of the report, no repeats, a deadline that is not in the past", () => {
    const open = new Set(["k1", "k2"]);
    const errors = validateReview(
      {
        ...confirm,
        conditions: [
          { findingKey: "", deadline: "2026-11-01" },
          { findingKey: "k9", deadline: "2026-11-01" },
          { findingKey: "k1", deadline: "2026-10-06" },
          { findingKey: "k1", deadline: "" },
          { findingKey: "k2", deadline: TODAY },
        ],
      },
      "fail",
      TODAY,
      open,
    );
    expect(errors["condition.0.finding"]).toBeDefined();
    expect(errors["condition.1.finding"]).toMatch(/not an open finding/);
    expect(errors["condition.2.deadline"]).toMatch(/past/);
    expect(errors["condition.3.finding"]).toMatch(/twice/);
    expect(errors["condition.3.deadline"]).toBeDefined();
    expect(errors["condition.4.deadline"]).toBeUndefined();
    expect(errors["condition.4.finding"]).toBeUndefined();
  });

  it("builds the request the API expects", () => {
    expect(
      buildReviewBody(
        { ...confirm, conditions: [{ findingKey: "k1", deadline: "2026-11-01" }], internalNotes: "note" },
        "application",
      ),
    ).toEqual({
      decision: "confirm",
      conditions: [{ finding_hash: "k1", deadline: "2026-11-01" }],
      internal_notes: "note",
    });
    expect(buildReviewBody(override({ verdict: "pass", reason: "  checked it  ", vendorCopy: true }), "vendor")).toEqual({
      decision: "override",
      verdict: "pass",
      reason: "checked it",
      conditions: [],
      internal_notes: "",
      vendor_copy: true,
    });
  });

  it("starts the form from the saved review", () => {
    const report: ReportDetailLike = {
      proposed_verdict: "fail",
      conditions: [{ finding_hash: "k1", deadline: "2026-11-01T00:00:00Z" }],
      internal_notes: "n",
      vendor_copy: true,
    };
    expect(initialReview(report as never)).toEqual({
      decision: "confirm",
      verdict: "",
      reason: "",
      conditions: [{ findingKey: "k1", deadline: "2026-11-01" }],
      internalNotes: "n",
      vendorCopy: true,
    });
    expect(initialReview({ ...report, proposed_verdict: "pending" } as never).decision).toBe("override");
  });
});

// ---------------------------------------------------------------------------------------------
type Call = { method: string; path: string; body?: unknown; headers?: Record<string, string> };

function fakeApi(handlers: Record<string, (call: Call) => unknown>) {
  const calls: Call[] = [];
  vi.mocked(apiFetch).mockImplementation(((path: string, init: ApiInit = {}) => {
    const method = (init.method ?? "GET").toUpperCase();
    const call: Call = { method, path, body: init.body, headers: init.headers };
    calls.push(call);
    const handler = handlers[`${method} ${path}`];
    if (!handler) return Promise.reject(new Error(`unexpected call ${method} ${path}`));
    return Promise.resolve(handler(call));
  }) as unknown as typeof apiFetch);
  return calls;
}

const page = <T>(items: T[]) => ({ items, next_cursor: null });

describe("prepareSast and startPreparedScan", () => {
  it("creates the application, version and zip target, then starts the scan with an idempotency key", async () => {
    const calls = fakeApi({
      "POST /applications": () => ({ id: "app-1", name: "Payroll", type: "internal" }),
      "GET /applications/app-1/versions": () => page([]),
      "POST /applications/app-1/versions": () => ({ id: "ver-1", label: "2026-10" }),
      "POST /versions/ver-1/targets": () => ({ id: "tgt-1", version_id: "ver-1", credential_id: null }),
      "POST /scans": () => ({ id: "scan-1" }),
    });
    const seen: string[] = [];
    const req = request({
      source: { kind: "zip", artifactId: "art-1", filename: "payroll.zip" },
      application: {
        kind: "new",
        name: "Payroll",
        type: "internal",
        vendorId: "",
        newVendorName: "",
        vendorProduct: "",
        hosting: "",
      },
      versionLabel: "2026-10",
    });
    const prepared = await prepareSast(req, { onApplication: (app) => seen.push(app.id) });
    expect(seen).toEqual(["app-1"]);
    expect(prepared.deployKey).toBeNull();
    await startPreparedScan(prepared, req, "key-1");

    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      "POST /applications",
      "GET /applications/app-1/versions",
      "POST /applications/app-1/versions",
      "POST /versions/ver-1/targets",
      "POST /scans",
    ]);
    expect(calls[0]?.body).toEqual({
      name: "Payroll",
      type: "internal",
      vendor_id: null,
      vendor_product: null,
      hosting: null,
    });
    expect(calls[2]?.body).toEqual({ label: "2026-10", label_kind: "upload" });
    expect(calls[3]?.body).toEqual({ kind: "zip", upload_artifact_id: "art-1", name: "payroll.zip" });
    expect(calls[4]?.body).toEqual({ version_id: "ver-1", target_id: "tgt-1", profile: "code-standard" });
    expect(calls[4]?.headers).toEqual({ "Idempotency-Key": "key-1" });
  });

  it("reuses an existing version and repository target and lists the tools only when some are unticked", async () => {
    const calls = fakeApi({
      "GET /applications/app-1/versions": () => page([{ id: "ver-1", label: "main" }]),
      "GET /versions/ver-1/targets": () =>
        page([{ id: "tgt-1", version_id: "ver-1", kind: "github_repo", locator: "sona/payroll", archived_at: null }]),
      "POST /scans": () => ({ id: "scan-1" }),
    });
    const req = request({ tools: ["gitleaks"], ref: " release/2 " });
    const prepared = await prepareSast(req);
    await startPreparedScan(prepared, req, "k");
    expect(calls.map((call) => `${call.method} ${call.path}`)).toEqual([
      "GET /applications/app-1/versions",
      "GET /versions/ver-1/targets",
      "POST /scans",
    ]);
    expect(calls[2]?.body).toEqual({
      version_id: "ver-1",
      target_id: "tgt-1",
      profile: "code-standard",
      tools: ["gitleaks"],
      ref: "release/2",
    });
  });

  it("creates a new vendor and a vendor repository with a generated deploy key", async () => {
    const calls = fakeApi({
      "POST /vendors": () => ({ id: "ven-1", name: "Acme" }),
      "POST /applications": () => ({ id: "app-2", name: "Acme CRM", type: "vendor" }),
      "GET /applications/app-2/versions": () => page([]),
      "POST /applications/app-2/versions": () => ({ id: "ver-2", label: "3.1" }),
      "GET /versions/ver-2/targets": () => page([]),
      "POST /versions/ver-2/targets": () => ({ id: "tgt-2", version_id: "ver-2", credential_id: null }),
      "POST /credentials/deploy-key": () => ({ id: "cred-1", public_key: "ssh-ed25519 AAAA", instructions: "Add it" }),
    });
    const prepared = await prepareSast(
      request({
        source: { kind: "url", url: "https://github.com/acme/crm", credential: { mode: "deploy_key" } },
        application: {
          kind: "new",
          name: "Acme CRM",
          type: "vendor",
          vendorId: "new",
          newVendorName: "Acme",
          vendorProduct: "CRM",
          hosting: "saas",
        },
        versionLabel: "3.1",
      }),
    );
    expect(prepared.deployKey?.public_key).toBe("ssh-ed25519 AAAA");
    expect(calls.find((call) => call.path === "/applications")?.body).toEqual({
      name: "Acme CRM",
      type: "vendor",
      vendor_id: "ven-1",
      vendor_product: "CRM",
      hosting: "saas",
    });
    expect(calls.find((call) => call.path === "/versions/ver-2/targets" && call.method === "POST")?.body).toEqual({
      kind: "vendor_repo",
      locator: "https://github.com/acme/crm",
    });
    expect(calls.find((call) => call.path === "/credentials/deploy-key")?.body).toEqual({
      target_id: "tgt-2",
      replace: false,
    });
  });

  it("stores a vendor token and replaces the credential the target already has", async () => {
    const calls = fakeApi({
      "GET /applications/app-2/versions": () => page([{ id: "ver-2", label: "3.1" }]),
      "GET /versions/ver-2/targets": () =>
        page([
          { id: "tgt-2", version_id: "ver-2", kind: "vendor_repo", locator: "acme/crm", archived_at: null, credential_id: "old" },
        ]),
      "POST /credentials/vendor-token": () => ({ id: "cred-2" }),
    });
    await prepareSast(
      request({
        source: {
          kind: "url",
          url: "acme/crm",
          credential: { mode: "token", token: "t".repeat(24), expiresOn: "2027-01-31" },
        },
        application: existingApp({ id: "app-2", type: "vendor" }),
        versionLabel: "3.1",
      }),
    );
    expect(calls.at(-1)?.body).toEqual({
      target_id: "tgt-2",
      token: "t".repeat(24),
      expires_at: "2027-01-31T23:59:59Z",
      replace: true,
    });
  });

  it("explains when a vendor repository has no stored credential and none was chosen", async () => {
    fakeApi({
      "GET /applications/app-2/versions": () => page([{ id: "ver-2", label: "3.1" }]),
      "GET /versions/ver-2/targets": () =>
        page([{ id: "tgt-2", version_id: "ver-2", kind: "vendor_repo", locator: "acme/crm", archived_at: null, credential_id: null }]),
    });
    await expect(
      prepareSast(
        request({
          source: { kind: "url", url: "acme/crm", credential: { mode: "existing" } },
          application: existingApp({ id: "app-2", type: "vendor" }),
          versionLabel: "3.1",
        }),
      ),
    ).rejects.toThrow(/no deploy key or token/);
  });
});
