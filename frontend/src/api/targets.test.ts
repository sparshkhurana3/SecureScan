import type { ApplicationChoice } from "./applications";
import {
  authorizationSummary,
  buildTargetCreateBody,
  buildTargetUpdateBody,
  emptyTargetForm,
  formatBlackoutWindow,
  isValidUrl,
  loginProfileAllowed,
  modesForEnvironment,
  parseBlackoutLine,
  parseBlackoutText,
  splitLines,
  validateTargetForm,
  type Target,
  type TargetFormValues,
} from "./targets";

const internalApp = { type: "internal", hosting: null } as const;
const saasApp = { type: "vendor", hosting: "saas" } as const;
const existing: ApplicationChoice = { kind: "existing", application: null };

function form(patch: Partial<TargetFormValues> = {}): TargetFormValues {
  return {
    ...emptyTargetForm(existing),
    versionLabel: "uat",
    url: "https://app.example.com",
    environment: "uat",
    ...patch,
  };
}

describe("modesForEnvironment", () => {
  it("offers only the baseline for production", () => {
    expect(modesForEnvironment("production")).toEqual(["baseline"]);
  });

  it("offers baseline, full, API and Nuclei for UAT", () => {
    expect(modesForEnvironment("uat")).toEqual(["baseline", "full", "api", "nuclei"]);
  });

  it("offers nothing for an address without a tag", () => {
    expect(modesForEnvironment(null)).toEqual([]);
    expect(modesForEnvironment(undefined)).toEqual([]);
  });

  it("returns a copy that callers can change", () => {
    modesForEnvironment("uat").pop();
    expect(modesForEnvironment("uat")).toHaveLength(4);
  });

  it("allows login profiles on UAT only", () => {
    expect(loginProfileAllowed("uat")).toBe(true);
    expect(loginProfileAllowed("production")).toBe(false);
    expect(loginProfileAllowed("")).toBe(false);
    expect(loginProfileAllowed(null)).toBe(false);
  });
});

describe("blackout windows", () => {
  it("reads a weekly window", () => {
    expect(parseBlackoutLine("Mon,Wed 22:00-23:30 nightly batch")).toEqual({
      ok: true,
      window: { days: [0, 2], start: "22:00", end: "23:30", reason: "nightly batch" },
    });
  });

  it("accepts day numbers and full names and sorts the days", () => {
    expect(parseBlackoutLine("sunday,0 01:00-02:00")).toEqual({
      ok: true,
      window: { days: [0, 6], start: "01:00", end: "02:00" },
    });
  });

  it("reads a one-off window", () => {
    const parsed = parseBlackoutLine("2026-10-10T22:00Z/2026-10-11T02:00Z release freeze");
    expect(parsed).toEqual({
      ok: true,
      window: { starts_at: "2026-10-10T22:00:00.000Z", ends_at: "2026-10-11T02:00:00.000Z", reason: "release freeze" },
    });
  });

  it("explains what is wrong", () => {
    expect(parseBlackoutLine("Someday 22:00-23:00")).toMatchObject({ ok: false });
    expect(parseBlackoutLine("Mon 25:00-26:00")).toMatchObject({ ok: false });
    expect(parseBlackoutLine("Mon")).toMatchObject({ ok: false });
    expect(parseBlackoutLine("2026-10-11T02:00Z/2026-10-10T22:00Z")).toMatchObject({ ok: false });
    expect(parseBlackoutLine("nonsense/never")).toMatchObject({ ok: false });
  });

  it("numbers the lines of a text and skips blank lines", () => {
    const parsed = parseBlackoutText("Mon 01:00-02:00\n\n  \nFunday 01:00-02:00\nTue 03:00-04:00");
    expect(parsed.windows).toHaveLength(2);
    expect(parsed.errors).toHaveLength(1);
    expect(parsed.errors[0]).toMatch(/^Line 2:/);
  });

  it("writes a window back as the text it was read from", () => {
    for (const line of ["Mon,Wed 22:00-23:30 nightly batch", "Sat,Sun 00:00-06:00"]) {
      const parsed = parseBlackoutLine(line);
      expect(parsed.ok && formatBlackoutWindow(parsed.window)).toBe(line);
    }
    const oneOff = parseBlackoutLine("2026-10-10T22:00Z/2026-10-11T02:00Z freeze");
    expect(oneOff.ok && parseBlackoutLine(formatBlackoutWindow(oneOff.window))).toEqual(oneOff);
  });
});

describe("small helpers", () => {
  it("splits text into trimmed non-empty lines", () => {
    expect(splitLines(" /a \r\n\n/b\n  ")).toEqual(["/a", "/b"]);
  });

  it("accepts http and https addresses without credentials", () => {
    expect(isValidUrl("https://app.example.com/path")).toBe(true);
    expect(isValidUrl("http://10.0.0.5:8080")).toBe(true);
    expect(isValidUrl("ftp://app.example.com")).toBe(false);
    expect(isValidUrl("https://user:pw@app.example.com")).toBe(false);
    expect(isValidUrl("app.example.com")).toBe(false);
    expect(isValidUrl("")).toBe(false);
  });
});

describe("validateTargetForm", () => {
  const create = { mode: "create", application: internalApp } as const;

  it("accepts a complete UAT address", () => {
    expect(validateTargetForm(form(), create)).toEqual({});
  });

  it("asks for the address, the tag and the version label", () => {
    const errors = validateTargetForm(form({ url: "", environment: "", versionLabel: " " }), create);
    expect(Object.keys(errors).sort()).toEqual(["environment", "url", "versionLabel"]);
  });

  it("does not ask for a version label when editing", () => {
    expect(validateTargetForm(form({ versionLabel: "" }), { mode: "edit", application: internalApp })).toEqual({});
  });

  it("refuses a login profile on production and a malformed id on UAT", () => {
    const id = "3f2b8c1e-0000-4000-8000-000000000000";
    expect(validateTargetForm(form({ environment: "production", loginProfileId: id }), create).loginProfileId).toMatch(
      /UAT targets only/,
    );
    expect(validateTargetForm(form({ loginProfileId: "abc" }), create).loginProfileId).toBeDefined();
    expect(validateTargetForm(form({ loginProfileId: id }), create)).toEqual({});
  });

  it("checks the request limit, the schedule and the blackout windows", () => {
    expect(validateTargetForm(form({ rateLimit: "0" }), create).rateLimit).toBeDefined();
    expect(validateTargetForm(form({ rateLimit: "1001" }), create).rateLimit).toBeDefined();
    expect(validateTargetForm(form({ rateLimit: "2.5" }), create).rateLimit).toBeDefined();
    expect(validateTargetForm(form({ rateLimit: "50" }), create)).toEqual({});
    expect(validateTargetForm(form({ cron: "0 2 * *" }), create).cron).toBeDefined();
    expect(validateTargetForm(form({ cron: "0 2 * * 0" }), create)).toEqual({});
    expect(validateTargetForm(form({ blackouts: "Mon 22:00" }), create).blackouts).toMatch(/Line 1/);
  });

  it("needs the type and the address of an API definition together", () => {
    expect(validateTargetForm(form({ apiSpecType: "openapi" }), create).apiSpecLocator).toBeDefined();
    expect(validateTargetForm(form({ apiSpecLocator: "https://x/openapi.json" }), create).apiSpecType).toBeDefined();
    expect(
      validateTargetForm(form({ apiSpecType: "openapi", apiSpecLocator: "https://x/openapi.json" }), create),
    ).toEqual({});
  });

  it("needs the vendor's authorization for a SaaS product", () => {
    const saas = { mode: "create", application: saasApp } as const;
    const errors = validateTargetForm(form(), saas);
    expect(Object.keys(errors).sort()).toEqual([
      "vendorAuthorization",
      "vendorAuthorizedFrom",
      "vendorAuthorizedUntil",
      "vendorContact",
    ]);
    const complete = form({
      vendorAuthorizationArtifactId: "art-1",
      vendorAuthorizedFrom: "2026-11-01",
      vendorAuthorizedUntil: "2026-11-30",
      vendorContact: "security@vendor.example",
    });
    expect(validateTargetForm(complete, saas)).toEqual({});
    expect(
      validateTargetForm({ ...complete, vendorAuthorizedUntil: "2026-10-01" }, saas).vendorAuthorizedUntil,
    ).toBeDefined();
  });

  it("does not ask an internal or deployable application for authorization", () => {
    expect(validateTargetForm(form(), { mode: "create", application: { type: "vendor", hosting: "deployable" } })).toEqual(
      {},
    );
  });
});

describe("request bodies", () => {
  it("sends only what was filled in when creating", () => {
    expect(buildTargetCreateBody(form(), internalApp, false)).toEqual({
      kind: "url",
      locator: "https://app.example.com",
      environment: "uat",
    });
  });

  it("sends the filled-in fields", () => {
    const body = buildTargetCreateBody(
      form({
        name: " Shop ",
        scopeIncludes: "^https://app\\.example\\.com/.*\n",
        scopeExcludes: "/logout\n/admin",
        rateLimit: "20",
        cron: "0 2 * * 0",
        blackouts: "Mon 22:00-23:00",
        apiSpecType: "openapi",
        apiSpecLocator: " https://app.example.com/openapi.json ",
        loginProfileId: "3f2b8c1e-0000-4000-8000-000000000000",
      }),
      internalApp,
      false,
    );
    expect(body).toMatchObject({
      name: "Shop",
      scope_includes: ["^https://app\\.example\\.com/.*"],
      scope_excludes: ["/logout", "/admin"],
      rate_limit_rps: 20,
      dast_cron: "0 2 * * 0",
      blackout_windows: [{ days: [0], start: "22:00", end: "23:00" }],
      api_spec_type: "openapi",
      api_spec_locator: "https://app.example.com/openapi.json",
      login_profile_id: "3f2b8c1e-0000-4000-8000-000000000000",
    });
  });

  it("never sends a login profile for a production address", () => {
    const body = buildTargetCreateBody(
      form({ environment: "production", loginProfileId: "3f2b8c1e-0000-4000-8000-000000000000" }),
      internalApp,
      false,
    );
    expect(body.login_profile_id).toBeUndefined();
    const update = buildTargetUpdateBody(
      form({ environment: "production", loginProfileId: "3f2b8c1e-0000-4000-8000-000000000000" }),
      internalApp,
      false,
      { host_approved: false },
    );
    expect(update.login_profile_id).toBeNull();
  });

  it("sends host_approved only for an Admin", () => {
    expect(buildTargetCreateBody(form({ hostApproved: true }), internalApp, false).host_approved).toBeUndefined();
    expect(buildTargetCreateBody(form({ hostApproved: true }), internalApp, true).host_approved).toBe(true);
    expect(buildTargetUpdateBody(form({ hostApproved: true }), internalApp, true, { host_approved: true })).not.toHaveProperty(
      "host_approved",
    );
    expect(
      buildTargetUpdateBody(form({ hostApproved: false }), internalApp, true, { host_approved: true }).host_approved,
    ).toBe(false);
  });

  it("clears fields that were emptied when updating", () => {
    const body = buildTargetUpdateBody(form(), internalApp, false, { host_approved: false });
    expect(body).toMatchObject({
      locator: "https://app.example.com",
      environment: "uat",
      name: null,
      scope_includes: [],
      scope_excludes: [],
      rate_limit_rps: null,
      dast_cron: null,
      blackout_windows: [],
      login_profile_id: null,
      api_spec_type: null,
      api_spec_locator: null,
    });
  });

  it("carries the vendor authorization of a SaaS product with its dates", () => {
    const body = buildTargetCreateBody(
      form({
        vendorAuthorizationArtifactId: "art-1",
        vendorAuthorizedFrom: "2026-11-01",
        vendorAuthorizedUntil: "2026-11-30",
        vendorContact: "security@vendor.example",
        vendorNotes: "Window agreed by phone",
      }),
      saasApp,
      false,
    );
    expect(body).toMatchObject({
      vendor_authorization_artifact_id: "art-1",
      vendor_authorized_from: "2026-11-01T00:00:00Z",
      vendor_authorized_until: "2026-11-30T23:59:59Z",
      vendor_contact: "security@vendor.example",
      vendor_authorization_notes: "Window agreed by phone",
    });
    expect(buildTargetCreateBody(form(), internalApp, false)).not.toHaveProperty("vendor_contact");
  });
});

describe("authorizationSummary", () => {
  const target = { vendor_authorization_artifact_id: null, vendor_authorized_until: null } as Target;

  it("says when it is not needed, missing or on file", () => {
    expect(authorizationSummary(target, internalApp)).toBe("Not needed");
    expect(authorizationSummary(target, saasApp)).toBe("Missing");
    expect(
      authorizationSummary(
        { ...target, vendor_authorization_artifact_id: "a", vendor_authorized_until: "2026-11-30T23:59:59Z" },
        saasApp,
      ),
    ).toBe("On file until 2026-11-30");
  });
});
