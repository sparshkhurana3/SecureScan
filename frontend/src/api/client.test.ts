import {
  ApiError,
  apiFetch,
  apiUrl,
  buildQueryString,
  CSRF_COOKIE,
  CSRF_HEADER,
  readCookie,
  setCsrfFallback,
} from "./client";

type FetchCall = { url: string; init: RequestInit };

function mockFetch(response: Response): FetchCall[] {
  const calls: FetchCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init: RequestInit) => {
      calls.push({ url, init });
      return Promise.resolve(response.clone());
    }),
  );
  return calls;
}

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

function problem(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/problem+json" },
  });
}

function header(call: FetchCall | undefined, name: string): string | undefined {
  return (call?.init.headers as Record<string, string> | undefined)?.[name];
}

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfFallback(null);
});

describe("apiUrl and query strings", () => {
  it("puts paths under /api/v1 once", () => {
    expect(apiUrl("/me")).toBe("/api/v1/me");
    expect(apiUrl("me")).toBe("/api/v1/me");
    expect(apiUrl("/api/v1/me")).toBe("/api/v1/me");
  });

  it("repeats array keys and leaves out undefined and empty values", () => {
    const query = buildQueryString({
      tool: ["semgrep", "gitleaks"],
      severity: [],
      q: "",
      limit: 50,
      active: true,
      after: undefined,
    });
    expect(query).toBe("?tool=semgrep&tool=gitleaks&limit=50&active=true");
    expect(buildQueryString({})).toBe("");
    expect(buildQueryString(undefined)).toBe("");
  });

  it("encodes special characters", () => {
    expect(apiUrl("/x", { q: "a&b=c d" })).toBe("/api/v1/x?q=a%26b%3Dc+d");
  });
});

describe("readCookie", () => {
  it("finds a cookie by name", () => {
    expect(readCookie("b", "a=1; b=two%20words; c=3")).toBe("two words");
    expect(readCookie("missing", "a=1")).toBeNull();
  });
});

describe("apiFetch", () => {
  it("sends the CSRF header from the cookie on unsafe methods", async () => {
    document.cookie = `${CSRF_COOKIE}=token-123; path=/`;
    for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
      const calls = mockFetch(json({ ok: true }));
      await apiFetch("/things", { method, body: { a: 1 } });
      expect(header(calls[0], CSRF_HEADER)).toBe("token-123");
    }
  });

  it("does not send the CSRF header on GET", async () => {
    document.cookie = `${CSRF_COOKIE}=token-123; path=/`;
    const calls = mockFetch(json({ ok: true }));
    await apiFetch("/things");
    expect(calls[0]?.init.method).toBe("GET");
    expect(header(calls[0], CSRF_HEADER)).toBeUndefined();
  });

  it("falls back to the token from /me when the cookie cannot be read", async () => {
    setCsrfFallback("from-me");
    const calls = mockFetch(json({}));
    await apiFetch("/things", { method: "POST", body: {} });
    expect(header(calls[0], CSRF_HEADER)).toBe("from-me");
  });

  it("calls the API with same-origin credentials and a JSON body", async () => {
    const calls = mockFetch(json({ id: 1 }));
    const result = await apiFetch<{ id: number }>("/policies", {
      method: "POST",
      body: { name: "x" },
      query: { dry_run: true },
    });
    expect(result).toEqual({ id: 1 });
    expect(calls[0]?.url).toBe("/api/v1/policies?dry_run=true");
    expect(calls[0]?.init.credentials).toBe("same-origin");
    expect(calls[0]?.init.body).toBe('{"name":"x"}');
    expect(header(calls[0], "Content-Type")).toBe("application/json");
  });

  it("sends form data without a JSON content type", async () => {
    const calls = mockFetch(json({}));
    const formData = new FormData();
    formData.append("name", "template");
    await apiFetch("/templates", { method: "POST", formData });
    expect(calls[0]?.init.body).toBe(formData);
    expect(header(calls[0], "Content-Type")).toBeUndefined();
  });

  it("returns undefined for 204", async () => {
    mockFetch(new Response(null, { status: 204 }));
    await expect(apiFetch("/auth/logout", { method: "POST" })).resolves.toBeUndefined();
  });

  it("returns text for a non-JSON answer", async () => {
    mockFetch(new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }));
    await expect(apiFetch<string>("/templates/1/preview", { method: "POST" })).resolves.toBe("<html></html>");
  });

  it("throws ApiError with the parsed problem details", async () => {
    mockFetch(
      problem(422, {
        type: "urn:securescan:problem:unprocessable-entity",
        title: "Unprocessable Entity",
        status: 422,
        detail: "An active policy already exists for this data classification.",
        code: "policy.duplicate_classification",
        errors: [{ field: "body.name", message: "field required", code: "missing" }, { nonsense: true }],
      }),
    );
    const error = await apiFetch("/policies", { method: "POST", body: {} }).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    const api = error as ApiError;
    expect(api.status).toBe(422);
    expect(api.problem.title).toBe("Unprocessable Entity");
    expect(api.problem.detail).toBe("An active policy already exists for this data classification.");
    expect(api.problem.code).toBe("policy.duplicate_classification");
    expect(api.problem.errors).toEqual([{ field: "body.name", message: "field required", code: "missing" }]);
    expect(api.message).toBe("An active policy already exists for this data classification.");
  });

  it("uses the title when the problem has no detail", async () => {
    mockFetch(problem(404, { title: "Not Found", status: 404 }));
    const error = (await apiFetch("/x").catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(404);
    expect(error.problem).toEqual({ title: "Not Found" });
    expect(error.message).toBe("Not Found");
  });

  it("copes with an error that is not JSON", async () => {
    mockFetch(new Response("Bad gateway", { status: 502, statusText: "Bad Gateway" }));
    const error = (await apiFetch("/x").catch((e: unknown) => e)) as ApiError;
    expect(error).toBeInstanceOf(ApiError);
    expect(error.status).toBe(502);
    expect(error.problem.title).toBe("Bad Gateway");
  });
});
