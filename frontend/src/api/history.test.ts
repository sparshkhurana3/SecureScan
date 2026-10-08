import { buildQueryString } from "./client";
import {
  activeFilterCount,
  EMPTY_FILTERS,
  filtersToQuery,
  type HistoryFilters,
  historySearchFromFilters,
  parseHistorySearch,
} from "./history";

const APP = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

describe("parseHistorySearch (URL -> filters)", () => {
  it("returns the scans tab and no filters for an empty address", () => {
    expect(parseHistorySearch({})).toEqual({ tab: "scans", filters: EMPTY_FILTERS });
    expect(parseHistorySearch(undefined)).toEqual({ tab: "scans", filters: EMPTY_FILTERS });
  });

  it("reads single values and repeated keys", () => {
    const { tab, filters } = parseHistorySearch({
      tab: "findings",
      app: APP,
      tool: ["semgrep", "gitleaks"],
      severity: ["critical", "high"],
      state: "open",
      cwe: "79",
      from: "2026-10-01",
      to: "2026-10-07",
      type: "vendor",
      q: "sql injection",
    });
    expect(tab).toBe("findings");
    expect(filters.application).toBe(APP);
    expect(filters.tools).toEqual(["semgrep", "gitleaks"]);
    expect(filters.severities).toEqual(["critical", "high"]);
    expect(filters.statesNow).toEqual(["open"]);
    expect(filters.cwe).toBe("79");
    expect(filters.from).toBe("2026-10-01");
    expect(filters.to).toBe("2026-10-07");
    expect(filters.type).toBe("vendor");
    expect(filters.q).toBe("sql injection");
  });

  it("accepts a number and a CWE- prefix for the CWE", () => {
    expect(parseHistorySearch({ cwe: 89 }).filters.cwe).toBe("89");
    expect(parseHistorySearch({ cwe: "CWE-352" }).filters.cwe).toBe("352");
  });

  it("drops values that are not valid instead of passing them to the API", () => {
    const { tab, filters } = parseHistorySearch({
      tab: "bogus",
      app: "not-a-uuid",
      by: "nope",
      severity: ["critical", "catastrophic"],
      state: ["open", "weird"],
      scan_state: "exploded",
      verdict: "maybe",
      type: "other",
      kind: "mobile",
      source: "ftp",
      from: "yesterday",
      to: "2026-13",
      cwe: "seventy-nine",
    });
    expect(tab).toBe("scans");
    expect(filters).toEqual({ ...EMPTY_FILTERS, severities: ["critical"], statesNow: ["open"] });
  });

  it("ignores duplicates and blank list items", () => {
    expect(parseHistorySearch({ tool: ["semgrep", "semgrep", " "] }).filters.tools).toEqual(["semgrep"]);
  });
});

describe("historySearchFromFilters (filters -> URL)", () => {
  it("is empty for the default view, so the address stays clean", () => {
    expect(historySearchFromFilters("scans", EMPTY_FILTERS)).toEqual({});
  });

  it("writes only what is set, repeating list keys", () => {
    const filters: HistoryFilters = {
      ...EMPTY_FILTERS,
      application: APP,
      tools: ["semgrep", "gitleaks"],
      severities: ["critical"],
      from: "2026-10-01",
    };
    expect(historySearchFromFilters("findings", filters)).toEqual({
      tab: "findings",
      app: APP,
      tool: ["semgrep", "gitleaks"],
      severity: ["critical"],
      from: "2026-10-01",
    });
  });

  it("round-trips through the URL for both tabs", () => {
    const filters: HistoryFilters = {
      ...EMPTY_FILTERS,
      application: APP,
      vendor: APP,
      type: "internal",
      kind: "sast",
      source: "zip",
      tools: ["semgrep"],
      severities: ["high", "medium"],
      cwe: "79",
      cve: "CVE-2024-1",
      q: "xss",
      statesNow: ["open"],
      statesThen: ["open", "false_positive"],
      scanStates: ["failed"],
      verdicts: ["fail"],
      from: "2026-10-01",
      to: "2026-10-07",
      startedBy: APP,
    };
    for (const tab of ["scans", "findings"] as const) {
      const search = historySearchFromFilters(tab, filters);
      expect(parseHistorySearch(search)).toEqual({ tab, filters });
    }
  });

  it("counts the filters that are set", () => {
    expect(activeFilterCount(EMPTY_FILTERS)).toBe(0);
    expect(activeFilterCount({ ...EMPTY_FILTERS, tools: ["a", "b"], cwe: "79" })).toBe(2);
  });
});

describe("filtersToQuery (filters -> API parameters)", () => {
  it("maps the scans tab to the scan filters of GET /history/scans", () => {
    const query = filtersToQuery("scans", {
      ...EMPTY_FILTERS,
      application: APP,
      kind: "dast",
      scanStates: ["failed", "cancelled"],
      verdicts: ["fail"],
      tools: ["zap"],
      from: "2026-10-01",
      to: "2026-10-07",
      severities: ["critical"], // findings only: must not leak into the scans query
    });
    const params = new URLSearchParams(buildQueryString(query));
    expect(params.get("application_id")).toBe(APP);
    expect(params.get("kind")).toBe("dast");
    expect(params.getAll("state")).toEqual(["failed", "cancelled"]);
    expect(params.getAll("verdict")).toEqual(["fail"]);
    expect(params.getAll("tool")).toEqual(["zap"]);
    expect(params.get("date_from")).toBe("2026-10-01T00:00:00Z");
    expect(params.get("date_to")).toBe("2026-10-07T23:59:59Z");
    expect(params.has("severity")).toBe(false);
  });

  it("maps the findings tab to the finding filters of GET /history/findings", () => {
    const query = filtersToQuery("findings", {
      ...EMPTY_FILTERS,
      severities: ["critical", "high"],
      statesNow: ["open"],
      statesThen: ["open", "risk_accepted"],
      cwe: "79",
      cve: "CVE-2024-1",
      q: "injection",
      source: "image",
      type: "vendor",
      startedBy: APP,
      scanStates: ["failed"], // scans only
    });
    const params = new URLSearchParams(buildQueryString(query));
    expect(params.getAll("severity")).toEqual(["critical", "high"]);
    expect(params.getAll("state_now")).toEqual(["open"]);
    expect(params.getAll("state_then")).toEqual(["open", "risk_accepted"]);
    expect(params.get("cwe")).toBe("79");
    expect(params.get("cve")).toBe("CVE-2024-1");
    expect(params.get("q")).toBe("injection");
    expect(params.get("source")).toBe("image");
    expect(params.get("type")).toBe("vendor");
    expect(params.get("started_by")).toBe(APP);
    expect(params.has("state")).toBe(false);
  });

  it("sends nothing for empty filters", () => {
    expect(buildQueryString(filtersToQuery("scans", EMPTY_FILTERS))).toBe("");
    expect(buildQueryString(filtersToQuery("findings", EMPTY_FILTERS))).toBe("");
  });
});
