import { EMPTY_FILTERS } from "../api/history";
import { findingsCsvUrl } from "./csv";

describe("findingsCsvUrl", () => {
  it("points at the findings export", () => {
    expect(findingsCsvUrl(EMPTY_FILTERS)).toBe("/api/v1/history/findings.csv");
  });

  it("carries the same filters as the findings list", () => {
    const url = findingsCsvUrl({
      ...EMPTY_FILTERS,
      severities: ["critical", "high"],
      tools: ["semgrep"],
      from: "2026-10-01",
      statesNow: ["open"],
    });
    const [path, query] = url.split("?");
    expect(path).toBe("/api/v1/history/findings.csv");
    const params = new URLSearchParams(query);
    expect(params.getAll("severity")).toEqual(["critical", "high"]);
    expect(params.getAll("tool")).toEqual(["semgrep"]);
    expect(params.getAll("state_now")).toEqual(["open"]);
    expect(params.get("date_from")).toBe("2026-10-01T00:00:00Z");
  });

  it("exports the whole filtered result: no paging parameters", () => {
    const params = new URLSearchParams(findingsCsvUrl({ ...EMPTY_FILTERS, cwe: "79" }).split("?")[1]);
    expect(params.has("after")).toBe(false);
    expect(params.has("limit")).toBe(false);
  });
});
