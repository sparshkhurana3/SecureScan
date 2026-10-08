import { formatDuration, formatRelative, humanize, shortSha } from "./format";
import { cn, parseSearchString, safeNextPath, stringifySearchObject } from "./utils";

describe("cn", () => {
  it("joins classes and lets the later Tailwind class win", () => {
    expect(cn("px-2", false, "px-4", undefined)).toBe("px-4");
  });
});

describe("search string codec", () => {
  it("keeps values as strings and groups repeated keys", () => {
    expect(parseSearchString("?cwe=79&tool=a&tool=b")).toEqual({ cwe: "79", tool: ["a", "b"] });
    expect(parseSearchString("")).toEqual({});
  });

  it("writes a leading question mark, or nothing", () => {
    expect(stringifySearchObject({ tab: "findings", tool: ["a", "b"], empty: "", none: undefined })).toBe(
      "?tab=findings&tool=a&tool=b",
    );
    expect(stringifySearchObject({})).toBe("");
  });

  it("round-trips", () => {
    const search = { next: "/history?tab=findings", tool: ["a", "b"] };
    expect(parseSearchString(stringifySearchObject(search))).toEqual(search);
  });
});

describe("safeNextPath", () => {
  it("allows same-site paths only", () => {
    expect(safeNextPath("/history?tab=findings")).toBe("/history?tab=findings");
    expect(safeNextPath("https://evil.example")).toBe("/");
    expect(safeNextPath("//evil.example")).toBe("/");
    expect(safeNextPath("/\\evil.example")).toBe("/");
    expect(safeNextPath("/login")).toBe("/");
    expect(safeNextPath(42)).toBe("/");
  });
});

describe("format helpers", () => {
  it("humanizes state names", () => {
    expect(humanize("false_positive")).toBe("False positive");
    expect(humanize(null)).toBe("-");
  });

  it("shortens commit hashes", () => {
    expect(shortSha("0123456789abcdef")).toBe("01234567");
    expect(shortSha(null)).toBe("-");
  });

  it("formats durations", () => {
    expect(formatDuration(45)).toBe("45 s");
    expect(formatDuration(125)).toBe("2 min 05 s");
    expect(formatDuration(7500)).toBe("2 h 05 min");
    expect(formatDuration(null)).toBe("-");
  });

  it("formats relative times", () => {
    const now = new Date("2026-10-07T12:00:00Z");
    expect(formatRelative("2026-10-07T11:55:00Z", now)).toBe("5 minutes ago");
    expect(formatRelative("2026-10-07T14:00:00Z", now)).toBe("in 2 hours");
    expect(formatRelative("2026-10-07T11:59:50Z", now)).toBe("just now");
    expect(formatRelative(null, now)).toBe("-");
  });
});
