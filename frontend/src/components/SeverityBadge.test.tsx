import { render, screen } from "@testing-library/react";

import { SeverityBadge, SeverityCountBadges, severityTone } from "./SeverityBadge";
import { StatusBadge, statusLabel, statusTone } from "./StatusBadge";

describe("SeverityBadge", () => {
  it("always shows the severity as text, never colour alone", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("shows a count after the word", () => {
    render(<SeverityBadge severity="high" count={3} />);
    expect(screen.getByText("High")).toHaveTextContent("High3");
  });

  it("uses the colour token of its severity", () => {
    render(
      <>
        <SeverityBadge severity="critical" />
        <SeverityBadge severity="low" />
      </>,
    );
    expect(screen.getByText("Critical").className).toContain("bg-sev-critical-bg");
    expect(screen.getByText("Critical").className).toContain("text-sev-critical-fg");
    expect(screen.getByText("Low").className).toContain("bg-sev-low-bg");
  });

  it("maps every severity and treats an unknown one as informational", () => {
    expect(severityTone("CRITICAL")).toBe("critical");
    expect(severityTone("high")).toBe("high");
    expect(severityTone("medium")).toBe("medium");
    expect(severityTone("low")).toBe("low");
    expect(severityTone("info")).toBe("info");
    expect(severityTone("whatever")).toBe("info");
  });
});

describe("SeverityCountBadges", () => {
  it("lists only severities that have findings, most severe first", () => {
    render(<SeverityCountBadges counts={{ critical: 0, high: 2, medium: 0, low: 5, total: 7 }} />);
    expect(screen.getByText("High")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
    expect(screen.queryByText("Critical")).not.toBeInTheDocument();
  });

  it("says None when nothing is open", () => {
    render(<SeverityCountBadges counts={{ total: 0 }} />);
    expect(screen.getByText("None")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("shows the state in words with a tone", () => {
    render(<StatusBadge status="completed_partial" />);
    const badge = screen.getByText("Completed (partial)");
    expect(badge.className).toContain("bg-status-warn-bg");
  });

  it("maps scan states and verdicts", () => {
    expect(statusTone("running")).toBe("active");
    expect(statusTone("completed")).toBe("ok");
    expect(statusTone("failed")).toBe("bad");
    expect(statusTone("cancelled")).toBe("neutral");
    expect(statusTone("pass")).toBe("ok");
    expect(statusTone("conditional")).toBe("warn");
    expect(statusTone("fail")).toBe("bad");
    expect(statusTone("pending")).toBe("neutral");
    expect(statusTone("dead_letter")).toBe("bad");
    expect(statusLabel("timed_out")).toBe("Timed out");
    expect(statusLabel("some_new_state")).toBe("Some new state");
  });

  it("lets the caller replace the wording", () => {
    render(<StatusBadge status="active" label="In use" />);
    expect(screen.getByText("In use")).toBeInTheDocument();
  });
});
