import { render, screen } from "@testing-library/react";

import { App } from "./App";

describe("App", () => {
  it("shows the wordmark and the product name", () => {
    render(<App />);
    expect(screen.getByAltText("SonaComstar")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "SecureScan" })).toBeInTheDocument();
  });
});
