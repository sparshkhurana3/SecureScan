import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";

import type { UploadOptions, UploadResult } from "../lib/upload";
import { UploadWidget, type Uploader } from "./UploadWidget";

function Harness({ uploader, onValue }: { uploader: Uploader; onValue?: (value: UploadResult | null) => void }) {
  const [value, setValue] = useState<UploadResult | null>(null);
  return (
    <UploadWidget
      label="Zip file"
      accept=".zip"
      value={value}
      onChange={(next) => {
        setValue(next);
        onValue?.(next);
      }}
      uploader={uploader}
    />
  );
}

const zip = () => new File([new Uint8Array(10)], "payroll.zip", { type: "application/zip" });

function result(name: string): UploadResult {
  return { uploadId: "up-1", artifactId: "art-1", sha256: null, sizeBytes: 10, filename: name };
}

afterEach(() => localStorage.clear());

describe("UploadWidget", () => {
  it("shows progress, then the finished upload, and remembers the upload only while it runs", async () => {
    let finish: (value: UploadResult) => void = () => undefined;
    const uploader: Uploader = (_file, name, options?: UploadOptions) => {
      options?.onStart?.("up-1");
      options?.onProgress?.({ sentBytes: 5, totalBytes: 10, fraction: 0.5, retries: 0 });
      return new Promise<UploadResult>((resolve) => {
        finish = () => resolve(result(name));
      });
    };
    const onValue = vi.fn();
    const user = userEvent.setup();
    render(<Harness uploader={uploader} onValue={onValue} />);

    await user.upload(screen.getByLabelText("Zip file"), zip());
    const bar = await screen.findByRole("progressbar");
    expect(bar).toHaveAttribute("aria-valuenow", "50");
    expect(localStorage.length).toBe(1);

    finish(result("payroll.zip"));
    expect(await screen.findByTestId("upload-done")).toHaveTextContent("payroll.zip");
    expect(onValue).toHaveBeenLastCalledWith(expect.objectContaining({ artifactId: "art-1" }));
    expect(localStorage.length).toBe(0);
  });

  it("resumes the same upload when trying again", async () => {
    const seen: (string | null | undefined)[] = [];
    const uploader: Uploader = (_file, name, options) => {
      seen.push(options?.resumeUploadId);
      options?.onStart?.("up-7");
      return Promise.reject(new Error("The connection dropped"));
    };
    const user = userEvent.setup();
    render(<Harness uploader={uploader} />);
    await user.upload(screen.getByLabelText("Zip file"), zip());
    expect(await screen.findByRole("alert")).toHaveTextContent("The connection dropped");
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(seen).toHaveLength(2));
    expect(seen[0]).toBeNull();
    expect(seen[1]).toBe("up-7");
  });

  it("stops on request and can continue", async () => {
    const uploader: Uploader = (_file, _name, options) =>
      new Promise<UploadResult>((_resolve, reject) => {
        options?.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
      });
    const user = userEvent.setup();
    render(<Harness uploader={uploader} />);
    await user.upload(screen.getByLabelText("Zip file"), zip());
    await user.click(await screen.findByRole("button", { name: "Stop upload" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/Stopped/);
    expect(screen.getByRole("button", { name: "Continue upload" })).toBeInTheDocument();
  });

  it("removes a finished upload", async () => {
    const uploader: Uploader = (_file, name) => Promise.resolve(result(name));
    const onValue = vi.fn();
    const user = userEvent.setup();
    render(<Harness uploader={uploader} onValue={onValue} />);
    await user.upload(screen.getByLabelText("Zip file"), zip());
    await user.click(await screen.findByRole("button", { name: "Remove payroll.zip" }));
    expect(onValue).toHaveBeenLastCalledWith(null);
    expect(screen.queryByTestId("upload-done")).not.toBeInTheDocument();
  });
});
