import { useEffect, useId, useRef, useState, type ReactNode } from "react";

import { upload as uploadToServer } from "../api/uploads";
import { formatBytes } from "../lib/format";
import {
  clearResumeId,
  loadResumeId,
  resumeKey,
  saveResumeId,
  type UploadOptions,
  type UploadProgress,
  type UploadResult,
  type UploadSource,
} from "../lib/upload";
import { fieldHelp } from "./FormBits";
import { Button } from "./ui/button";
import { Field } from "./ui/page";

type Phase = "idle" | "uploading" | "done" | "failed" | "stopped";

export type Uploader = (file: UploadSource, filename: string, options?: UploadOptions) => Promise<UploadResult>;

/**
 * Choose a file and send it in chunks. The upload starts at once, shows its progress, retries and resumes
 * by itself, and can be stopped; choosing the same file again continues where it stopped (even after the
 * page was closed). `value` is the finished upload, `onChange` reports it (or null when removed).
 */
export function UploadWidget({
  label,
  accept,
  help,
  error,
  value,
  onChange,
  disabled,
  uploader = uploadToServer,
  chunkBytes,
}: {
  label: string;
  /** File name extensions that the file chooser offers, for example ".zip". */
  accept?: string;
  help?: ReactNode;
  error?: string;
  value: UploadResult | null;
  onChange: (value: UploadResult | null) => void;
  disabled?: boolean;
  uploader?: Uploader;
  chunkBytes?: number;
}) {
  const id = useId();
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [phase, setPhase] = useState<Phase>(value ? "done" : "idle");
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => () => abortRef.current?.abort(), []);
  useEffect(() => {
    // The form was reset from outside: forget the finished upload.
    if (value === null && phase === "done") setPhase("idle");
  }, [value, phase]);

  const start = async (chosen: File) => {
    const key = resumeKey(chosen);
    const controller = new AbortController();
    abortRef.current = controller;
    setPhase("uploading");
    setMessage(null);
    setProgress({ sentBytes: 0, totalBytes: chosen.size, fraction: 0, retries: 0 });
    try {
      const result = await uploader(chosen, chosen.name, {
        chunkBytes,
        signal: controller.signal,
        resumeUploadId: loadResumeId(key),
        onStart: (uploadId) => saveResumeId(key, uploadId),
        onProgress: setProgress,
      });
      clearResumeId(key);
      setPhase("done");
      onChange(result);
    } catch (caught) {
      if (controller.signal.aborted) {
        setPhase("stopped");
        setMessage("Stopped. Choose the same file again to continue where it stopped.");
        return;
      }
      setPhase("failed");
      setMessage(caught instanceof Error && caught.message ? caught.message : "The upload failed.");
    }
  };

  const onPick = (picked: File | undefined) => {
    if (!picked) return;
    setFile(picked);
    onChange(null);
    void start(picked);
  };

  const remove = () => {
    abortRef.current?.abort();
    setFile(null);
    setPhase("idle");
    setProgress(null);
    setMessage(null);
    onChange(null);
    if (inputRef.current) inputRef.current.value = "";
  };

  const percent = Math.round((progress?.fraction ?? 0) * 100);
  const name = value?.filename ?? file?.name ?? "";

  return (
    <Field id={id} label={label} help={fieldHelp(error, help)}>
      <input
        ref={inputRef}
        id={id}
        type="file"
        accept={accept}
        disabled={disabled || phase === "uploading"}
        aria-invalid={error ? true : undefined}
        aria-describedby={error || help ? `${id}-help` : undefined}
        onChange={(event) => onPick(event.target.files?.[0])}
        className="block w-full text-sm file:mr-3 file:rounded-md file:border file:border-input file:bg-background file:px-3 file:py-1.5 file:text-sm file:font-medium hover:file:bg-muted"
      />
      {phase === "uploading" ? (
        <div className="flex flex-col gap-1.5" data-testid="upload-progress">
          <div
            role="progressbar"
            aria-label={`Upload progress of ${name}`}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={percent}
            className="h-2 w-full overflow-hidden rounded-full bg-muted"
          >
            <div className="h-full bg-accent transition-[width]" style={{ width: `${String(percent)}%` }} />
          </div>
          <p className="m-0 text-xs text-muted-foreground" aria-live="polite">
            Uploading {name}: {percent} % ({formatBytes(progress?.sentBytes)} of {formatBytes(progress?.totalBytes)})
            {progress && progress.retries > 0 ? `. Connection problem, trying again (${String(progress.retries)}).` : ""}
          </p>
          <div>
            <Button variant="outline" size="sm" onClick={() => abortRef.current?.abort()}>
              Stop upload
            </Button>
          </div>
        </div>
      ) : null}
      {phase === "done" && value ? (
        <div className="flex flex-wrap items-center gap-3 text-sm" data-testid="upload-done">
          <p className="m-0">
            Uploaded <span className="font-medium">{value.filename}</span> ({formatBytes(value.sizeBytes)})
          </p>
          <Button variant="outline" size="sm" onClick={remove} aria-label={`Remove ${value.filename}`}>
            Remove
          </Button>
        </div>
      ) : null}
      {(phase === "failed" || phase === "stopped") && file ? (
        <div className="flex flex-col gap-2 text-sm" role={phase === "failed" ? "alert" : "status"}>
          <p className="m-0 font-medium">{message}</p>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => void start(file)}>
              {phase === "failed" ? "Try again" : "Continue upload"}
            </Button>
            <Button variant="ghost" size="sm" onClick={remove}>
              Discard
            </Button>
          </div>
        </div>
      ) : null}
    </Field>
  );
}
