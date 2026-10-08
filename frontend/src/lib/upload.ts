/**
 * Chunked, resumable file upload (protocol: `backend/securescan/domain/uploads.py`).
 *
 * 1. `create`   announces the file and returns the upload id and the chunk size.
 * 2. `chunk`    sends the bytes in order, each with `Content-Range: bytes start-end/total`.
 * 3. `complete` finishes the upload; the server checks the size and hashes the file.
 *
 * When a chunk fails for a reason that can pass (network error, 408, 409, 425, 429, 5xx) the upload asks
 * the server how many bytes it holds (`status`), continues from there and waits longer before every
 * further try. A person can also come back after closing the page: the upload id is remembered in
 * localStorage per file (`resumeKey`) and `uploadFile` continues the same upload.
 *
 * The functions here do not know about HTTP: `src/api/uploads.ts` supplies the transport, the tests a fake.
 */

export type UploadState = "receiving" | "complete" | "aborted";

export type UploadInfo = {
  id: string;
  filename: string;
  size_bytes: number;
  received_bytes: number;
  chunk_bytes: number;
  state: UploadState;
  sha256: string | null;
  artifact_id: string | null;
};

export type UploadCompleted = {
  upload_id: string;
  artifact_id: string;
  sha256: string;
  size_bytes: number;
};

export type ChunkRange = { start: number; end: number; total: number };

export type UploadTransport = {
  create(
    body: { filename: string; size_bytes: number; content_type?: string },
    signal?: AbortSignal,
  ): Promise<UploadInfo>;
  /** Resolves with the upload; throws (status 404) when the server no longer has it. */
  status(id: string, signal?: AbortSignal): Promise<UploadInfo>;
  chunk(id: string, range: ChunkRange, data: Blob, signal?: AbortSignal): Promise<UploadInfo>;
  complete(id: string, signal?: AbortSignal): Promise<UploadCompleted>;
};

export type UploadProgress = {
  sentBytes: number;
  totalBytes: number;
  /** 0 to 1 */
  fraction: number;
  /** Consecutive failed attempts so far (0 while everything goes well). */
  retries: number;
};

export type UploadResult = {
  uploadId: string;
  artifactId: string;
  sha256: string | null;
  sizeBytes: number;
  filename: string;
};

export type UploadOptions = {
  /** Upper bound for the chunk size; the server's `chunk_bytes` applies when smaller. */
  chunkBytes?: number;
  /** Consecutive failures tolerated before giving up (default 5). */
  maxRetries?: number;
  /** First wait before a retry, doubled each time (default 500 ms, at most `maxDelayMs`). */
  retryDelayMs?: number;
  maxDelayMs?: number;
  signal?: AbortSignal;
  onProgress?: (progress: UploadProgress) => void;
  /** Called once the upload id is known, so that the caller can remember it for resuming. */
  onStart?: (uploadId: string) => void;
  /** Continue this earlier upload when the server still has it. */
  resumeUploadId?: string | null;
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
};

export class UploadError extends Error {
  constructor(
    message: string,
    readonly cause_?: unknown,
  ) {
    super(message);
    this.name = "UploadError";
  }
}

export type UploadSource = Blob & { name?: string };

const DEFAULT_MAX_RETRIES = 5;
const DEFAULT_DELAY_MS = 500;
const DEFAULT_MAX_DELAY_MS = 15_000;

export function errorStatus(error: unknown): number | undefined {
  if (typeof error === "object" && error !== null && "status" in error) {
    const status = (error as { status: unknown }).status;
    if (typeof status === "number") return status;
  }
  return undefined;
}

export function isAbort(error: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return true;
  return typeof error === "object" && error !== null && (error as { name?: unknown }).name === "AbortError";
}

/** Failures that can pass: no HTTP status at all (network), timeouts, conflicts, throttling, server errors. */
export function isRetryable(error: unknown): boolean {
  if (isAbort(error)) return false;
  if (error instanceof UploadError) return false;
  const status = errorStatus(error);
  if (status === undefined) return true;
  return status === 408 || status === 409 || status === 425 || status === 429 || status >= 500;
}

export function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export function retryDelay(failures: number, base: number, max: number): number {
  return Math.min(max, base * 2 ** Math.max(0, failures - 1));
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException("Aborted", "AbortError");
}

function resultOf(info: UploadInfo, completed?: UploadCompleted): UploadResult {
  return {
    uploadId: info.id,
    artifactId: completed?.artifact_id ?? info.artifact_id ?? "",
    sha256: completed?.sha256 ?? info.sha256,
    sizeBytes: completed?.size_bytes ?? info.size_bytes,
    filename: info.filename,
  };
}

/** Uploads `file` and returns the artifact the server made from it. Throws `UploadError` when it gives up. */
export async function uploadFile(
  file: UploadSource,
  filename: string,
  transport: UploadTransport,
  options: UploadOptions = {},
): Promise<UploadResult> {
  const { signal } = options;
  const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  const baseDelay = options.retryDelayMs ?? DEFAULT_DELAY_MS;
  const maxDelay = options.maxDelayMs ?? DEFAULT_MAX_DELAY_MS;
  const sleep = options.sleep ?? defaultSleep;
  const total = file.size;
  if (total <= 0) throw new UploadError("The file is empty.");

  // Continue an earlier upload when the server still has it and it is for this very file.
  let info: UploadInfo | null = null;
  if (options.resumeUploadId) {
    try {
      const earlier = await transport.status(options.resumeUploadId, signal);
      if (earlier.state !== "aborted" && earlier.size_bytes === total) info = earlier;
    } catch (error) {
      if (isAbort(error, signal)) throw error;
      // gone, or not readable: start again
    }
  }
  if (info?.state === "complete" && info.artifact_id) {
    options.onProgress?.({ sentBytes: total, totalBytes: total, fraction: 1, retries: 0 });
    return resultOf(info);
  }
  throwIfAborted(signal);
  info ??= await createWithRetry(transport, filename, file, signal, maxRetries, baseDelay, maxDelay, sleep);
  options.onStart?.(info.id);

  const chunkSize = Math.max(1, Math.min(info.chunk_bytes, options.chunkBytes ?? info.chunk_bytes));
  let offset = Math.min(info.received_bytes, total);
  let failures = 0;
  const report = () =>
    options.onProgress?.({ sentBytes: offset, totalBytes: total, fraction: offset / total, retries: failures });
  report();

  while (offset < total) {
    throwIfAborted(signal);
    const end = Math.min(offset + chunkSize, total) - 1;
    try {
      const updated = await transport.chunk(
        info.id,
        { start: offset, end, total },
        file.slice(offset, end + 1, "application/octet-stream"),
        signal,
      );
      // Trust the server's count when it is sane, otherwise assume the chunk arrived.
      offset =
        updated.received_bytes > offset && updated.received_bytes <= total ? updated.received_bytes : end + 1;
      failures = 0;
      report();
    } catch (error) {
      if (isAbort(error, signal)) throw error;
      if (!isRetryable(error)) throw toUploadError(error);
      failures += 1;
      if (failures > maxRetries) {
        throw new UploadError("The upload keeps failing. Check the connection and try again.", error);
      }
      report();
      await sleep(retryDelay(failures, baseDelay, maxDelay), signal);
      // Ask the server where it is: the failed chunk may have been stored after all.
      try {
        const current = await transport.status(info.id, signal);
        if (current.state === "aborted") throw new UploadError("The upload was cancelled on the server.");
        offset = Math.min(current.received_bytes, total);
        report();
      } catch (statusError) {
        if (isAbort(statusError, signal)) throw statusError;
        if (statusError instanceof UploadError) throw statusError;
        if (errorStatus(statusError) === 404) {
          throw new UploadError("The server no longer has this upload. Start it again.", statusError);
        }
        // the status call failed too; the next chunk attempt (and its 409) resynchronises
      }
    }
  }

  // Finish. A failure here is retried the same way; the bytes are already on the server.
  let completeFailures = 0;
  for (;;) {
    throwIfAborted(signal);
    try {
      const completed = await transport.complete(info.id, signal);
      options.onProgress?.({ sentBytes: total, totalBytes: total, fraction: 1, retries: 0 });
      return resultOf(info, completed);
    } catch (error) {
      if (isAbort(error, signal)) throw error;
      if (!isRetryable(error)) throw toUploadError(error);
      completeFailures += 1;
      if (completeFailures > maxRetries) {
        throw new UploadError("The upload could not be finished. Try again.", error);
      }
      await sleep(retryDelay(completeFailures, baseDelay, maxDelay), signal);
    }
  }
}

async function createWithRetry(
  transport: UploadTransport,
  filename: string,
  file: UploadSource,
  signal: AbortSignal | undefined,
  maxRetries: number,
  baseDelay: number,
  maxDelay: number,
  sleep: (ms: number, signal?: AbortSignal) => Promise<void>,
): Promise<UploadInfo> {
  let failures = 0;
  for (;;) {
    throwIfAborted(signal);
    try {
      return await transport.create(
        { filename, size_bytes: file.size, ...(file.type ? { content_type: file.type } : {}) },
        signal,
      );
    } catch (error) {
      if (isAbort(error, signal)) throw error;
      if (!isRetryable(error)) throw toUploadError(error);
      failures += 1;
      if (failures > maxRetries) throw new UploadError("The upload could not be started.", error);
      await sleep(retryDelay(failures, baseDelay, maxDelay), signal);
    }
  }
}

/** A non-retryable failure keeps its own message (the server's reason), wrapped so the caller sees one type. */
function toUploadError(error: unknown): UploadError {
  if (error instanceof UploadError) return error;
  const message = error instanceof Error && error.message ? error.message : "The upload was refused.";
  return new UploadError(message, error);
}

// --------------------------------------------------------------------------- remembering an upload
const RESUME_PREFIX = "securescan.upload.";

/** The same file (name, size, modification time) gets the same key, so a second visit can resume. */
export function resumeKey(file: { name: string; size: number; lastModified?: number }): string {
  return `${RESUME_PREFIX}${file.name}:${String(file.size)}:${String(file.lastModified ?? 0)}`;
}

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function storage(): StorageLike | null {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

export function loadResumeId(key: string, store: StorageLike | null = storage()): string | null {
  try {
    return store?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

export function saveResumeId(key: string, uploadId: string, store: StorageLike | null = storage()): void {
  try {
    store?.setItem(key, uploadId);
  } catch {
    // private window or blocked storage: resuming after a reload is simply not offered
  }
}

export function clearResumeId(key: string, store: StorageLike | null = storage()): void {
  try {
    store?.removeItem(key);
  } catch {
    // ignore
  }
}
