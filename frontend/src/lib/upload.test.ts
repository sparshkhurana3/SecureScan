import {
  clearResumeId,
  isRetryable,
  loadResumeId,
  resumeKey,
  retryDelay,
  saveResumeId,
  UploadError,
  uploadFile,
  type ChunkRange,
  type UploadCompleted,
  type UploadInfo,
  type UploadProgress,
  type UploadTransport,
} from "./upload";

function httpError(status: number, message = `HTTP ${String(status)}`): Error {
  return Object.assign(new Error(message), { status });
}

type FakeOptions = {
  chunkBytes?: number;
  /** Chunk calls (1-based) that fail; the value says how and whether the server kept the bytes. */
  failChunk?: Record<number, { error: Error; stored: boolean }>;
  /** The upload that status() finds, for resuming. */
  existing?: UploadInfo | "gone";
  failComplete?: number;
};

/** A server that keeps the received bytes, like the real one, and records what the client does. */
function fakeServer(size: number, options: FakeOptions = {}) {
  const chunkBytes = options.chunkBytes ?? 4;
  let received = options.existing && options.existing !== "gone" ? options.existing.received_bytes : 0;
  let chunkCalls = 0;
  let completeCalls = 0;
  const ranges: ChunkRange[] = [];
  const bodies: number[] = [];
  const calls = { create: 0, status: 0 };
  const info = (): UploadInfo => ({
    id: "up-1",
    filename: "app.zip",
    size_bytes: size,
    received_bytes: received,
    chunk_bytes: chunkBytes,
    state: "receiving",
    sha256: null,
    artifact_id: null,
  });
  const transport: UploadTransport = {
    create: () => {
      calls.create += 1;
      return Promise.resolve(info());
    },
    status: (id) => {
      calls.status += 1;
      if (options.existing === "gone" && id === "old") return Promise.reject(httpError(404));
      if (options.existing && options.existing !== "gone" && id === options.existing.id) {
        return Promise.resolve({ ...options.existing, received_bytes: received });
      }
      return Promise.resolve(info());
    },
    chunk: async (_id, range, data) => {
      chunkCalls += 1;
      const failure = options.failChunk?.[chunkCalls];
      if (failure) {
        if (failure.stored) received = range.end + 1;
        throw failure.error;
      }
      if (range.start !== received) throw httpError(409, "wrong offset");
      expect(data.size).toBe(range.end - range.start + 1);
      ranges.push(range);
      bodies.push(data.size);
      received = range.end + 1;
      return info();
    },
    complete: () => {
      completeCalls += 1;
      if (options.failComplete && completeCalls <= options.failComplete) return Promise.reject(httpError(503));
      const done: UploadCompleted = { upload_id: "up-1", artifact_id: "art-1", sha256: "ab".repeat(32), size_bytes: size };
      return Promise.resolve(done);
    },
  };
  return { transport, ranges, bodies, calls, received: () => received, completeCalls: () => completeCalls };
}

const sleeps: number[] = [];
const noSleep = (ms: number): Promise<void> => {
  sleeps.push(ms);
  return Promise.resolve();
};

function file(size: number): Blob {
  return new Blob([new Uint8Array(size).fill(7)], { type: "application/zip" });
}

beforeEach(() => {
  sleeps.length = 0;
});

describe("uploadFile", () => {
  it("sends the file in ordered chunks with exact ranges and reports progress", async () => {
    const server = fakeServer(10, { chunkBytes: 4 });
    const progress: UploadProgress[] = [];
    const result = await uploadFile(file(10), "app.zip", server.transport, {
      onProgress: (p) => progress.push(p),
      sleep: noSleep,
    });
    expect(server.ranges).toEqual([
      { start: 0, end: 3, total: 10 },
      { start: 4, end: 7, total: 10 },
      { start: 8, end: 9, total: 10 },
    ]);
    expect(result).toMatchObject({ artifactId: "art-1", uploadId: "up-1", sizeBytes: 10, filename: "app.zip" });
    expect(progress.map((p) => p.sentBytes)).toEqual([0, 4, 8, 10, 10]);
    expect(progress.at(-1)?.fraction).toBe(1);
    expect(server.calls.create).toBe(1);
  });

  it("uses the smaller of the server's chunk size and the requested one", async () => {
    const server = fakeServer(10, { chunkBytes: 8 });
    await uploadFile(file(10), "app.zip", server.transport, { chunkBytes: 5, sleep: noSleep });
    expect(server.bodies).toEqual([5, 5]);
  });

  it("retries a failed chunk after asking the server where it is", async () => {
    const server = fakeServer(10, { failChunk: { 2: { error: httpError(503), stored: false } } });
    await uploadFile(file(10), "app.zip", server.transport, { sleep: noSleep });
    expect(server.received()).toBe(10);
    expect(server.calls.status).toBe(1);
    expect(sleeps).toHaveLength(1);
  });

  it("does not send a chunk twice when the server stored it but the answer was lost", async () => {
    const server = fakeServer(10, { failChunk: { 1: { error: new TypeError("network"), stored: true } } });
    await uploadFile(file(10), "app.zip", server.transport, { sleep: noSleep });
    // the first chunk (0-3) reached the server; the client resumed at 4
    expect(server.ranges[0]).toEqual({ start: 4, end: 7, total: 10 });
    expect(server.ranges).toHaveLength(2);
  });

  it("resynchronises after a 409 from the server", async () => {
    const server = fakeServer(8, { failChunk: { 2: { error: httpError(409), stored: false } } });
    await uploadFile(file(8), "app.zip", server.transport, { sleep: noSleep });
    expect(server.received()).toBe(8);
  });

  it("waits longer before every retry and gives up after maxRetries consecutive failures", async () => {
    const failures: Record<number, { error: Error; stored: boolean }> = {};
    for (let call = 1; call <= 10; call += 1) failures[call] = { error: httpError(500), stored: false };
    const server = fakeServer(8, { failChunk: failures });
    const waits: number[] = [];
    const sleep = (ms: number): Promise<void> => {
      waits.push(ms);
      return Promise.resolve();
    };
    await expect(
      uploadFile(file(8), "app.zip", server.transport, { maxRetries: 3, retryDelayMs: 100, sleep }),
    ).rejects.toBeInstanceOf(UploadError);
    expect(waits).toEqual([100, 200, 400]);
  });

  it("starts counting again after a chunk goes through", async () => {
    const server = fakeServer(16, {
      failChunk: {
        1: { error: httpError(500), stored: false },
        3: { error: httpError(500), stored: false },
        5: { error: httpError(500), stored: false },
      },
    });
    await uploadFile(file(16), "app.zip", server.transport, { maxRetries: 1, sleep: noSleep });
    expect(server.received()).toBe(16);
  });

  it("does not retry a refusal such as 413", async () => {
    const server = fakeServer(8, { failChunk: { 1: { error: httpError(413, "Too large"), stored: false } } });
    await expect(uploadFile(file(8), "app.zip", server.transport, { sleep: noSleep })).rejects.toThrow("Too large");
    expect(sleeps).toEqual([]);
  });

  it("retries completing the upload", async () => {
    const server = fakeServer(4, { failComplete: 2 });
    const result = await uploadFile(file(4), "app.zip", server.transport, { sleep: noSleep });
    expect(result.artifactId).toBe("art-1");
    expect(server.completeCalls()).toBe(3);
  });

  it("continues an earlier upload from the bytes the server holds", async () => {
    const existing: UploadInfo = {
      id: "old",
      filename: "app.zip",
      size_bytes: 10,
      received_bytes: 8,
      chunk_bytes: 4,
      state: "receiving",
      sha256: null,
      artifact_id: null,
    };
    const server = fakeServer(10, { existing });
    const started: string[] = [];
    await uploadFile(file(10), "app.zip", server.transport, {
      resumeUploadId: "old",
      onStart: (id) => started.push(id),
      sleep: noSleep,
    });
    expect(server.calls.create).toBe(0);
    expect(server.ranges).toEqual([{ start: 8, end: 9, total: 10 }]);
    expect(started).toEqual(["old"]);
  });

  it("starts a new upload when the earlier one is gone or belongs to a different file", async () => {
    const gone = fakeServer(10, { existing: "gone" });
    await uploadFile(file(10), "app.zip", gone.transport, { resumeUploadId: "old", sleep: noSleep });
    expect(gone.calls.create).toBe(1);

    const other: UploadInfo = {
      id: "old",
      filename: "other.zip",
      size_bytes: 99,
      received_bytes: 50,
      chunk_bytes: 4,
      state: "receiving",
      sha256: null,
      artifact_id: null,
    };
    const different = fakeServer(10, { existing: other });
    await uploadFile(file(10), "app.zip", different.transport, { resumeUploadId: "old", sleep: noSleep });
    expect(different.calls.create).toBe(1);
  });

  it("returns an upload the server already finished", async () => {
    const done: UploadInfo = {
      id: "old",
      filename: "app.zip",
      size_bytes: 10,
      received_bytes: 10,
      chunk_bytes: 4,
      state: "complete",
      sha256: "cd".repeat(32),
      artifact_id: "art-9",
    };
    const server = fakeServer(10, { existing: done });
    const result = await uploadFile(file(10), "app.zip", server.transport, { resumeUploadId: "old", sleep: noSleep });
    expect(result.artifactId).toBe("art-9");
    expect(server.ranges).toHaveLength(0);
    expect(server.completeCalls()).toBe(0);
  });

  it("stops when aborted", async () => {
    const server = fakeServer(12);
    const controller = new AbortController();
    const chunk = server.transport.chunk.bind(server.transport);
    server.transport.chunk = async (id, range, data, signal) => {
      const result = await chunk(id, range, data, signal);
      controller.abort();
      return result;
    };
    await expect(
      uploadFile(file(12), "app.zip", server.transport, { signal: controller.signal, sleep: noSleep }),
    ).rejects.toThrow("Aborted");
    expect(server.ranges).toHaveLength(1);
  });

  it("refuses an empty file", async () => {
    const server = fakeServer(1);
    await expect(uploadFile(new Blob([]), "empty.zip", server.transport)).rejects.toBeInstanceOf(UploadError);
    expect(server.calls.create).toBe(0);
  });
});

describe("retry rules", () => {
  it("retries network errors, timeouts, conflicts, throttling and server errors", () => {
    for (const status of [408, 409, 425, 429, 500, 502, 503]) expect(isRetryable(httpError(status))).toBe(true);
    expect(isRetryable(new TypeError("Failed to fetch"))).toBe(true);
  });

  it("does not retry refusals", () => {
    for (const status of [400, 401, 403, 404, 413, 415, 422]) expect(isRetryable(httpError(status))).toBe(false);
    expect(isRetryable(new UploadError("no"))).toBe(false);
    expect(isRetryable(Object.assign(new Error("aborted"), { name: "AbortError" }))).toBe(false);
  });

  it("doubles the wait up to a limit", () => {
    expect([1, 2, 3, 4, 5].map((n) => retryDelay(n, 500, 3000))).toEqual([500, 1000, 2000, 3000, 3000]);
  });
});

describe("remembering an upload", () => {
  function memory() {
    const data = new Map<string, string>();
    return {
      getItem: (key: string) => data.get(key) ?? null,
      setItem: (key: string, value: string) => void data.set(key, value),
      removeItem: (key: string) => void data.delete(key),
    };
  }

  it("keys by name, size and modification time", () => {
    const a = resumeKey({ name: "a.zip", size: 10, lastModified: 5 });
    expect(a).toBe(resumeKey({ name: "a.zip", size: 10, lastModified: 5 }));
    expect(a).not.toBe(resumeKey({ name: "a.zip", size: 11, lastModified: 5 }));
    expect(a).not.toBe(resumeKey({ name: "a.zip", size: 10, lastModified: 6 }));
  });

  it("stores and clears the upload id", () => {
    const store = memory();
    const key = resumeKey({ name: "a.zip", size: 10 });
    expect(loadResumeId(key, store)).toBeNull();
    saveResumeId(key, "up-1", store);
    expect(loadResumeId(key, store)).toBe("up-1");
    clearResumeId(key, store);
    expect(loadResumeId(key, store)).toBeNull();
  });

  it("works without usable storage", () => {
    const broken = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
      removeItem: () => {
        throw new Error("blocked");
      },
    };
    expect(loadResumeId("k", broken)).toBeNull();
    expect(() => saveResumeId("k", "x", broken)).not.toThrow();
    expect(() => clearResumeId("k", broken)).not.toThrow();
  });
});
