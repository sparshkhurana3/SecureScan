/**
 * The upload endpoints (`backend/securescan/api/uploads.py`) as an `UploadTransport` for `lib/upload.ts`.
 *
 * Every Analyst can upload; the file ends up as an artifact that a zip or image target, or a vendor
 * authorization document, points to.
 */
import { apiFetch } from "./client";
import {
  uploadFile,
  type ChunkRange,
  type UploadCompleted,
  type UploadInfo,
  type UploadOptions,
  type UploadResult,
  type UploadSource,
  type UploadTransport,
} from "../lib/upload";

export type { UploadCompleted, UploadInfo, UploadOptions, UploadResult } from "../lib/upload";

/**
 * `apiFetch` sends `init.body` as JSON, so a raw chunk goes through its `formData` slot: the value is
 * handed to `fetch` as is, and a Blob body is sent as raw bytes with the Blob's type as content type.
 * (If `apiFetch` gains a dedicated raw-body option, switch to it here; nothing else changes.)
 */
function asRawBody(chunk: Blob): FormData {
  return chunk as unknown as FormData;
}

export const uploadTransport: UploadTransport = {
  create(body, signal) {
    return apiFetch<UploadInfo>("/uploads", { method: "POST", body, signal });
  },
  status(id, signal) {
    return apiFetch<UploadInfo>(`/uploads/${id}`, { signal });
  },
  chunk(id: string, range: ChunkRange, data: Blob, signal?: AbortSignal) {
    return apiFetch<UploadInfo>(`/uploads/${id}`, {
      method: "PATCH",
      formData: asRawBody(data),
      headers: { "Content-Range": `bytes ${String(range.start)}-${String(range.end)}/${String(range.total)}` },
      signal,
    });
  },
  complete(id, signal) {
    return apiFetch<UploadCompleted>(`/uploads/${id}/complete`, { method: "POST", signal });
  },
};

export function abortUpload(id: string): Promise<void> {
  return apiFetch<void>(`/uploads/${id}`, { method: "DELETE" });
}

/** Uploads a file through the real API. */
export function upload(file: UploadSource, filename: string, options?: UploadOptions): Promise<UploadResult> {
  return uploadFile(file, filename, uploadTransport, options);
}
