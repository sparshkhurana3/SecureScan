import { type QueryParams, useCursorList } from "./client";

/** `AuditEventOut` of `GET /api/v1/audit-events` (Admin). */
export type AuditEvent = {
  id: string;
  created_at: string;
  actor_id: string | null;
  actor_label: string;
  action: string;
  object_type: string | null;
  object_id: string | null;
  source_ip: string | null;
  request_id: string | null;
  detail: Record<string, unknown>;
};

export type AuditFilters = {
  actor: string;
  action_prefix: string;
  object_type: string;
  object_id: string;
  /** `YYYY-MM-DD` */
  from: string;
  /** `YYYY-MM-DD` */
  to: string;
};

export const EMPTY_AUDIT_FILTERS: AuditFilters = {
  actor: "",
  action_prefix: "",
  object_type: "",
  object_id: "",
  from: "",
  to: "",
};

export function auditQuery(f: AuditFilters): QueryParams {
  return {
    actor: f.actor.trim() || undefined,
    action_prefix: f.action_prefix.trim() || undefined,
    object_type: f.object_type.trim() || undefined,
    object_id: f.object_id.trim() || undefined,
    created_after: f.from ? f.from + "T00:00:00Z" : undefined,
    created_before: f.to ? f.to + "T23:59:59Z" : undefined,
  };
}

export function useAuditEvents(filters: AuditFilters) {
  return useCursorList<AuditEvent>(["audit-events"], "/audit-events", auditQuery(filters), {
    limit: 50,
  });
}
