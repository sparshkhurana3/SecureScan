import type { ComponentProps, ReactNode } from "react";

import { ApiError, errorMessage } from "../../api/client";
import { cn } from "../../lib/utils";
import { Button } from "./button";
import { Label } from "./label";

/** Page title row: a level-1 heading, an optional lead sentence and actions on the right. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description ? <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** A failed request, in words, with an optional retry. */
export function ErrorNotice({
  error,
  title = "Something went wrong",
  onRetry,
  className,
}: {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  className?: string;
}) {
  const fieldErrors = error instanceof ApiError ? (error.problem.errors ?? []) : [];
  return (
    <div
      role="alert"
      className={cn("rounded-md border border-foreground bg-background p-4 text-sm", className)}
    >
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-muted-foreground">{errorMessage(error)}</p>
      {fieldErrors.length > 0 ? (
        <ul className="mt-2 list-disc pl-5">
          {fieldErrors.map((item, index) => (
            <li key={index}>
              {item.field ? <strong>{item.field}: </strong> : null}
              {item.message}
            </li>
          ))}
        </ul>
      ) : null}
      {onRetry ? (
        <Button variant="outline" size="sm" className="mt-3" onClick={onRetry}>
          Try again
        </Button>
      ) : null}
    </div>
  );
}

export function LoadingText({ children = "Loading..." }: { children?: ReactNode }) {
  return (
    <p role="status" className="py-6 text-sm text-muted-foreground">
      {children}
    </p>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <p className="rounded-md border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
      {children}
    </p>
  );
}

/** A form row: a label above its control, with optional help text. The control needs `id`. */
export function Field({
  id,
  label,
  help,
  children,
  className,
}: {
  id: string;
  label: string;
  help?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <Label htmlFor={id}>{label}</Label>
      {children}
      {help ? (
        <p id={id + "-help"} className="text-xs text-muted-foreground">
          {help}
        </p>
      ) : null}
    </div>
  );
}

/** "Load more" for cursor-paged lists. */
export function LoadMore({
  hasMore,
  loading,
  onClick,
}: {
  hasMore: boolean;
  loading: boolean;
  onClick: () => void;
}) {
  if (!hasMore) return null;
  return (
    <div className="mt-3 flex justify-center">
      <Button variant="outline" onClick={onClick} disabled={loading}>
        {loading ? "Loading..." : "Load more"}
      </Button>
    </div>
  );
}

/** A native link styled as text with an underline. */
export function TextLink({ className, ...props }: ComponentProps<"a">) {
  return <a className={cn("underline underline-offset-2 hover:no-underline", className)} {...props} />;
}
