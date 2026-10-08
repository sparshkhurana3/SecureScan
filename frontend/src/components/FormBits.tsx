import { useRouter } from "@tanstack/react-router";
import type { ComponentProps, MouseEvent, ReactNode } from "react";

import { ApiError } from "../api/client";
import { cn } from "../lib/utils";
import { Checkbox } from "./ui/checkbox";
import { Label } from "./ui/label";

/**
 * Help text of a field that turns into the error message when there is one. The message is announced
 * (`role="alert"`) and stays plain text: colour is not used for errors, the words are the signal.
 */
export function fieldHelp(error: string | undefined, help?: ReactNode): ReactNode {
  if (error) {
    return (
      <span role="alert" className="font-semibold text-foreground">
        {error}
      </span>
    );
  }
  return help;
}

/** `aria-*` props that tie a control to the help or error text of `Field` (which renders `<id>-help`). */
export function describedBy(id: string, error: string | undefined, hasHelp: boolean) {
  return {
    "aria-invalid": error ? true : undefined,
    "aria-describedby": error || hasHelp ? `${id}-help` : undefined,
  } as const;
}

/** A checkbox with its label to the right. */
export function CheckField({
  id,
  label,
  checked,
  onCheckedChange,
  disabled,
  help,
  className,
}: {
  id: string;
  label: ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  help?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start gap-2", className)}>
      <Checkbox
        id={id}
        checked={checked}
        disabled={disabled}
        onCheckedChange={(value) => onCheckedChange(value === true)}
        aria-describedby={help ? `${id}-help` : undefined}
        className="mt-0.5"
      />
      <div className="flex flex-col gap-0.5">
        <Label htmlFor={id} className="leading-snug">
          {label}
        </Label>
        {help ? (
          <p id={`${id}-help`} className="text-xs text-muted-foreground">
            {help}
          </p>
        ) : null}
      </div>
    </div>
  );
}

/**
 * A native radio with its label. Radios are native on purpose: a group is one `fieldset` with a legend,
 * arrow keys work without any script, and tests and screen readers see the same thing.
 */
export function RadioField({
  name,
  value,
  checked,
  onSelect,
  label,
  help,
  disabled,
}: {
  name: string;
  value: string;
  checked: boolean;
  onSelect: (value: string) => void;
  label: ReactNode;
  help?: ReactNode;
  disabled?: boolean;
}) {
  const id = `${name}-${value}`;
  return (
    <div className="flex items-start gap-2">
      <input
        type="radio"
        id={id}
        name={name}
        value={value}
        checked={checked}
        disabled={disabled}
        onChange={() => onSelect(value)}
        aria-describedby={help ? `${id}-help` : undefined}
        className="mt-1 size-4 accent-black"
      />
      <div className="flex flex-col gap-0.5">
        <Label htmlFor={id} className="leading-snug">
          {label}
        </Label>
        {help ? (
          <p id={`${id}-help`} className="text-xs text-muted-foreground">
            {help}
          </p>
        ) : null}
      </div>
    </div>
  );
}

/**
 * A request that failed, with the server's own words. The problem's `detail` is shown verbatim (for
 * example the production rule of the DAST modes), followed by field errors when it has any.
 */
export function ProblemNotice({
  error,
  title = "The request was refused",
  className,
}: {
  error: unknown;
  title?: string;
  className?: string;
}) {
  if (error === null || error === undefined) return null;
  let detail: string;
  let fields: { field: string; message: string }[] = [];
  let heading = title;
  if (error instanceof ApiError) {
    detail = error.problem.detail ?? error.problem.title;
    fields = error.problem.errors ?? [];
    if (error.status >= 500) heading = "The server could not do that";
  } else if (error instanceof Error) {
    detail = error.message;
  } else {
    detail = "Something went wrong.";
  }
  return (
    <div role="alert" className={cn("rounded-md border border-foreground p-4 text-sm", className)}>
      <p className="font-semibold">{heading}</p>
      <p className="mt-1" data-testid="problem-detail">
        {detail}
      </p>
      {fields.length > 0 ? (
        <ul className="mt-2 list-disc pl-5">
          {fields.map((item, index) => (
            <li key={`${item.field}-${String(index)}`}>
              {item.field ? <span className="font-medium">{item.field}: </span> : null}
              {item.message}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

/**
 * A link to a page of the portal. It navigates inside the app when it can (the router is in context and
 * the click is a plain left click) and is an ordinary link otherwise (new tab, copy address, no router).
 */
export function AppLink({ href, onClick, children, ...props }: ComponentProps<"a"> & { href: string }) {
  const router = useRouter({ warn: false }) as ReturnType<typeof useRouter> | undefined;
  const handle = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented || !router) return;
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    if (props.target && props.target !== "_self") return;
    event.preventDefault();
    router.history.push(href);
  };
  return (
    <a href={href} onClick={handle} {...props}>
      {children}
    </a>
  );
}

/** A group of related controls (radios, checkboxes) with a visible legend. */
export function FieldGroup({
  legend,
  children,
  className,
}: {
  legend: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <fieldset className={cn("flex flex-col gap-2 border-0 p-0", className)}>
      <legend className="mb-1 p-0 text-sm font-medium">{legend}</legend>
      {children}
    </fieldset>
  );
}

/** Navigate to a page of the portal from code (after a scan started). Works without a router in tests. */
export function useGoto(): (path: string) => void {
  const router = useRouter({ warn: false }) as ReturnType<typeof useRouter> | undefined;
  return (path: string) => {
    if (router) router.history.push(path);
    else window.location.assign(path);
  };
}
