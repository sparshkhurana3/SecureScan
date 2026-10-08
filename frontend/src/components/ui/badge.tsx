import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

/**
 * The tones are the only coloured elements of the portal. Severity and status badges always show
 * their meaning as text, so colour is never the only signal.
 */
export const badgeVariants = cva(
  "inline-flex items-center whitespace-nowrap rounded-full px-2.5 py-0.5 text-xs font-semibold",
  {
    variants: {
      tone: {
        outline: "border border-border bg-background text-foreground",
        neutral: "bg-status-neutral-bg text-status-neutral-fg",
        active: "bg-status-active-bg text-status-active-fg",
        ok: "bg-status-ok-bg text-status-ok-fg",
        warn: "bg-status-warn-bg text-status-warn-fg",
        bad: "bg-status-bad-bg text-status-bad-fg",
        critical: "bg-sev-critical-bg text-sev-critical-fg",
        high: "bg-sev-high-bg text-sev-high-fg",
        medium: "bg-sev-medium-bg text-sev-medium-fg",
        low: "bg-sev-low-bg text-sev-low-fg",
        info: "bg-sev-info-bg text-sev-info-fg",
      },
    },
    defaultVariants: { tone: "outline" },
  },
);

export type BadgeTone = NonNullable<VariantProps<typeof badgeVariants>["tone"]>;

export function Badge({
  className,
  tone,
  ...props
}: ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
