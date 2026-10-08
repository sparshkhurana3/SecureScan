import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

export const fieldClasses =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring";

export function Input({ className, type = "text", ...props }: ComponentProps<"input">) {
  return <input type={type} className={cn(fieldClasses, "h-9", className)} {...props} />;
}
