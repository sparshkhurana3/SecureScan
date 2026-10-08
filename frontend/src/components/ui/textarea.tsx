import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";
import { fieldClasses } from "./input";

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return <textarea className={cn(fieldClasses, "min-h-24", className)} {...props} />;
}
