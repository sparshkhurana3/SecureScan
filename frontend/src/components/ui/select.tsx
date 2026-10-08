import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";
import { fieldClasses } from "./input";

/**
 * A styled native `<select>`: labelled by `<Label htmlFor>`, fully keyboard and screen reader
 * accessible, and it works the same in every browser and in tests.
 */
export function Select({ className, children, ...props }: ComponentProps<"select">) {
  return (
    <select className={cn(fieldClasses, "h-9 pr-8", className)} {...props}>
      {children}
    </select>
  );
}
