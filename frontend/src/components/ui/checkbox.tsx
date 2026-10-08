import * as CheckboxPrimitive from "@radix-ui/react-checkbox";
import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

export function Checkbox({ className, ...props }: ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      className={cn(
        "peer inline-flex size-5 shrink-0 items-center justify-center rounded border border-input bg-background focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:bg-accent data-[state=checked]:text-accent-foreground",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator>
        <svg viewBox="0 0 16 16" className="size-3.5" aria-hidden="true" fill="none">
          <path
            d="M3 8.5l3.2 3.2L13 4.8"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}
