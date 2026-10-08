import type { ComponentProps } from "react";

import { cn } from "../../lib/utils";

/** The wrapper scrolls sideways on narrow screens; give the table a caption or an aria-label. */
export function Table({ className, ...props }: ComponentProps<"table">) {
  return (
    <div className="w-full overflow-x-auto rounded-md border border-border">
      <table className={cn("w-full caption-bottom text-left text-sm", className)} {...props} />
    </div>
  );
}

export function TableHeader({ className, ...props }: ComponentProps<"thead">) {
  return <thead className={cn("bg-muted [&_tr]:border-b", className)} {...props} />;
}

export function TableBody({ className, ...props }: ComponentProps<"tbody">) {
  return <tbody className={cn("[&_tr:last-child]:border-0", className)} {...props} />;
}

export function TableRow({ className, ...props }: ComponentProps<"tr">) {
  return <tr className={cn("border-b border-border hover:bg-muted/50", className)} {...props} />;
}

export function TableHead({ className, ...props }: ComponentProps<"th">) {
  return (
    <th
      scope="col"
      className={cn("h-10 px-3 text-left align-middle text-xs font-semibold uppercase tracking-wide", className)}
      {...props}
    />
  );
}

export function TableCell({ className, ...props }: ComponentProps<"td">) {
  return <td className={cn("px-3 py-2 align-top", className)} {...props} />;
}

export function TableCaption({ className, ...props }: ComponentProps<"caption">) {
  return <caption className={cn("p-2 text-sm text-muted-foreground", className)} {...props} />;
}
