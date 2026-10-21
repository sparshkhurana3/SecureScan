import { BRAND } from "../brand/brand";
import { cn } from "../lib/utils";

/** The ink brand tile with the SonaComstar emblem. Decorative: the product name sits beside it. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn("grid size-9 shrink-0 place-items-center rounded-md bg-accent", className)}
    >
      <img src={BRAND.logo.emblemOnInk} alt="" className="block size-[74%] object-contain" />
    </span>
  );
}
