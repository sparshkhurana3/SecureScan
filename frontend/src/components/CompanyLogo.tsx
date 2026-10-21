import { BRAND } from "../brand/brand";

/** The full SonaComstar logo (emblem over wordmark) in ink, for light surfaces. */
export function CompanyLogo({ width = 160 }: { width?: number }) {
  return (
    <img
      src={BRAND.logo.stackedOnLight}
      alt={BRAND.companyName}
      width={width}
      style={{ width, height: "auto" }}
    />
  );
}
