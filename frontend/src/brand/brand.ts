// Every SonaComstar name and asset path the portal shows, in one place.
// The files live in frontend/public/brand/, so they are served from /brand/.

export const BRAND = {
  companyName: "SonaComstar",
  productName: "SecureScan",

  logo: {
    /** Stacked logo (emblem over wordmark) in ink, for light surfaces. */
    stackedOnLight: "/brand/logo/sona-comstar-logo-ink.svg",
    /** Emblem alone in white, for the ink brand tile. */
    emblemOnInk: "/brand/logo/sona-comstar-emblem-white.svg",
  },
} as const;
