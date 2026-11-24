/**
 * The Argust logo, shown as the brand kit's own artwork (public/brand/argust-logo-dark*.svg) — never redrawn,
 * so every screen shows exactly the approved logo. The wordmark is set in Inter SemiBold embedded in the file,
 * so it looks the same on every device, with or without Inter or SF Pro installed.
 *
 *  - "stacked":    the full logo with INTELLIGENT CYBER DEFENSE, larger — sign-in, setup.
 *  - "horizontal": the compact logo (mark and wordmark) — headers and the sidebar. With `tagline`, the full one.
 */
export default function LegionLogo({
  layout = "horizontal",
  size = 36,
  tagline = true,
  className = "",
}: {
  layout?: "horizontal" | "stacked";
  /** Height of the logo's mark in px; the rest of the artwork scales with it. */
  size?: number;
  tagline?: boolean;
  className?: string;
}) {
  const full = layout === "stacked" ? tagline : tagline && size >= 28;
  // The mark is about 80 % of the artwork's height in both files.
  const height = Math.round(size * (layout === "stacked" ? 1.15 : 1.05));
  const src = full ? "/brand/argust-logo-dark.svg" : "/brand/argust-logo-dark-compact.svg";
  const ratio = full ? 1200 / 320 : 1000 / 290;
  return (
    <span className={`inline-flex ${layout === "stacked" ? "justify-center" : ""} ${className}`}>
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={src}
        // i18n-ignore: brand name
        alt="Argust — Intelligent Cyber Defense"
        width={Math.round(height * ratio)}
        height={height}
        className="max-w-full h-auto select-none"
        draggable={false}
      />
    </span>
  );
}

/** The full logo file (mark, Argust, INTELLIGENT CYBER DEFENSE) at a given width, for places with room for it. */
export function LegionLockup({ width = 420, className = "" }: { width?: number; className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src="/brand/argust-logo-dark.svg"
      // i18n-ignore: brand name
      alt="Argust — Intelligent Cyber Defense"
      width={width}
      height={Math.round((width * 320) / 1200)}
      className={`max-w-full h-auto select-none ${className}`}
      draggable={false}
    />
  );
}
