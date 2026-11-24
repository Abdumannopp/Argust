/**
 * "Argust" as set in the brand kit (public/brand/argust-logo*.svg): a clean semibold sans-serif with tight
 * tracking (Inter / SF Pro, the system font otherwise). Colour is currentColor.
 */
export default function LegionWordmark({
  height = 16,
  className,
  decorative = false,
}: {
  /** Cap height in px, roughly. */
  height?: number;
  className?: string;
  /** True when the text "Argust" is already provided nearby for screen readers. */
  decorative?: boolean;
}) {
  // The kit's wordmark: 142 px type with -6 px tracking. The box reaches below the baseline so the tail of
  // the "g" is not cut off (without it the word reads "Arqust").
  const h = (height * 1.3 * 146) / 112;
  return (
    <svg
      viewBox="0 0 440 146"
      height={h}
      width={(h * 440) / 146}
      className={className}
      role={decorative ? undefined : "img"}
      aria-label={decorative ? undefined : "Argust"}
      aria-hidden={decorative || undefined}
      xmlns="http://www.w3.org/2000/svg"
    >
      <text x="0" y="104" fill="currentColor" fontFamily="Inter, 'SF Pro Display', -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif" fontSize="142" fontWeight="620" letterSpacing="-6" textLength="432" lengthAdjust="spacingAndGlyphs">
        {/* i18n-ignore: brand name */}
        Argust
      </text>
    </svg>
  );
}
