import LegionMark from "./LegionMark";
import LegionWordmark from "./LegionWordmark";

/**
 * The two lock-ups from the brand sheet.
 *
 *  - "stacked":    mark above, Argust, INTELLIGENT CYBER DEFENSE — sign-in, setup.
 *  - "horizontal": mark beside Argust over the tagline — headers.
 */
export default function LegionLogo({
  layout = "horizontal",
  size = 36,
  tagline = true,
  className = "",
}: {
  layout?: "horizontal" | "stacked";
  /** Height of the mark in px; everything else scales from it. */
  size?: number;
  tagline?: boolean;
  className?: string;
}) {
  const markWidth = size;

  if (layout === "stacked") {
    return (
      <div className={`flex flex-col items-center ${className}`}>
        <LegionMark
          size={markWidth}
          title=""
          className="drop-shadow-[0_0_28px_rgba(57,120,246,0.35)]"
        />
        <LegionWordmark decorative height={size * 0.3} className="text-ink mt-[0.45em]" />
        {tagline && (
          <span
            aria-hidden
            className="text-ink-muted uppercase whitespace-nowrap font-semibold"
            style={{ fontSize: size * 0.1, letterSpacing: "0.3em", marginTop: size * 0.12, marginRight: "-0.3em" }}
          >
            {/* i18n-ignore: logo lockup, a brand mark */}
            Intelligent Cyber Defense
          </span>
        )}
        <span
          aria-hidden
          className="block h-px bg-gradient-to-r from-transparent via-[#3978F6] to-transparent opacity-70"
          style={{ width: size * 1.2, marginTop: size * 0.14 }}
        />
        {/* i18n-ignore: brand name */}
      <span className="sr-only">Argust — Intelligent Cyber Defense</span>
      </div>
    );
  }

  return (
    <div className={`flex items-center ${className}`} style={{ gap: size * 0.3 }}>
      <LegionMark size={markWidth} title="" className="shrink-0 drop-shadow-[0_0_10px_rgba(57,120,246,0.30)]" />
      <span className="flex flex-col justify-center">
        <LegionWordmark decorative height={size * 0.34} className="text-ink" />
        {tagline && (
          <span
            aria-hidden
            className="text-ink-muted uppercase whitespace-nowrap font-semibold"
            style={{ fontSize: Math.max(7, size * 0.17), letterSpacing: "0.3em", marginTop: size * 0.12 }}
          >
            {/* i18n-ignore: logo lockup, a brand mark */}
            Intelligent Cyber Defense
          </span>
        )}
      </span>
      {/* i18n-ignore: brand name */}
      <span className="sr-only">Argust — Intelligent Cyber Defense</span>
    </div>
  );
}

/**
 * The official logo file itself (mark, Argust, INTELLIGENT CYBER DEFENSE — the kit's dark-background version),
 * for places with room for it. It keeps its proportions (1200 × 320) and a transparent background.
 */
export function LegionLockup({ width = 420, className = "" }: { width?: number; className?: string }) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img
      src="/brand/argust-logo-dark.svg"
      // i18n-ignore: brand name
      alt="Argust — Intelligent Cyber Defense"
      width={width}
      height={Math.round((width * 320) / 1200)}
      className={`max-w-full h-auto ${className}`}
      draggable={false}
    />
  );
}
