/**
 * VulnSight brand logo — the "eye in frame" mark.
 *
 * Rendered as an inline SVG so it:
 *  • inherits `color` / Tailwind text-* classes for fill/stroke
 *  • scales perfectly at any size via width/height props
 *  • requires no external image load
 *
 * Usage:
 *   <VulnSightLogo className="h-8 w-8 text-cyan-400" />
 */
export function VulnSightLogo({ className = '' }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 100 100"
      xmlns="http://www.w3.org/2000/svg"
      fill="currentColor"
      className={className}
      aria-label="VulnSight logo"
    >
      {/* ── Corner bracket pieces ── */}

      {/* Top-left */}
      <rect x="0"  y="0"  width="27" height="7" />
      <rect x="0"  y="0"  width="7"  height="27" />

      {/* Top-right */}
      <rect x="73" y="0"  width="27" height="7" />
      <rect x="93" y="0"  width="7"  height="27" />

      {/* Bottom-left */}
      <rect x="0"  y="93" width="27" height="7" />
      <rect x="0"  y="73" width="7"  height="27" />

      {/* Bottom-right */}
      <rect x="73" y="93" width="27" height="7" />
      <rect x="93" y="73" width="7"  height="27" />

      {/* ── Eye outline (bold almond / lens shape) ── */}
      {/*
        Path traces:
          left corner (10,50)
          upper lid arc → right corner (90,50)
          lower lid arc → back to left corner
        The two quadratic curves give it the classic almond silhouette.
      */}
      <path
        d="M 10,50
           C 28,18 72,18 90,50
           C 72,82 28,82 10,50 Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* ── Iris circle ── */}
      <circle
        cx="50" cy="50" r="19"
        fill="none"
        stroke="currentColor"
        strokeWidth="5"
      />

      {/* ── Pupil: upper semi-circle of the iris filled solid ──
          Arc from left edge (31,50) counterclockwise over the top
          to right edge (69,50), then straight back — gives a
          "D rotated 90°" shape that matches the original mark.
      */}
      <path d="M 31,50 A 19,19 0 0,0 69,50 Z" />
    </svg>
  );
}
