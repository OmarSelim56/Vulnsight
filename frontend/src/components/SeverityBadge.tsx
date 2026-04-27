const MAP: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 ring-1 ring-red-500/40',
  high:     'bg-orange-500/20 text-orange-400 ring-1 ring-orange-500/40',
  medium:   'bg-amber-500/20 text-amber-400 ring-1 ring-amber-500/40',
  low:      'bg-yellow-500/20 text-yellow-400 ring-1 ring-yellow-500/40',
  info:     'bg-sky-500/20 text-sky-400 ring-1 ring-sky-500/40',
  warning:  'bg-purple-500/20 text-purple-400 ring-1 ring-purple-500/40',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = MAP[severity.toLowerCase()] ?? 'bg-slate-500/20 text-slate-400 ring-1 ring-slate-500/40';
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}
