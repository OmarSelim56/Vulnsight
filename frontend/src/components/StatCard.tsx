import type { LucideIcon } from 'lucide-react';

interface Props {
  label: string;
  value: string | number;
  sub?: string;
  icon: LucideIcon;
  accent?: 'cyan' | 'red' | 'amber' | 'emerald' | 'slate';
}

const ACCENT: Record<string, string> = {
  cyan:    'text-cyan-400 bg-cyan-400/10 ring-1 ring-cyan-400/20',
  red:     'text-red-400 bg-red-400/10 ring-1 ring-red-400/20',
  amber:   'text-amber-400 bg-amber-400/10 ring-1 ring-amber-400/20',
  emerald: 'text-emerald-400 bg-emerald-400/10 ring-1 ring-emerald-400/20',
  slate:   'text-slate-400 bg-slate-400/10 ring-1 ring-slate-400/20',
};

export function StatCard({ label, value, sub, icon: Icon, accent = 'cyan' }: Props) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 backdrop-blur">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-slate-400">{label}</p>
          <p className="mt-1 text-3xl font-bold tracking-tight text-white">{value}</p>
          {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
        </div>
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${ACCENT[accent]}`}>
          <Icon className="h-5 w-5" />
        </span>
      </div>
    </div>
  );
}
