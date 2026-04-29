import { format } from 'date-fns';
import { ChevronDown, ChevronUp, Shield, ShieldAlert } from 'lucide-react';
import { useMemo, useState } from 'react';
import type { Alert } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { ShapDrawer } from './ShapDrawer';

type SortKey = 'timestamp' | 'severity' | 'source_ip' | 'confidence';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, warning: 4, info: 5,
};

interface Props {
  alerts: Alert[];
  compact?: boolean;
}

export function AlertTable({ alerts, compact = false }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>('timestamp');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterMalicious, setFilterMalicious] = useState<'' | 'true' | 'false'>('');
  const [selected, setSelected] = useState<Alert | null>(null);

  const handleSort = (key: SortKey) => {
    if (key === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('desc'); }
  };

  const sorted = useMemo(() => {
    let rows = alerts.filter((a) => a.severity !== 'info'); // info = benign noise, excluded
    if (filterSeverity) rows = rows.filter((a) => a.severity === filterSeverity);
    if (filterMalicious !== '') rows = rows.filter((a) => String(a.is_malicious) === filterMalicious);
    rows.sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'timestamp') cmp = a.timestamp.localeCompare(b.timestamp);
      else if (sortKey === 'severity') cmp = (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
      else if (sortKey === 'source_ip') cmp = a.source_ip.localeCompare(b.source_ip);
      else if (sortKey === 'confidence') cmp = a.confidence - b.confidence;
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return rows;
  }, [alerts, sortKey, sortDir, filterSeverity, filterMalicious]);

  const SortIcon = ({ k }: { k: SortKey }) =>
    sortKey === k
      ? sortDir === 'asc' ? <ChevronUp className="inline h-3 w-3" /> : <ChevronDown className="inline h-3 w-3" />
      : <ChevronDown className="inline h-3 w-3 opacity-30" />;

  const Th = ({ label, k }: { label: string; k: SortKey }) => (
    <th
      onClick={() => handleSort(k)}
      className="cursor-pointer select-none whitespace-nowrap px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-cyan-400"
    >
      {label} <SortIcon k={k} />
    </th>
  );

  // Always show the full canonical severity list so the filter is predictable,
  // regardless of which severities happen to be present in the current data.
  const severities = ['critical', 'high', 'medium', 'low', 'warning'];

  return (
    <>
      {!compact && (
        <div className="mb-3 flex flex-wrap items-center gap-3">
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="">All severities</option>
            {severities.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select
            value={filterMalicious}
            onChange={(e) => setFilterMalicious(e.target.value as '' | 'true' | 'false')}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="">All traffic</option>
            <option value="true">Malicious only</option>
            <option value="false">Benign only</option>
          </select>
          <span className="ml-auto text-xs text-slate-500">{sorted.length} events</span>
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead className="bg-slate-900/80">
              <tr>
                <th className="w-6 px-4 py-3" />
                <Th label="Time" k="timestamp" />
                <Th label="Severity" k="severity" />
                <Th label="Source IP" k="source_ip" />
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Destination IP</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Label</th>
                <Th label="Confidence" k="confidence" />
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-400">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">No alerts found</td>
                </tr>
              )}
              {sorted.map((alert, i) => (
                <tr
                  key={i}
                  onClick={() => setSelected(alert)}
                  className="cursor-pointer transition-colors hover:bg-slate-800/40"
                >
                  <td className="pl-4 pr-2 py-3">
                    {alert.is_malicious
                      ? <ShieldAlert className="h-4 w-4 text-red-400" />
                      : <Shield className="h-4 w-4 text-emerald-500/60" />}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">
                    {format(new Date(alert.timestamp), 'MM/dd HH:mm:ss')}
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={alert.severity} /></td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{alert.source_ip}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-300">{alert.destination_ip}</td>
                  <td className="px-4 py-3 text-xs">
                    <span className="text-slate-300">{alert.label}</span>
                    {alert.attack_type && alert.attack_type !== 'normal' && alert.attack_type !== 'unknown' && (
                      <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-400 uppercase tracking-wide">
                        {alert.attack_type.replace(/_/g, ' ')}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className="h-full rounded-full bg-cyan-500"
                          style={{ width: `${(alert.confidence * 100).toFixed(0)}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400">{(alert.confidence * 100).toFixed(1)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">{alert.triage_action.replace(/_/g, ' ')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {selected && <ShapDrawer alert={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
