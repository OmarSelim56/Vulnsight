import { format } from 'date-fns';
import { Radio, Shield, ShieldAlert, Trash2 } from 'lucide-react';
import { useLiveAlerts } from '../components/Layout';
import { DetectionPanel } from '../components/DetectionPanel';
import { SeverityBadge } from '../components/SeverityBadge';
import { ShapDrawer } from '../components/ShapDrawer';
import { protocolName } from '../utils/protocols';
import { useState } from 'react';
import type { Alert } from '../types';

export function LiveTrafficPage() {
  const { liveAlerts, connected, clear } = useLiveAlerts();
  const [selected, setSelected] = useState<Alert | null>(null);

  // Show the full live stream — both malicious and benign flows
  const visible = liveAlerts;

  const maliciousCount = visible.filter((a) => a.is_malicious).length;
  const benignCount = visible.filter((a) => !a.is_malicious).length;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Live Traffic</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Real-time network event stream from the detection engine
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium ${
            connected
              ? 'bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/30'
              : 'bg-slate-800 text-slate-500'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`} />
            {connected ? 'Live' : 'Offline'}
          </span>
          {liveAlerts.length > 0 && (
            <button
              onClick={clear}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-1.5 text-xs text-slate-400 hover:text-red-400 transition"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Detection engine control */}
      <DetectionPanel />

      {/* Live counters */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total Events', value: visible.length, color: 'text-cyan-400' },
          { label: 'Malicious', value: maliciousCount, color: 'text-red-400' },
          { label: 'Benign', value: benignCount, color: 'text-emerald-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded-xl border border-slate-800 bg-slate-900/60 px-5 py-4">
            <p className="text-xs text-slate-500">{label}</p>
            <p className={`mt-1 text-3xl font-bold tabular-nums ${color}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Live event stream */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60">
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-200">Event Stream</h2>
          </div>
          <span className="text-xs text-slate-500">{visible.length} events since page load</span>
        </div>

        {visible.length === 0 ? (
          <div className="flex flex-col items-center gap-3 py-16 text-slate-500">
            <Radio className="h-8 w-8 opacity-30" />
            <p className="text-sm">
              {connected
                ? 'Waiting for network events — start the detection engine above'
                : 'WebSocket offline — start the backend server'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-800/60 overflow-hidden">
            {[...visible].reverse().map((alert, i) => (
              <div
                key={i}
                onClick={() => setSelected(alert)}
                className={`flex cursor-pointer items-center gap-4 px-5 py-3 text-xs transition hover:bg-slate-800/40 ${
                  i === 0 ? 'bg-slate-800/20' : ''
                }`}
              >
                {/* icon */}
                <span className="shrink-0">
                  {alert.is_malicious
                    ? <ShieldAlert className="h-4 w-4 text-red-400" />
                    : <Shield className="h-4 w-4 text-emerald-500/60" />}
                </span>

                {/* time */}
                <span className="w-24 shrink-0 font-mono text-slate-500">
                  {format(new Date(alert.timestamp), 'HH:mm:ss.SSS').slice(0, 12)}
                </span>

                {/* severity */}
                <span className="shrink-0">
                  <SeverityBadge severity={alert.severity} />
                </span>

                {/* src → dst */}
                <span className="flex-1 truncate font-mono text-slate-300">
                  {alert.source_ip}
                  <span className="mx-1 text-slate-600">→</span>
                  {alert.destination_ip}
                </span>

                {/* protocol */}
                <span className="w-14 shrink-0 text-slate-500">
                  {protocolName(alert.protocol)}
                </span>

                {/* attack type */}
                {alert.attack_type && alert.attack_type !== 'normal' && alert.attack_type !== 'unknown' && (
                  <span className="shrink-0 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-slate-400">
                    {alert.attack_type.replace(/_/g, ' ')}
                  </span>
                )}

                {/* confidence */}
                <span className="w-12 shrink-0 text-right text-slate-500">
                  {(alert.confidence * 100).toFixed(0)}%
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {selected && <ShapDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
