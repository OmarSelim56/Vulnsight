import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, AlertTriangle, ChevronDown, Play, Square, Wifi, WifiOff } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getDetectionStatus, getInterfaces, startDetection, stopDetection } from '../api/client';
import type { DetectionStatus, NetworkInterface } from '../types';

function fmt(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleTimeString();
}

function StatItem({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex flex-col">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="font-mono text-sm font-semibold text-slate-200">{value}</span>
    </div>
  );
}

export function DetectionPanel() {
  const queryClient = useQueryClient();
  const [selectedDevice, setSelectedDevice] = useState('');
  const [busy, setBusy] = useState(false);

  const { data: status } = useQuery<DetectionStatus>({
    queryKey: ['detection-status'],
    queryFn: getDetectionStatus,
    refetchInterval: 3000,
    retry: false,
  });

  const { data: interfaces = [] } = useQuery<NetworkInterface[]>({
    queryKey: ['detection-interfaces'],
    queryFn: getInterfaces,
    staleTime: 60_000,
    retry: false,
  });

  // Auto-select when exactly one interface is available
  useEffect(() => {
    if (interfaces.length === 1 && !selectedDevice) {
      setSelectedDevice(interfaces[0].device);
    }
  }, [interfaces, selectedDevice]);

  const running = status?.running ?? false;

  async function handleStart() {
    setBusy(true);
    try {
      const next = await startDetection(selectedDevice || undefined);
      queryClient.setQueryData(['detection-status'], next);
    } finally {
      setBusy(false);
    }
  }

  async function handleStop() {
    setBusy(true);
    try {
      const next = await stopDetection();
      queryClient.setQueryData(['detection-status'], next);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-slate-200">Live Detection Engine</h2>
        </div>
        <span
          className={`flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium ${
            running
              ? 'bg-emerald-500/15 text-emerald-400'
              : 'bg-slate-800 text-slate-500'
          }`}
        >
          {running ? (
            <><Wifi className="h-3 w-3 animate-pulse" /> Capturing</>
          ) : (
            <><WifiOff className="h-3 w-3" /> Stopped</>
          )}
        </span>
      </div>

      {/* Error banner */}
      {status?.error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-800/60 bg-red-950/40 px-3 py-2 text-xs text-red-400">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{status.error}</span>
        </div>
      )}

      {/* Stats grid */}
      <div className="grid grid-cols-3 gap-4 sm:grid-cols-5">
        <StatItem label="Interface" value={status?.interface ?? '—'} />
        <StatItem label="Flows" value={(status?.flows_processed ?? 0).toLocaleString()} />
        <StatItem label="Predictions" value={(status?.predictions_made ?? 0).toLocaleString()} />
        <StatItem label="Malicious" value={(status?.malicious_detected ?? 0).toLocaleString()} />
        <StatItem label="Last alert" value={fmt(status?.last_alert_at ?? null)} />
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3">
        {!running && (
          <div className="relative flex-1">
            <select
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              className="w-full appearance-none rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 pr-8 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            >
              {interfaces.length === 0 ? (
                <option value="">Loading interfaces…</option>
              ) : (
                <>
                  {interfaces.length > 1 && (
                    <option value="">Select interface…</option>
                  )}
                  {interfaces.map((iface) => (
                    <option key={iface.device} value={iface.device}>
                      {iface.name}
                      {iface.description && iface.description !== iface.name
                        ? ` — ${iface.description}`
                        : ''}
                      {iface.status.toLowerCase() === 'up' ? '' : ` (${iface.status})`}
                    </option>
                  ))}
                </>
              )}
            </select>
            <ChevronDown className="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          </div>
        )}
        {running ? (
          <button
            onClick={handleStop}
            disabled={busy}
            className="flex items-center gap-1.5 rounded-lg bg-red-600 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-red-500 disabled:opacity-50"
          >
            <Square className="h-3 w-3" />
            Stop
          </button>
        ) : (
          <button
            onClick={handleStart}
            disabled={busy || (!selectedDevice && interfaces.length > 0)}
            className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-emerald-500 disabled:opacity-50"
          >
            <Play className="h-3 w-3" />
            Start Capture
          </button>
        )}
      </div>
    </div>
  );
}
