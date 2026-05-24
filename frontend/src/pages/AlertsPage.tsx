import { useQuery } from '@tanstack/react-query';
import { RefreshCw, Trash2, Wifi, WifiOff } from 'lucide-react';
import { useState } from 'react';
import { getAlerts } from '../api/client';
import { AlertTable } from '../components/AlertTable';
import { useLiveAlerts } from '../components/Layout';

export function AlertsPage() {
  const { liveAlerts, connected, clear } = useLiveAlerts();
  const [showLive, setShowLive] = useState(true);

  const { data: historical = [], isFetching, refetch } = useQuery({
    queryKey: ['alerts', 500],
    queryFn: () => getAlerts(500),
    refetchInterval: 30_000,
  });

  const allAlerts = showLive ? [...liveAlerts, ...historical].slice(0, 500) : historical;
  const alerts = allAlerts.filter((a) => a.is_malicious);

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-white">Alerts</h1>
          <p className="mt-0.5 text-sm text-slate-500">Malicious detections — history and real-time feed</p>
        </div>

        {/* Live toggle */}
        <button
          onClick={() => setShowLive((v) => !v)}
          className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition ${
            showLive
              ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-400'
              : 'border-slate-700 bg-slate-800/60 text-slate-400 hover:text-slate-200'
          }`}
        >
          {connected
            ? <Wifi className="h-4 w-4" />
            : <WifiOff className="h-4 w-4" />}
          {showLive ? 'Live ON' : 'Live OFF'}
        </button>

        {liveAlerts.filter((a) => a.is_malicious).length > 0 && (
          <button
            onClick={clear}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-400 hover:text-red-400"
          >
            <Trash2 className="h-4 w-4" />
            Clear live ({liveAlerts.filter((a) => a.is_malicious).length})
          </button>
        )}

        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-300 hover:text-white disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Live feed banner */}
      {showLive && liveAlerts.filter((a) => a.is_malicious).length > 0 && (
        <div className="flex items-center gap-3 rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3">
          <span className="h-2 w-2 rounded-full bg-red-400 animate-pulse" />
          <span className="text-sm text-red-400 font-medium">
            {liveAlerts.filter((a) => a.is_malicious).length} malicious detection{liveAlerts.filter((a) => a.is_malicious).length !== 1 ? 's' : ''} this session
          </span>
          <span className="ml-auto text-xs text-red-400/60">Click any row to inspect</span>
        </div>
      )}

      <AlertTable alerts={alerts} />
    </div>
  );
}
