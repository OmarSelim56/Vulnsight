import { useQuery } from '@tanstack/react-query';
import {
  Activity,
  AlertTriangle,
  RefreshCw,
  Shield,
  ShieldAlert,
  Skull,
  Wifi,
} from 'lucide-react';
import { useMemo } from 'react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getAlerts, getHealth, getSeverityBreakdown, getTimeline, getTopAttackers } from '../api/client';
import { AlertTable } from '../components/AlertTable';
import { StatCard } from '../components/StatCard';
import { useLiveAlerts } from '../components/Layout';

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#eab308',
  warning: '#a855f7',
};

const ATTACK_COLORS: Record<string, string> = {
  ddos:             '#ef4444',
  port_scan:        '#f97316',
  brute_force:      '#f59e0b',
  data_exfiltration:'#a855f7',
  c2_beacon:        '#ec4899',
  intrusion:        '#64748b',
};

// Severity order for chart rendering
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'warning'];

export function DashboardPage() {
  const { liveAlerts } = useLiveAlerts();

  const { data: health, refetch: refetchHealth } = useQuery({
    queryKey: ['health'],
    queryFn: getHealth,
    refetchInterval: 15_000,
  });

  const { data: alerts = [], refetch: refetchAlerts } = useQuery({
    queryKey: ['alerts', 200],
    queryFn: () => getAlerts(200),
    refetchInterval: 30_000,
  });

  const { data: timeline = [], refetch: refetchTimeline } = useQuery({
    queryKey: ['timeline'],
    queryFn: () => getTimeline(24),
    refetchInterval: 60_000,
  });

  const { data: topAttackers = [], refetch: refetchAttackers } = useQuery({
    queryKey: ['top-attackers'],
    queryFn: () => getTopAttackers(8),
    refetchInterval: 60_000,
  });

  const { data: severityData = [], refetch: refetchSeverity } = useQuery({
    queryKey: ['severity-breakdown'],
    queryFn: getSeverityBreakdown,
    refetchInterval: 60_000,
  });

  const handleRefreshAll = () => {
    refetchHealth();
    refetchAlerts();
    refetchTimeline();
    refetchAttackers();
    refetchSeverity();
  };

  // Merge live + historical for table and derived stats
  const allAlerts = useMemo(
    () => [...liveAlerts, ...alerts].slice(0, 200),
    [liveAlerts, alerts],
  );

  // Stat card values — derived live from fetched alerts, no report needed
  const maliciousCount = useMemo(
    () => allAlerts.filter((a) => a.is_malicious).length,
    [allAlerts],
  );
  const benignCount = useMemo(
    () => allAlerts.filter((a) => !a.is_malicious).length,
    [allAlerts],
  );
  const maliciousRatio = allAlerts.length > 0
    ? `${((maliciousCount / allAlerts.length) * 100).toFixed(1)}%`
    : '—';

  // Severity Breakdown — from dedicated backend query, same refresh cadence as other analytics
  const severityChartData = useMemo(() => {
    const byName = Object.fromEntries(severityData.map((d) => [d.severity, d.event_count]));
    return SEV_ORDER.filter((s) => (byName[s] ?? 0) > 0).map((name) => ({ name, value: byName[name] }));
  }, [severityData]);

  // Top Targeted IPs — aggregated from allAlerts by destination_ip
  const topTargetsData = useMemo(() => {
    const counts: Record<string, number> = {};
    allAlerts.forEach((a) => {
      if (a.destination_ip) {
        counts[a.destination_ip] = (counts[a.destination_ip] ?? 0) + 1;
      }
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([name, value]) => ({ name, value }));
  }, [allAlerts]);

  // Attack type breakdown — computed from fetched alerts, intrusion/normal excluded
  const EXCLUDED_TYPES = new Set(['intrusion', 'normal', 'unknown', null, undefined, '']);
  const attackTypeData = useMemo(() => {
    const counts: Record<string, number> = {};
    allAlerts.forEach((a) => {
      if (!a.is_malicious) return;
      const t = a.attack_type ?? '';
      if (EXCLUDED_TYPES.has(t)) return;
      counts[t] = (counts[t] ?? 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .map(([type, count]) => ({ type, count }));
  }, [allAlerts]);

  const recentAlerts = allAlerts.filter((a) => a.is_malicious).slice(0, 8);
  const totalAlerts = health?.counts.alerts ?? 0;

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Dashboard</h1>
          <p className="mt-0.5 text-sm text-slate-500">Real-time network threat monitoring</p>
        </div>
        <button
          onClick={handleRefreshAll}
          className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-300 transition hover:border-slate-600 hover:text-white"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Total Alerts"
          value={totalAlerts.toLocaleString()}
          sub={`${health?.counts.flow ?? 0} flows captured`}
          icon={Shield}
          accent="cyan"
        />
        <StatCard
          label="Malicious Events"
          value={maliciousCount.toLocaleString()}
          sub={`${maliciousRatio} of traffic`}
          icon={ShieldAlert}
          accent="red"
        />
        <StatCard
          label="Live Events"
          value={liveAlerts.length}
          sub="since page load"
          icon={Wifi}
          accent="amber"
        />
        <StatCard
          label="Benign Traffic"
          value={benignCount.toLocaleString()}
          sub="clean flows"
          icon={Activity}
          accent="emerald"
        />
      </div>

      {/* Severity Breakdown + Top Targeted IPs */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Severity breakdown */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="mb-4 text-sm font-semibold text-slate-200">Severity Breakdown</h2>
          {severityChartData.length === 0 ? (
            <div className="flex h-48 items-center justify-center text-sm text-slate-500">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={severityChartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityChartData.map((entry) => (
                    <Cell key={entry.name} fill={SEV_COLORS[entry.name] ?? '#64748b'} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }}
                  labelStyle={{ color: '#94a3b8' }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Legend
                  iconType="circle"
                  iconSize={8}
                  formatter={(value) => <span className="text-xs text-slate-400">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Top targeted IPs */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <h2 className="mb-4 text-sm font-semibold text-slate-200">Top Targeted IPs</h2>
          {topTargetsData.length === 0 ? (
            <div className="flex h-48 items-center justify-center text-sm text-slate-500">No data yet</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topTargetsData} layout="vertical" margin={{ left: 8, right: 16 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={108}
                  tick={{ fill: '#94a3b8', fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }}
                  itemStyle={{ color: '#e2e8f0' }}
                  cursor={{ fill: '#1e293b' }}
                />
                <Bar dataKey="value" name="Alerts" fill="#22d3ee" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Top attackers + Attack types */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Top attackers */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-4 flex items-center gap-2">
            <Skull className="h-4 w-4 text-red-400" />
            <h2 className="text-sm font-semibold text-slate-200">Top Attackers</h2>
          </div>
          {topAttackers.length === 0 ? (
            <div className="flex h-36 items-center justify-center text-sm text-slate-500">No malicious traffic yet</div>
          ) : (
            <div className="space-y-2.5">
              {topAttackers.map((a) => (
                <div key={a.source_ip} className="flex items-center gap-3">
                  <span className="w-32 truncate font-mono text-xs text-slate-300">{a.source_ip}</span>
                  <div className="flex-1 overflow-hidden rounded-full bg-slate-800 h-2">
                    <div
                      className="h-2 rounded-full bg-red-500"
                      style={{ width: `${Math.min(100, (a.event_count / (topAttackers[0]?.event_count || 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="w-10 text-right font-mono text-xs text-slate-400">{a.event_count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Attack type breakdown */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="mb-4 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-orange-400" />
            <h2 className="text-sm font-semibold text-slate-200">Attack Categories</h2>
          </div>
          {attackTypeData.length === 0 ? (
            <div className="flex h-36 items-center justify-center text-sm text-slate-500">
              No classified attacks yet
            </div>
          ) : (
            <div className="space-y-2.5">
              {attackTypeData.map(({ type, count }) => (
                <div key={type} className="flex items-center gap-3">
                  <span
                    className="w-2.5 h-2.5 shrink-0 rounded-full"
                    style={{ background: ATTACK_COLORS[type] ?? '#64748b' }}
                  />
                  <span className="w-28 shrink-0 text-xs font-medium capitalize text-slate-300">
                    {type.replace(/_/g, ' ')}
                  </span>
                  <div className="flex-1 overflow-hidden rounded-full bg-slate-800 h-2">
                    <div
                      className="h-2 rounded-full transition-all"
                      style={{
                        width: `${Math.min(100, (count / (attackTypeData[0]?.count || 1)) * 100)}%`,
                        background: ATTACK_COLORS[type] ?? '#64748b',
                      }}
                    />
                  </div>
                  <span className="w-8 text-right font-mono text-xs text-slate-400">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Alert Timeline (24 h) */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <h2 className="mb-4 text-sm font-semibold text-slate-200">Alert Timeline (24 h)</h2>
        {timeline.length === 0 ? (
          <div className="flex h-36 items-center justify-center text-sm text-slate-500">No data yet</div>
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timeline} margin={{ left: 0, right: 8, top: 4, bottom: 0 }}>
              <defs>
                <linearGradient id="gradAll" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradMal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="bucket"
                tick={{ fill: '#64748b', fontSize: 10 }}
                axisLine={false}
                tickLine={false}
                tickFormatter={(v: string) => v.slice(11, 16)}
              />
              <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} width={30} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }}
                itemStyle={{ color: '#e2e8f0' }}
                labelStyle={{ color: '#94a3b8', fontSize: 11 }}
              />
              <Area type="monotone" dataKey="count" name="Total" stroke="#22d3ee" strokeWidth={2} fill="url(#gradAll)" dot={false} />
              <Area type="monotone" dataKey="malicious" name="Malicious" stroke="#ef4444" strokeWidth={2} fill="url(#gradMal)" dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Recent alerts */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200">Recent Alerts</h2>
          {liveAlerts.length > 0 && (
            <span className="flex items-center gap-1.5 text-xs text-red-400">
              <AlertTriangle className="h-3.5 w-3.5" />
              {liveAlerts.length} new live events
            </span>
          )}
        </div>
        <AlertTable alerts={recentAlerts} compact />
      </div>
    </div>
  );
}
