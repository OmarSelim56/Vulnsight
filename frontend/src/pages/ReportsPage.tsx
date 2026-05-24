import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { toCanvas } from 'html-to-image';
import { jsPDF } from 'jspdf';
import {
  Activity, BarChart3, Download, FileText, Loader2, RefreshCw,
  ShieldAlert, Swords, Target, Trash2, TrendingUp,
} from 'lucide-react';
import { useRef, useState } from 'react';
import {
  Bar, BarChart, CartesianGrid, Cell, Legend,
  Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import {
  deleteReport, downloadCsv,
  generateReport, getAttackTypes, getReportHistory, ApiError,
} from '../api/client';
import type { Report, SavedReport } from '../types';

// ─── Constants ───────────────────────────────────────────────────────────────

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#f59e0b',
  low:      '#eab308',
  warning:  '#a855f7',
};

const ATTACK_COLORS: Record<string, string> = {
  ddos:             '#ef4444',
  port_scan:        '#f97316',
  brute_force:      '#f59e0b',
  data_exfiltration:'#a855f7',
  c2_beacon:        '#ec4899',
  intrusion:        '#64748b',
};

function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}

// ─── Metric card ─────────────────────────────────────────────────────────────

function Metric({
  label, value, sub, icon: Icon, color,
}: {
  label: string; value: string | number; sub?: string;
  icon: React.ElementType; color: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <div className="mb-3 flex items-center gap-3">
        <span className={`flex h-8 w-8 items-center justify-center rounded-lg ${color}`}>
          <Icon className="h-4 w-4" />
        </span>
        <span className="text-sm font-medium text-slate-400">{label}</span>
      </div>
      <p className="text-3xl font-bold tracking-tight text-white">{value}</p>
      {sub && <p className="mt-1 text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

// ─── Report History table ─────────────────────────────────────────────────────

function ReportHistoryTable({
  onDownload,
  pdfLoading,
}: {
  onDownload: (id: number, generatedAt: string) => void;
  pdfLoading: boolean;
}) {
  const queryClient = useQueryClient();

  const { data: history = [], isLoading } = useQuery<SavedReport[]>({
    queryKey: ['report-history'],
    queryFn: () => getReportHistory(50),
    refetchOnWindowFocus: false,
  });

  const { mutate: remove } = useMutation({
    mutationFn: (id: number) => deleteReport(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['report-history'] }),
  });

  if (isLoading) return (
    <div className="flex h-24 items-center justify-center text-sm text-slate-500">Loading history…</div>
  );

  if (history.length === 0) return (
    <div className="flex h-24 items-center justify-center text-sm text-slate-500">
      No reports yet — generate one above.
    </div>
  );

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            {['ID', 'Name', 'Type', 'Period', 'Alerts', 'Generated', 'Size', 'Actions'].map((h) => (
              <th key={h} className="pb-3 pr-4 text-left text-xs font-semibold uppercase tracking-wider text-slate-500 first:pl-1">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/50">
          {history.map((r) => (
            <tr key={r.id} className="group">
              <td className="py-3 pl-1 pr-4 font-mono text-xs text-slate-500">#{r.id}</td>
              <td className="py-3 pr-4 text-slate-200">{r.name}</td>
              <td className="py-3 pr-4">
                <span className="rounded bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-400">
                  {r.type}
                </span>
              </td>
              <td className="py-3 pr-4 text-xs text-slate-400">{r.period}</td>
              <td className="py-3 pr-4 font-mono text-xs text-slate-300">
                {r.alert_count.toLocaleString()}
              </td>
              <td className="py-3 pr-4 font-mono text-xs text-slate-400">
                {format(new Date(r.generated_at), 'yyyy-MM-dd HH:mm')}
              </td>
              <td className="py-3 pr-4 text-xs text-slate-500">{fmtBytes(r.report_size)}</td>
              <td className="py-3">
                <div className="flex items-center gap-2 opacity-0 transition group-hover:opacity-100">
                  <button
                    onClick={() => onDownload(r.id, r.generated_at)}
                    title="Download PDF"
                    disabled={pdfLoading}
                    className="rounded p-1 text-slate-400 hover:text-cyan-400 disabled:opacity-40"
                  >
                    {pdfLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
                  </button>
                  <button
                    onClick={() => remove(r.id)}
                    title="Delete"
                    className="rounded p-1 text-slate-400 hover:text-red-400"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ReportsPage() {
  const queryClient = useQueryClient();
  const reportRef = useRef<HTMLDivElement>(null);

  const [report, setReport] = useState<Report | null>(
    () => queryClient.getQueryData<Report>(['report']) ?? null,
  );
  const [loading, setLoading] = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [error, setError] = useState('');
  const [generatedAt, setGeneratedAt] = useState<Date | null>(
    report ? new Date(report.generated_at) : null,
  );

  const { data: attackTypes = [] } = useQuery({
    queryKey: ['attack-types'],
    queryFn: getAttackTypes,
    refetchInterval: 60_000,
  });

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await generateReport();
      setReport(data);
      setGeneratedAt(new Date());
      queryClient.setQueryData(['report'], data);
      queryClient.invalidateQueries({ queryKey: ['report-history'] });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to generate report');
    } finally {
      setLoading(false);
    }
  };

  // ── Core PDF renderer — converts the live reportRef DOM node to PDF ────────
  const renderPDF = async (filename: string) => {
    if (!reportRef.current) throw new Error('Report not rendered');

    const PDF_W  = 297;  // A4 landscape mm
    const PDF_H  = 210;
    const MARGIN = 10;
    const PIXEL_RATIO = 2;

    const el = reportRef.current;

    // Collect child-element top offsets BEFORE capturing canvas so the DOM
    // is in its natural scroll position.  These become our break candidates.
    const containerTop = el.getBoundingClientRect().top;
    const childBreaks: number[] = Array.from(el.children).map((child) => {
      const top = child.getBoundingClientRect().top - containerTop;
      return Math.round(top * PIXEL_RATIO);
    });

    const canvas = await toCanvas(el, {
      pixelRatio: PIXEL_RATIO,
      backgroundColor: '#020617',
      width: el.scrollWidth,
      height: el.scrollHeight,
    });

    const totalCanvasH = canvas.height;
    const pdf          = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'landscape' });
    const contentW     = PDF_W - MARGIN * 2;
    const pxPerMm      = canvas.width / contentW;
    const pageH_px     = Math.round((PDF_H - MARGIN * 2 - 8) * pxPerMm); // 8mm footer

    // ── Smart break points using real element boundaries ──────────────────
    // For each ideal cut, pick the child boundary that is closest to (but
    // does not exceed) the cut. This guarantees breaks happen between cards,
    // never through a table row or chart.
    const findBreak = (idealCutY: number): number => {
      let best = 0;
      for (const b of childBreaks) {
        if (b <= idealCutY && b > best) best = b;
      }
      // If no child boundary found within half a page, fall back to ideal cut
      return best > idealCutY - pageH_px * 0.5 ? best : idealCutY;
    };

    // Pre-compute all page slices
    const breaks: number[] = [0];
    let pos = 0;
    while (pos < totalCanvasH) {
      const ideal = pos + pageH_px;
      if (ideal >= totalCanvasH) break;
      const cut = findBreak(ideal);
      // Guard against infinite loop if findBreak returns same pos
      if (cut <= pos) { breaks.push(pos + pageH_px); pos = pos + pageH_px; continue; }
      breaks.push(cut);
      pos = cut;
    }
    breaks.push(totalCanvasH);

    const totalPages = breaks.length - 1;

    for (let page = 0; page < totalPages; page++) {
      if (page > 0) pdf.addPage();

      pdf.setFillColor(2, 6, 23);
      pdf.rect(0, 0, PDF_W, PDF_H, 'F');

      const srcY = breaks[page];
      const srcH = breaks[page + 1] - srcY;

      const slice    = document.createElement('canvas');
      slice.width    = canvas.width;
      slice.height   = srcH;
      const sliceCtx = slice.getContext('2d')!;
      sliceCtx.drawImage(canvas, 0, srcY, canvas.width, srcH, 0, 0, canvas.width, srcH);

      pdf.addImage(slice.toDataURL('image/jpeg', 0.94), 'JPEG', MARGIN, MARGIN, contentW, srcH / pxPerMm);

      pdf.setFontSize(7);
      pdf.setTextColor(100, 116, 139);
      pdf.text(
        `VulnSight — Threat Intelligence Report  •  Page ${page + 1} of ${totalPages}`,
        PDF_W / 2, PDF_H - 4, { align: 'center' },
      );
    }

    pdf.save(filename);
  };

  const handleExportPDF = async () => {
    setPdfLoading(true);
    setError('');
    try {
      const filename = `vulnsight_report_${format(generatedAt ?? new Date(), 'yyyy-MM-dd_HHmm')}.pdf`;
      await renderPDF(filename);
    } catch (err) {
      setError(`PDF export failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setPdfLoading(false);
    }
  };

  // ── History row: load saved report then export as PDF ───────────────────────
  const handleHistoryDownload = async (id: number, generatedAtStr: string) => {
    setPdfLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('vs_token') ?? '';
      const res   = await fetch(`/api/v1/reports/${id}/download`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const data: Report = await res.json();

      // Load the historical report into the view so reportRef renders it
      setReport(data);
      setGeneratedAt(new Date(generatedAtStr));

      // Wait one frame for React to commit the new report to the DOM
      await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));

      const ts      = format(new Date(generatedAtStr), 'yyyy-MM-dd_HHmm');
      const filename = `vulnsight_report_${ts}.pdf`;
      await renderPDF(filename);
    } catch (err) {
      setError(`PDF export failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setPdfLoading(false);
    }
  };

  const severityData = report
    ? Object.entries(report.severity_breakdown)
        .filter(([k]) => k !== 'info')
        .map(([name, value]) => ({ name, value }))
    : [];

  const targetsData = report
    ? Object.entries(report.top_targets)
        .sort((a, b) => b[1] - a[1])
        .map(([name, hits]) => ({ name, hits }))
    : [];

  const attackData = attackTypes.map((a) => ({
    name: a.attack_type.replace(/_/g, ' '),
    raw: a.attack_type,
    value: a.event_count,
  }));

  const threatScore = report
    ? Math.min(100, Math.round(
        (report.malicious_ratio * 50) +
        (severityData.find((s) => s.name === 'critical')?.value ?? 0) > 0 ? 25 : 0 +
        (severityData.find((s) => s.name === 'high')?.value ?? 0) > 10 ? 15 : 0,
      ))
    : null;

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1">
          <h1 className="text-xl font-bold text-white">Reports</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Threat intelligence analysis and executive summaries
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => downloadCsv().catch((e) => setError(e.message))}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-300 hover:border-slate-600 hover:text-white transition"
          >
            <Download className="h-3.5 w-3.5" />
            CSV
          </button>
          <button
            onClick={handleExportPDF}
            disabled={!report || pdfLoading}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/60 px-3 py-2 text-sm text-slate-300 hover:border-slate-600 hover:text-white transition disabled:opacity-40"
          >
            {pdfLoading
              ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
              : <Download className="h-3.5 w-3.5" />}
            PDF
          </button>
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            {loading ? 'Generating…' : 'Generate Report'}
          </button>
        </div>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* ── Empty / loading state ── */}
      {!report && !loading && (
        <div className="flex flex-col items-center gap-4 rounded-xl border border-slate-800 bg-slate-900/60 py-20">
          <FileText className="h-10 w-10 text-slate-600" />
          <p className="text-slate-500">
            No report yet — click <span className="text-cyan-400">Generate Report</span> to analyse current data.
          </p>
        </div>
      )}
      {loading && !report && (
        <div className="flex flex-col items-center gap-4 rounded-xl border border-slate-800 bg-slate-900/60 py-20">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
          <p className="text-slate-500">Analysing traffic data…</p>
        </div>
      )}

      {/* ── Report content ── */}
      {report && (
        <div ref={reportRef} className="space-y-6">
          {/* Timestamp + threat score banner */}
          <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/60 px-6 py-4">
            <div>
              <p className="text-xs text-slate-500">Report generated</p>
              <p className="mt-0.5 font-mono text-sm text-slate-300">
                {generatedAt ? format(generatedAt, 'yyyy-MM-dd HH:mm:ss') : '—'}
              </p>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500">Threat Score</p>
              <p className={`mt-0.5 text-2xl font-bold ${
                (threatScore ?? 0) >= 60 ? 'text-red-400'
                : (threatScore ?? 0) >= 30 ? 'text-amber-400'
                : 'text-emerald-400'
              }`}>
                {threatScore ?? '—'}<span className="text-sm font-normal text-slate-500"> / 100</span>
              </p>
            </div>
            <div className="text-right">
              <p className="text-xs text-slate-500">Analysis period</p>
              <p className="mt-0.5 text-sm text-slate-300">All time</p>
            </div>
          </div>

          {/* Metric grid */}
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Metric label="Total Events"    value={report.total_events.toLocaleString()}    icon={BarChart3}   color="bg-cyan-400/10 text-cyan-400"    />
            <Metric label="Malicious"       value={report.malicious_events.toLocaleString()} sub={`${(report.malicious_ratio * 100).toFixed(1)}% of traffic`} icon={ShieldAlert} color="bg-red-400/10 text-red-400"     />
            <Metric label="Benign Traffic"  value={report.benign_events.toLocaleString()}    icon={Activity}    color="bg-emerald-400/10 text-emerald-400" />
            <Metric label="Threat Ratio"    value={`${(report.malicious_ratio * 100).toFixed(2)}%`} sub="malicious / total" icon={TrendingUp} color="bg-amber-400/10 text-amber-400" />
          </div>

          {/* Charts row 1 */}
          <div className="grid gap-4 lg:grid-cols-3">
            {/* Severity donut */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="mb-4 text-sm font-semibold text-slate-200">Severity Distribution</h2>
              {severityData.length === 0
                ? <div className="flex h-48 items-center justify-center text-sm text-slate-500">No data</div>
                : (
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie data={severityData} cx="50%" cy="50%" outerRadius={75} innerRadius={45}
                        paddingAngle={3} dataKey="value">
                        {severityData.map((e) => (
                          <Cell key={e.name} fill={SEV_COLORS[e.name] ?? '#64748b'} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }} itemStyle={{ color: '#e2e8f0' }} />
                      <Legend iconType="circle" iconSize={8} formatter={(v) => <span className="text-xs text-slate-400">{v}</span>} />
                    </PieChart>
                  </ResponsiveContainer>
                )}
            </div>

            {/* Top targets */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <div className="mb-4 flex items-center gap-2">
                <Target className="h-4 w-4 text-slate-500" />
                <h2 className="text-sm font-semibold text-slate-200">Top Targeted Hosts</h2>
              </div>
              {targetsData.length === 0
                ? <div className="flex h-48 items-center justify-center text-sm text-slate-500">No data</div>
                : (
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={targetsData} layout="vertical" margin={{ left: 4, right: 16 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                      <XAxis type="number" tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                      <YAxis type="category" dataKey="name" width={104} tick={{ fill: '#94a3b8', fontSize: 10 }} axisLine={false} tickLine={false} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }} itemStyle={{ color: '#e2e8f0' }} cursor={{ fill: '#1e293b' }} />
                      <Bar dataKey="hits" fill="#22d3ee" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                )}
            </div>

            {/* Attack types */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <div className="mb-4 flex items-center gap-2">
                <Swords className="h-4 w-4 text-slate-500" />
                <h2 className="text-sm font-semibold text-slate-200">Attack Vectors</h2>
              </div>
              {attackData.length === 0
                ? <div className="flex h-48 items-center justify-center text-sm text-slate-500">No data</div>
                : (
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart data={attackData} margin={{ left: 4, right: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                      <XAxis dataKey="name" tick={{ fill: '#64748b', fontSize: 9 }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} width={28} />
                      <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: 8 }} itemStyle={{ color: '#e2e8f0' }} />
                      <Bar dataKey="value" name="Events" radius={[4, 4, 0, 0]}>
                        {attackData.map((e) => (
                          <Cell key={e.raw} fill={ATTACK_COLORS[e.raw] ?? '#64748b'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
            </div>
          </div>

          {/* Severity table */}
          {severityData.length > 0 && (
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
              <h2 className="mb-4 text-sm font-semibold text-slate-200">Severity Breakdown</h2>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-800">
                    {['Severity', 'Count', '% of Total', 'Risk Level'].map((h) => (
                      <th key={h} className="pb-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/50">
                  {[...severityData].sort((a, b) => b.value - a.value).map(({ name, value }) => (
                    <tr key={name}>
                      <td className="py-3">
                        <span className="flex items-center gap-2">
                          <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[name] ?? '#64748b' }} />
                          <span className="capitalize text-slate-300">{name}</span>
                        </span>
                      </td>
                      <td className="py-3 font-mono text-slate-200">{value.toLocaleString()}</td>
                      <td className="py-3 text-slate-500">{((value / report.total_events) * 100).toFixed(1)}%</td>
                      <td className="py-3">
                        <div className="h-1.5 w-32 overflow-hidden rounded-full bg-slate-800">
                          <div className="h-full rounded-full" style={{ width: `${((value / report.total_events) * 100).toFixed(1)}%`, background: SEV_COLORS[name] ?? '#64748b' }} />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Report History ── */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
        <div className="mb-4 flex items-center gap-2">
          <FileText className="h-4 w-4 text-slate-500" />
          <h2 className="text-sm font-semibold text-slate-200">Report History</h2>
        </div>
        <ReportHistoryTable onDownload={handleHistoryDownload} pdfLoading={pdfLoading} />
      </div>
    </div>
  );
}
