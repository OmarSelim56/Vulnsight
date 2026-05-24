import { format } from 'date-fns';
import { X } from 'lucide-react';
import { useEffect } from 'react';
import type { Alert } from '../types';
import { SeverityBadge } from './SeverityBadge';
import { protocolName } from '../utils/protocols';

interface Props {
  alert: Alert;
  onClose: () => void;
}

export function ShapDrawer({ alert, onClose }: Props) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const maxImpact = Math.max(...(alert.shap_top_features.map((f) => f.impact)), 0.001);
  const isSignature = alert.detection_source === 'signature';
  const explanationTitle = isSignature
    ? 'Rule Evidence (signature match)'
    : 'Top SHAP Feature Contributions (model attribution)';

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* backdrop */}
      <div className="flex-1 bg-black/60 backdrop-blur-sm" onClick={onClose} />

      {/* panel */}
      <div className="flex w-full max-w-lg flex-col overflow-y-auto border-l border-slate-800 bg-slate-950 shadow-2xl">
        {/* header */}
        <div className="flex items-center justify-between border-b border-slate-800 px-6 py-4">
          <h2 className="text-base font-semibold text-white">Alert Details</h2>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 space-y-6 p-6">
          {/* meta grid */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            {[
              ['Time', format(new Date(alert.timestamp), 'yyyy-MM-dd HH:mm:ss')],
              ['Severity', null],
              ['Source IP', alert.source_ip],
              ['Destination IP', alert.destination_ip],
              ['Protocol', protocolName(alert.protocol)],
              ['Attack Type', alert.attack_type ? alert.attack_type.replace(/_/g, ' ') : '—'],
              ['Interface', alert.interface ?? '—'],
              ['Label', alert.label],
              ['Confidence', `${(alert.confidence * 100).toFixed(1)}%`],
              ['Confidence Level', alert.confidence_level],
              ['Triage Action', alert.triage_action.replace(/_/g, ' ')],
            ].map(([k, v]) => (
              <div key={k as string} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-xs text-slate-500">{k}</p>
                {k === 'Severity'
                  ? <div className="mt-1"><SeverityBadge severity={alert.severity} /></div>
                  : <p className="mt-0.5 font-mono text-xs text-slate-200 break-all">{v}</p>}
              </div>
            ))}
          </div>

          {/* Detection source badge + rule reason */}
          {alert.detection_source && (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">Detection source</span>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                    isSignature
                      ? 'bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30'
                      : 'bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30'
                  }`}
                >
                  {isSignature ? 'Signature Rule' : 'ML Model'}
                </span>
              </div>
              {alert.detection_reason && (
                <p className="mt-2 font-mono text-xs text-slate-300 break-words">
                  {alert.detection_reason}
                </p>
              )}
            </div>
          )}

          {/* SHAP features */}
          {alert.shap_top_features.length > 0 && (
            <div>
              <h3 className="mb-3 text-sm font-semibold text-slate-300">
                {explanationTitle}
              </h3>
              <div className="space-y-3">
                {alert.shap_top_features.map((f) => {
                  const pct = (f.impact / maxImpact) * 100;
                  const isRisk = f.direction === 'increases_risk';
                  return (
                    <div key={f.feature}>
                      <div className="mb-1 flex items-center justify-between text-xs">
                        <span className="text-slate-300">{f.feature}</span>
                        <span className={isRisk ? 'text-red-400' : 'text-emerald-400'}>
                          {isRisk ? '▲ increases risk' : '▼ decreases risk'}
                        </span>
                      </div>
                      <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className={`h-full rounded-full transition-all ${isRisk ? 'bg-red-500' : 'bg-emerald-500'}`}
                          style={{ width: `${pct.toFixed(1)}%` }}
                        />
                      </div>
                      <p className="mt-0.5 text-right text-xs text-slate-500">
                        impact {f.impact.toFixed(4)}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {alert.shap_top_features.length === 0 && (
            <p className="text-sm text-slate-500">No SHAP explanation available for this alert.</p>
          )}
        </div>
      </div>
    </div>
  );
}
