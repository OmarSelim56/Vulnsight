/**
 * AlertToast — shows a slide-in notification whenever an alert of a
 * user-selected severity arrives over the WebSocket live feed.
 *
 * Which severities trigger a toast is read live from the user's setting
 * "alert_notification_severities" (configured in Settings → Detection
 * Thresholds). Defaults to ["critical", "high"] when the API hasn't
 * answered yet or no preference has been saved.
 */
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, X } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { getThresholds } from '../api/client';
import type { Alert } from '../types';

interface Toast {
  id: string;
  alert: Alert;
}

const DEFAULT_NOTIFY_SEVERITIES = ['critical', 'high'];
const AUTO_DISMISS_MS = 6000;

const SEV_STYLE: Record<string, string> = {
  critical: 'border-red-500/60 bg-red-950/80 text-red-300',
  high:     'border-orange-500/60 bg-orange-950/80 text-orange-300',
  medium:   'border-amber-500/60 bg-amber-950/80 text-amber-300',
  low:      'border-yellow-500/60 bg-yellow-950/80 text-yellow-300',
  info:     'border-sky-500/60 bg-sky-950/80 text-sky-300',
};

const FALLBACK_STYLE = 'border-slate-500/60 bg-slate-900/80 text-slate-300';

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const { alert } = toast;
  const style = SEV_STYLE[alert.severity] ?? FALLBACK_STYLE;

  useEffect(() => {
    const t = setTimeout(onDismiss, AUTO_DISMISS_MS);
    return () => clearTimeout(t);
  }, [onDismiss]);

  return (
    <div
      className={`flex items-start gap-3 rounded-xl border px-4 py-3 shadow-2xl backdrop-blur-sm
        animate-in slide-in-from-right-4 fade-in duration-300 ${style}`}
      style={{ minWidth: 280, maxWidth: 360 }}
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-bold uppercase tracking-widest opacity-80">
          {alert.severity} alert
        </p>
        <p className="mt-0.5 truncate text-sm font-semibold">{alert.label}</p>
        <p className="mt-0.5 truncate font-mono text-xs opacity-60">
          {alert.source_ip} → {alert.destination_ip}
        </p>
        {alert.attack_type && alert.attack_type !== 'normal' && (
          <span className="mt-1 inline-block rounded bg-white/10 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider">
            {alert.attack_type.replace(/_/g, ' ')}
          </span>
        )}
      </div>
      <button onClick={onDismiss} className="ml-1 shrink-0 opacity-60 hover:opacity-100">
        <X className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}

export function AlertToastContainer({ liveAlerts }: { liveAlerts: Alert[] }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const seenRef = useRef(new Set<string>());

  // Pull the user's selected severities. Re-fetch on focus so changes saved
  // in another tab show up. Falls back to the default while the request is
  // in flight or if the call fails (e.g. logged out).
  const { data: thresholds } = useQuery({
    queryKey: ['thresholds'],
    queryFn:  getThresholds,
    retry:    false,
    staleTime: 30_000,
  });

  const notifySeverities = useMemo(
    () => new Set<string>(thresholds?.alert_notification_severities ?? DEFAULT_NOTIFY_SEVERITIES),
    [thresholds],
  );

  useEffect(() => {
    liveAlerts.forEach((alert) => {
      // Use timestamp+src+dst as a stable key (no separate id field)
      const key = `${alert.timestamp}|${alert.source_ip}|${alert.destination_ip}`;
      if (!notifySeverities.has(alert.severity)) return;
      if (seenRef.current.has(key)) return;
      seenRef.current.add(key);
      setToasts((prev) => [{ id: key, alert }, ...prev].slice(0, 5));
    });
  }, [liveAlerts, notifySeverities]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <div key={t.id} className="pointer-events-auto">
          <ToastItem toast={t} onDismiss={() => dismiss(t.id)} />
        </div>
      ))}
    </div>
  );
}
