/**
 * AlertToast — shows a slide-in notification whenever a high or critical
 * alert arrives over the WebSocket live feed.
 *
 * Usage: render once inside Layout, pass the latest liveAlerts array.
 * The component tracks which alert IDs it has already shown.
 */
import { AlertTriangle, X } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { Alert } from '../types';

interface Toast {
  id: string;
  alert: Alert;
}

const NOTIFY_SEVERITIES = new Set(['critical', 'high']);
const AUTO_DISMISS_MS = 6000;

const SEV_STYLE: Record<string, string> = {
  critical: 'border-red-500/60 bg-red-950/80 text-red-300',
  high:     'border-orange-500/60 bg-orange-950/80 text-orange-300',
};

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: () => void }) {
  const { alert } = toast;
  const style = SEV_STYLE[alert.severity] ?? SEV_STYLE.high;

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

  useEffect(() => {
    liveAlerts.forEach((alert) => {
      // Use timestamp+src+dst as a stable key (no separate id field)
      const key = `${alert.timestamp}|${alert.source_ip}|${alert.destination_ip}`;
      if (!NOTIFY_SEVERITIES.has(alert.severity)) return;
      if (seenRef.current.has(key)) return;
      seenRef.current.add(key);
      setToasts((prev) => [{ id: key, alert }, ...prev].slice(0, 5));
    });
  }, [liveAlerts]);

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
