import { useCallback, useEffect, useRef, useState } from 'react';
import type { Alert } from '../types';

const WS_PATH = '/api/v1/ws/alerts';
const MAX_BUFFERED = 500;
const RETRY_MS = 5000; // wait 5 s before reconnecting (reduces noise when backend is offline)

function wsUrl(): string {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${window.location.host}${WS_PATH}`;
}

export function useAlertsWebSocket() {
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const unmountedRef = useRef(false);

  const connect = useCallback(() => {
    if (unmountedRef.current) return;
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    let ws: WebSocket;
    try {
      ws = new WebSocket(wsUrl());
    } catch {
      retryRef.current = setTimeout(connect, RETRY_MS);
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => {
      if (!unmountedRef.current) setConnected(true);
    };

    ws.onmessage = (ev) => {
      if (unmountedRef.current) return;
      try {
        const alert: Alert = JSON.parse(ev.data as string);
        setLiveAlerts((prev) => {
          const next = [alert, ...prev];
          return next.length > MAX_BUFFERED ? next.slice(0, MAX_BUFFERED) : next;
        });
      } catch {
        // ignore malformed frames
      }
    };

    ws.onclose = () => {
      if (!unmountedRef.current) {
        setConnected(false);
        retryRef.current = setTimeout(connect, RETRY_MS);
      }
    };

    // onerror fires before onclose — let onclose handle the retry
    ws.onerror = () => {};
  }, []);

  useEffect(() => {
    unmountedRef.current = false;
    connect();
    return () => {
      unmountedRef.current = true;
      retryRef.current && clearTimeout(retryRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const clear = useCallback(() => setLiveAlerts([]), []);

  return { liveAlerts, connected, clear };
}
