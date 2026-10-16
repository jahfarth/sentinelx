import { useEffect, useState } from 'react';

/* ------------------------------------------------------------------ */
/* Types (mirror docs/11-api-reference.md)                             */
/* ------------------------------------------------------------------ */

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type AlertStatus = 'new' | 'acknowledged' | 'resolved';

export interface AlertMitre {
  tactic: string;
  technique_id: string;
  technique: string;
}

export interface Alert {
  id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  title: string;
  description: string;
  severity: Severity;
  score: number;
  mitre: AlertMitre;
  src_ip: string | null;
  dst_ip: string | null;
  host: string | null;
  user: string | null;
  evidence: Record<string, unknown>;
  intel: Record<string, unknown>;
  status: AlertStatus;
}

export interface AlertsResponse {
  total: number;
  alerts: Alert[];
}

export interface TopAttacker {
  ip: string;
  count: number;
}

export interface StatsOverview {
  total_events: number;
  total_alerts_24h: number;
  critical_24h: number;
  top_attackers: TopAttacker[];
  alerts_by_severity: Record<string, number>;
}

export interface TimelineBucket {
  ts: string;
  count: number;
  critical: number;
}

export interface TimelineResponse {
  buckets: TimelineBucket[];
}

export interface Attacker {
  ip: string;
  alerts: number;
  country: string;
  lat: number;
  lon: number;
}

export interface AttackersResponse {
  attackers: Attacker[];
}

/* ------------------------------------------------------------------ */
/* Base URL                                                            */
/* ------------------------------------------------------------------ */

const RAW_BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? '';
/** Same-origin '/api' by default; override with VITE_API_URL. */
export const API_BASE = RAW_BASE ? RAW_BASE.replace(/\/+$/, '') : '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  });
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${res.statusText || 'request failed'}`);
  }
  return (await res.json()) as T;
}

/* ------------------------------------------------------------------ */
/* Endpoints                                                           */
/* ------------------------------------------------------------------ */

export interface AlertFilters {
  severity?: string;
  status?: string;
  rule_id?: string;
  src_ip?: string;
  limit?: number;
  offset?: number;
}

export function fetchAlerts(filters: AlertFilters = {}): Promise<AlertsResponse> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== '') {
      params.set(key, String(value));
    }
  }
  const query = params.toString();
  return request<AlertsResponse>(`/v1/alerts${query ? `?${query}` : ''}`);
}

export function fetchAlert(id: string): Promise<Alert> {
  return request<Alert>(`/v1/alerts/${encodeURIComponent(id)}`);
}

export function patchAlertStatus(id: string, status: AlertStatus): Promise<Alert> {
  return request<Alert>(`/v1/alerts/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
}

export function fetchOverview(): Promise<StatsOverview> {
  return request<StatsOverview>('/v1/stats/overview');
}

export function fetchTimeline(hours = 24): Promise<TimelineResponse> {
  return request<TimelineResponse>(`/v1/stats/timeline?hours=${hours}`);
}

export function fetchAttackers(limit = 20): Promise<AttackersResponse> {
  return request<AttackersResponse>(`/v1/attackers?limit=${limit}`);
}

/** Liveness probe. /healthz sits at the API root, not under /api. */
export async function checkHealth(): Promise<boolean> {
  try {
    const root = API_BASE === '/api' ? '' : API_BASE;
    const res = await fetch(`${root}/healthz`, { cache: 'no-store' });
    return res.ok;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* SSE stream of new alerts, with automatic reconnect                   */
/* ------------------------------------------------------------------ */

export interface StreamCallbacks {
  onOpen?: () => void;
  onError?: () => void;
}

export function subscribeAlerts(
  onAlert: (alert: Alert) => void,
  callbacks: StreamCallbacks = {},
): () => void {
  let stopped = false;
  let source: EventSource | null = null;
  let retryTimer: number | undefined;

  const connect = () => {
    if (stopped) return;
    source = new EventSource(`${API_BASE}/v1/stream`);
    source.onopen = () => callbacks.onOpen?.();
    source.onmessage = (ev: MessageEvent) => {
      try {
        const alert = JSON.parse(ev.data as string) as Alert;
        if (alert && typeof alert.id === 'string') {
          onAlert(alert);
        }
      } catch {
        // Ignore malformed SSE payloads.
      }
    };
    source.onerror = () => {
      callbacks.onError?.();
      source?.close();
      source = null;
      if (!stopped) {
        retryTimer = window.setTimeout(connect, 3000);
      }
    };
  };

  connect();

  return () => {
    stopped = true;
    source?.close();
    if (retryTimer !== undefined) {
      window.clearTimeout(retryTimer);
    }
  };
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
};

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];

export function formatTime(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

export function formatBucketTime(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

/* ------------------------------------------------------------------ */
/* Data-fetching hook with loading / error / retry                      */
/* ------------------------------------------------------------------ */

export interface ApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  reload: () => void;
}

export function useApiData<T>(fetcher: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetcher()
      .then((d) => {
        if (!cancelled) {
          setData(d);
          setLoading(false);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : 'Request failed');
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
    // fetcher is intentionally not a dep: callers pass stable fetchers or
    // explicit deps; nonce drives manual reloads.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);

  return { data, loading, error, reload: () => setNonce((n) => n + 1) };
}
