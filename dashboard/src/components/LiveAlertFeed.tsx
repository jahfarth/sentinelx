import { useEffect, useState } from 'react';
import { subscribeAlerts, formatTime, SEVERITIES, type Alert, type Severity } from '../lib/api';
import { EmptyState, Spinner } from './ui';

const MAX_FEED = 25;
type SevFilter = 'all' | Severity;
const FILTERS: SevFilter[] = ['all', ...SEVERITIES];

interface Props {
  spanClass?: string;
}

export default function LiveAlertFeed({ spanClass = 'span-4' }: Props) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState<SevFilter>('all');
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    if (paused) return;
    const stop = subscribeAlerts(
      (alert) => {
        setAlerts((prev) =>
          prev.some((p) => p.id === alert.id) ? prev : [alert, ...prev].slice(0, MAX_FEED),
        );
      },
      {
        onOpen: () => setConnected(true),
        onError: () => setConnected(false),
      },
    );
    return stop;
  }, [paused]);

  const visible = filter === 'all' ? alerts : alerts.filter((a) => a.severity === filter);

  const statusLabel = paused ? 'Paused' : connected ? 'Live' : 'Reconnecting…';
  const statusClass = paused ? '' : connected ? 'ok' : 'bad';

  return (
    <div className={`card ${spanClass}`}>
      <h3 className="card-title">
        Live Alert Feed
        <span className="inline-status">
          <span className={`health-dot ${statusClass}`} />
          {statusLabel}
        </span>
      </h3>

      <div className="feed-head">
        <div className="pills">
          {FILTERS.map((f) => (
            <button
              key={f}
              type="button"
              className={`pill${filter === f ? ' active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f}
            </button>
          ))}
        </div>
        <button type="button" className="btn small" onClick={() => setPaused((p) => !p)}>
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {!connected && alerts.length === 0 ? (
        <div className="state-box">
          <Spinner />
          <p style={{ marginTop: 12 }}>Connecting to live stream…</p>
        </div>
      ) : visible.length === 0 ? (
        <EmptyState message="No alerts yet — run the lab attacks." />
      ) : (
        <div className="feed-list">
          {visible.map((a) => (
            <div className="feed-item" key={a.id}>
              <span className={`dot ${a.severity}`} style={{ marginTop: 4 }} />
              <div className="body">
                <div className="title" title={a.title}>
                  {a.title}
                </div>
                <div className="meta">
                  <span className="mono-sm">{a.mitre?.technique_id ?? '—'}</span>
                  {a.src_ip && <span className="mono-sm">{a.src_ip}</span>}
                  <span>{formatTime(a.timestamp)}</span>
                </div>
              </div>
              <span className={`badge ${a.severity}`}>{a.severity}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
