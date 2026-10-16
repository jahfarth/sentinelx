import { useApiData, fetchAlerts, formatTime } from '../lib/api';
import { SkeletonStack, ErrorBox, EmptyState } from './ui';

interface Props {
  refreshKey: number;
  limit?: number;
  spanClass?: string;
}

export default function AttackTimeline({ refreshKey, limit = 15, spanClass = 'span-4' }: Props) {
  const { data, loading, error, reload } = useApiData(
    () => fetchAlerts({ limit, offset: 0 }),
    [refreshKey, limit],
  );

  if (loading) {
    return (
      <div className={`card ${spanClass}`}>
        <h3 className="card-title">Latest Alerts</h3>
        <SkeletonStack rows={6} />
      </div>
    );
  }

  if (error) {
    return (
      <div className={`card ${spanClass}`}>
        <h3 className="card-title">Latest Alerts</h3>
        <ErrorBox message={error} onRetry={reload} />
      </div>
    );
  }

  const alerts = data?.alerts ?? [];

  return (
    <div className={`card ${spanClass}`}>
      <h3 className="card-title">
        Latest Alerts
        <span className="mono-sm">{alerts.length} shown</span>
      </h3>
      {alerts.length === 0 ? (
        <EmptyState message="No alerts yet — run the lab attacks." />
      ) : (
        <div className="attack-timeline">
          {alerts.map((a) => (
            <div className="tl-item" key={a.id}>
              <span className={`dot ${a.severity}`} style={{ marginTop: 4 }} />
              <div className="body">
                <div className="title">{a.title}</div>
                <div className="meta">
                  <span className="mono-sm">{a.mitre?.technique_id ?? '—'}</span>
                  <span className="mono-sm">{a.rule_id}</span>
                  {a.src_ip && <span className="mono-sm">{a.src_ip}</span>}
                </div>
              </div>
              <span className="time">{formatTime(a.timestamp)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
