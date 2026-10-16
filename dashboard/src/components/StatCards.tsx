import { useApiData, fetchOverview } from '../lib/api';
import { Skeleton, ErrorBox, EmptyState } from './ui';

export default function StatCards({ refreshKey }: { refreshKey: number }) {
  const { data, loading, error, reload } = useApiData(fetchOverview, [refreshKey]);

  if (loading) {
    return (
      <div className="grid">
        {[0, 1, 2, 3].map((i) => (
          <div className="card span-3" key={i}>
            <Skeleton height={12} width="55%" />
            <div style={{ marginTop: 12 }}>
              <Skeleton height={32} width="40%" />
            </div>
            <div style={{ marginTop: 8 }}>
              <Skeleton height={12} width="80%" />
            </div>
          </div>
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="card span-12">
        <ErrorBox message={error} onRetry={reload} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="card span-12">
        <EmptyState message="No stats yet — ingest some logs to see counters." />
      </div>
    );
  }

  const top = data.top_attackers?.[0];

  const cards = [
    { label: 'Total Events', value: data.total_events.toLocaleString(), sub: 'events normalized & stored' },
    { label: 'Alerts (24h)', value: data.total_alerts_24h.toLocaleString(), sub: 'detection engine hits' },
    { label: 'Critical (24h)', value: data.critical_24h.toLocaleString(), sub: 'critical-severity alerts' },
    {
      label: 'Top Attacker',
      value: top ? top.count.toLocaleString() : '—',
      sub: top ? `${top.ip} alerts in 24h` : 'no attackers yet',
    },
  ];

  return (
    <div className="grid">
      {cards.map((c) => (
        <div className="card span-3" key={c.label}>
          <div className="card-title">{c.label}</div>
          <div className="stat-value">{c.value}</div>
          <div className="stat-sub">{c.sub}</div>
        </div>
      ))}
    </div>
  );
}
