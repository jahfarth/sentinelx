import { useApiData, fetchOverview } from '../lib/api';
import { SkeletonStack, ErrorBox, EmptyState } from './ui';

interface Props {
  refreshKey: number;
  spanClass?: string;
}

export default function TopAttackers({ refreshKey, spanClass = 'span-4' }: Props) {
  const { data, loading, error, reload } = useApiData(fetchOverview, [refreshKey]);

  if (loading) {
    return (
      <div className={`card ${spanClass}`}>
        <h3 className="card-title">Top Attackers</h3>
        <SkeletonStack rows={5} />
      </div>
    );
  }

  if (error) {
    return (
      <div className={`card ${spanClass}`}>
        <h3 className="card-title">Top Attackers</h3>
        <ErrorBox message={error} onRetry={reload} />
      </div>
    );
  }

  const attackers = data?.top_attackers ?? [];
  const max = Math.max(1, ...attackers.map((a) => a.count));

  return (
    <div className={`card ${spanClass}`}>
      <h3 className="card-title">
        Top Attackers
        <span className="mono-sm">by alert volume</span>
      </h3>
      {attackers.length === 0 ? (
        <EmptyState message="No attacker data yet — run the lab attacks." />
      ) : (
        <div className="bar-list">
          {attackers.map((a) => (
            <div className="bar-row" key={a.ip}>
              <span className="ip" title={a.ip}>
                {a.ip}
              </span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${(a.count / max) * 100}%` }} />
              </div>
              <span className="count">{a.count} alerts</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
