import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { useApiData, fetchTimeline, formatBucketTime } from '../lib/api';
import { Spinner, ErrorBox, EmptyState } from './ui';

interface Props {
  refreshKey: number;
  hours?: number;
  spanClass?: string;
}

export default function TimelineChart({ refreshKey, hours = 24, spanClass = 'span-8' }: Props) {
  const { data, loading, error, reload } = useApiData(() => fetchTimeline(hours), [refreshKey, hours]);

  if (loading) {
    return (
      <div className={`card ${spanClass}`}>
        <h3 className="card-title">Event &amp; Critical Timeline</h3>
        <div className="chart-wrap" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Spinner />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`card ${spanClass}`}>
        <h3 className="card-title">Event &amp; Critical Timeline</h3>
        <ErrorBox message={error} onRetry={reload} />
      </div>
    );
  }

  const buckets = data?.buckets ?? [];
  const hasData = buckets.some((b) => b.count > 0 || b.critical > 0);

  return (
    <div className={`card ${spanClass}`}>
      <h3 className="card-title">
        Event &amp; Critical Timeline
        <span className="mono-sm">last {hours}h</span>
      </h3>
      {!hasData ? (
        <EmptyState message="No events in this window — ingest logs or run the lab attacks." />
      ) : (
        <div className="chart-wrap">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={buckets} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#22304a" />
              <XAxis
                dataKey="ts"
                tickFormatter={(v: string) => formatBucketTime(v)}
                tick={{ fill: '#8b98b0', fontSize: 11 }}
                minTickGap={48}
              />
              <YAxis tick={{ fill: '#8b98b0', fontSize: 11 }} allowDecimals={false} />
              <Tooltip
                labelFormatter={(v: string) => formatBucketTime(v)}
                formatter={(value, name) => [value, name]}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Area
                type="monotone"
                dataKey="count"
                name="Events"
                stroke="#38bdf8"
                fill="rgba(56, 189, 248, 0.18)"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="critical"
                name="Critical alerts"
                stroke="#ef4444"
                fill="rgba(239, 68, 68, 0.22)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}
