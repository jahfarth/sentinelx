import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { useApiData, fetchOverview, SEVERITY_COLORS, SEVERITIES } from '../lib/api';
import { Spinner, ErrorBox, EmptyState } from './ui';

export default function SeverityDonut({ refreshKey }: { refreshKey: number }) {
  const { data, loading, error, reload } = useApiData(fetchOverview, [refreshKey]);

  if (loading) {
    return (
      <div className="card span-4">
        <h3 className="card-title">Alerts by Severity</h3>
        <div className="chart-wrap" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Spinner />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card span-4">
        <h3 className="card-title">Alerts by Severity</h3>
        <ErrorBox message={error} onRetry={reload} />
      </div>
    );
  }

  const counts = data?.alerts_by_severity ?? {};
  const slices = SEVERITIES.map((sev) => ({
    name: sev.charAt(0).toUpperCase() + sev.slice(1),
    sev,
    value: counts[sev] ?? 0,
  })).filter((s) => s.value > 0);
  const total = slices.reduce((sum, s) => sum + s.value, 0);

  return (
    <div className="card span-4">
      <h3 className="card-title">
        Alerts by Severity
        <span className="mono-sm">{total} total</span>
      </h3>
      {slices.length === 0 ? (
        <EmptyState message="No alerts yet — run the lab attacks." />
      ) : (
        <>
          <div className="chart-wrap">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={slices} dataKey="value" nameKey="name" innerRadius={62} outerRadius={92} paddingAngle={2}>
                  {slices.map((s) => (
                    <Cell key={s.sev} fill={SEVERITY_COLORS[s.sev]} />
                  ))}
                </Pie>
                <Tooltip formatter={(value, name) => [value, name]} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="donut-legend">
            {slices.map((s) => (
              <span className="entry" key={s.sev}>
                <span className={`dot ${s.sev}`} />
                {s.name} <b>{s.value}</b>
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
