import { useCallback, useEffect, useState } from 'react';
import { checkHealth } from './lib/api';
import StatCards from './components/StatCards';
import SeverityDonut from './components/SeverityDonut';
import TimelineChart from './components/TimelineChart';
import LiveAlertFeed from './components/LiveAlertFeed';
import AlertsTable from './components/AlertsTable';
import AttackersMap from './components/AttackersMap';
import AttackTimeline from './components/AttackTimeline';
import TopAttackers from './components/TopAttackers';

type Tab = 'overview' | 'alerts' | 'attackers' | 'timeline';

const TABS: Array<{ id: Tab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'attackers', label: 'Attackers' },
  { id: 'timeline', label: 'Timeline' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('overview');
  const [healthy, setHealthy] = useState<boolean | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const pollHealth = useCallback(async () => {
    setHealthy(await checkHealth());
  }, []);

  useEffect(() => {
    pollHealth();
    const timer = window.setInterval(pollHealth, 30_000);
    return () => window.clearInterval(timer);
  }, [pollHealth]);

  const refresh = useCallback(() => setRefreshKey((k) => k + 1), []);

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <span className="logo" aria-hidden="true">
            🛡
          </span>
          <span>
            SentinelX
            <small>SOC Dashboard</small>
          </span>
        </div>

        <nav className="tabs" aria-label="Dashboard sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              className={`tab${tab === t.id ? ' active' : ''}`}
              onClick={() => setTab(t.id)}
              aria-current={tab === t.id ? 'page' : undefined}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <div className="header-right">
          <button type="button" className="btn small" onClick={refresh} title="Refresh all panels">
            ⟳ Refresh
          </button>
          <span className="health" title="Backend liveness (polled every 30s)">
            <span className={`health-dot ${healthy === null ? '' : healthy ? 'ok' : 'bad'}`} />
            {healthy === null ? 'Checking API…' : healthy ? 'API online' : 'API offline'}
          </span>
        </div>
      </header>

      <main className="main">
        {tab === 'overview' && (
          <div className="grid">
            <StatCards refreshKey={refreshKey} />
            <SeverityDonut refreshKey={refreshKey} />
            <TimelineChart refreshKey={refreshKey} />
            <TopAttackers refreshKey={refreshKey} />
            <AttackTimeline refreshKey={refreshKey} />
            <LiveAlertFeed />
          </div>
        )}

        {tab === 'alerts' && (
          <div className="grid">
            <AlertsTable refreshKey={refreshKey} onChanged={refresh} />
          </div>
        )}

        {tab === 'attackers' && (
          <div className="grid">
            <AttackersMap refreshKey={refreshKey} />
            <TopAttackers refreshKey={refreshKey} spanClass="span-12" />
          </div>
        )}

        {tab === 'timeline' && (
          <div className="grid">
            <TimelineChart refreshKey={refreshKey} hours={24} spanClass="span-12" />
            <AttackTimeline refreshKey={refreshKey} limit={20} spanClass="span-6" />
            <LiveAlertFeed spanClass="span-6" />
          </div>
        )}
      </main>

      <footer className="footer">
        SentinelX mini-SOC dashboard · data served live by the SentinelX API
      </footer>
    </div>
  );
}
