import { Fragment, useEffect, useState } from 'react';
import {
  fetchAlerts,
  patchAlertStatus,
  formatTime,
  SEVERITIES,
  type Alert,
  type AlertStatus,
  type AlertsResponse,
} from '../lib/api';
import { SkeletonStack, ErrorBox, EmptyState } from './ui';

const PAGE_SIZE = 15;
const STATUSES: Array<'' | AlertStatus> = ['', 'new', 'acknowledged', 'resolved'];

interface Filters {
  severity: string;
  status: string;
  rule_id: string;
  src_ip: string;
}

const EMPTY_FILTERS: Filters = { severity: '', status: '', rule_id: '', src_ip: '' };

interface Props {
  refreshKey: number;
  onChanged: () => void;
}

export default function AlertsTable({ refreshKey, onChanged }: Props) {
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [resp, setResp] = useState<AlertsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [updating, setUpdating] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchAlerts({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then((r) => {
        if (!cancelled) {
          setResp(r);
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
  }, [filters, page, refreshKey]);

  const setFilter = (key: keyof Filters, value: string) => {
    setFilters((f) => ({ ...f, [key]: value }));
    setPage(0);
  };

  const hasServerFilters = Object.values(filters).some((v) => v !== '');
  const query = search.trim().toLowerCase();
  const alerts: Alert[] = (resp?.alerts ?? []).filter((a) => {
    if (!query) return true;
    return [a.title, a.description, a.rule_id, a.rule_name, a.id, a.src_ip ?? '', a.host ?? '']
      .join(' ')
      .toLowerCase()
      .includes(query);
  });

  const totalPages = Math.max(1, Math.ceil((resp?.total ?? 0) / PAGE_SIZE));
  const rangeStart = resp && resp.alerts.length > 0 ? page * PAGE_SIZE + 1 : 0;
  const rangeEnd = page * PAGE_SIZE + (resp?.alerts.length ?? 0);

  const updateStatus = async (alert: Alert, status: AlertStatus) => {
    setUpdating((s) => new Set(s).add(alert.id));
    try {
      const updated = await patchAlertStatus(alert.id, status);
      setResp((r) =>
        r ? { ...r, alerts: r.alerts.map((a) => (a.id === updated.id ? updated : a)) } : r,
      );
      onChanged();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Status update failed');
    } finally {
      setUpdating((s) => {
        const next = new Set(s);
        next.delete(alert.id);
        return next;
      });
    }
  };

  const retry = () => {
    setError(null);
    setLoading(true);
    fetchAlerts({ ...filters, limit: PAGE_SIZE, offset: page * PAGE_SIZE })
      .then((r) => {
        setResp(r);
        setLoading(false);
      })
      .catch((e: unknown) => {
        setError(e instanceof Error ? e.message : 'Request failed');
        setLoading(false);
      });
  };

  return (
    <div className="card span-12">
      <h3 className="card-title">
        Alerts
        <span className="mono-sm">{resp ? `${resp.total} total` : ''}</span>
      </h3>

      <div className="filter-row">
        <select
          className="select"
          value={filters.severity}
          onChange={(e) => setFilter('severity', e.target.value)}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={filters.status}
          onChange={(e) => setFilter('status', e.target.value)}
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          {STATUSES.filter((s) => s !== '').map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <input
          className="input"
          placeholder="rule_id, e.g. brute-force"
          value={filters.rule_id}
          onChange={(e) => setFilter('rule_id', e.target.value)}
          aria-label="Filter by rule id"
        />
        <input
          className="input"
          placeholder="src_ip, e.g. 203.0.113.7"
          value={filters.src_ip}
          onChange={(e) => setFilter('src_ip', e.target.value)}
          aria-label="Filter by source IP"
        />
        <input
          className="input search"
          placeholder="Search title, description, id…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          aria-label="Search within results"
        />
        {(hasServerFilters || search) && (
          <button
            type="button"
            className="btn small"
            onClick={() => {
              setFilters(EMPTY_FILTERS);
              setSearch('');
              setPage(0);
            }}
          >
            Clear
          </button>
        )}
      </div>

      {loading ? (
        <SkeletonStack rows={6} />
      ) : error ? (
        <ErrorBox message={error} onRetry={retry} />
      ) : alerts.length === 0 ? (
        <EmptyState
          message={
            hasServerFilters || search
              ? 'No alerts match these filters.'
              : 'No alerts yet — run the lab attacks.'
          }
        />
      ) : (
        <>
          <div className="table-wrap">
            <table className="alerts">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>Rule</th>
                  <th>Source IP</th>
                  <th>Host</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <Fragment key={a.id}>
                    <tr
                      className="clickable"
                      onClick={() => setExpanded((id) => (id === a.id ? null : a.id))}
                    >
                      <td className="cell-time">{formatTime(a.timestamp)}</td>
                      <td>
                        <span className={`badge ${a.severity}`}>{a.severity}</span>
                      </td>
                      <td className="cell-title">{a.title}</td>
                      <td className="mono">{a.rule_id}</td>
                      <td className="mono">{a.src_ip ?? '—'}</td>
                      <td className="mono">{a.host ?? '—'}</td>
                      <td>
                        <span className={`badge status-${a.status}`}>{a.status}</span>
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        {a.status === 'new' && (
                          <button
                            type="button"
                            className="btn small warn"
                            disabled={updating.has(a.id)}
                            onClick={() => updateStatus(a, 'acknowledged')}
                          >
                            {updating.has(a.id) ? 'Saving…' : 'Acknowledge'}
                          </button>
                        )}
                        {a.status === 'acknowledged' && (
                          <button
                            type="button"
                            className="btn small ok"
                            disabled={updating.has(a.id)}
                            onClick={() => updateStatus(a, 'resolved')}
                          >
                            {updating.has(a.id) ? 'Saving…' : 'Resolve'}
                          </button>
                        )}
                      </td>
                    </tr>
                    {expanded === a.id && (
                      <tr>
                        <td colSpan={8}>
                          <div className="detail-panel">
                            <div className="row">
                              <span className="k">Description</span>
                              <span>{a.description}</span>
                            </div>
                            <div className="row">
                              <span className="k">MITRE ATT&CK</span>
                              <span>
                                {a.mitre?.technique_id} — {a.mitre?.technique} ({a.mitre?.tactic})
                              </span>
                            </div>
                            <div className="row">
                              <span className="k">Score</span>
                              <span>{a.score} / 100</span>
                            </div>
                            <div className="row">
                              <span className="k">Network</span>
                              <span className="mono">
                                {a.src_ip ?? '—'} → {a.dst_ip ?? '—'}
                                {a.user ? ` · user ${a.user}` : ''}
                              </span>
                            </div>
                            <div className="row">
                              <span className="k">Evidence</span>
                              <pre>{JSON.stringify(a.evidence ?? {}, null, 2)}</pre>
                            </div>
                            {Object.keys(a.intel ?? {}).length > 0 && (
                              <div className="row">
                                <span className="k">Threat intel</span>
                                <pre>{JSON.stringify(a.intel, null, 2)}</pre>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pagination">
            <span className="info">
              Showing {rangeStart}–{rangeEnd} of {resp?.total ?? 0}
              {query ? ` (search narrowed to this page)` : ''}
            </span>
            <div className="controls">
              <button
                type="button"
                className="btn small"
                disabled={page === 0 || loading}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
              >
                ← Prev
              </button>
              <span className="info">
                Page {page + 1} / {totalPages}
              </span>
              <button
                type="button"
                className="btn small"
                disabled={page + 1 >= totalPages || loading}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
