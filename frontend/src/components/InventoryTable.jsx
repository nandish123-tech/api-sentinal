import { timeAgo, riskColor } from '../utils';

const INV_FILTERS = [
  { key: 'ALL',        label: 'All' },
  { key: 'KNOWN',      label: 'Documented' },
  { key: 'SHADOW',     label: 'Shadow' },
  { key: 'DEPRECATED', label: 'Deprecated' },
];

function MethodBadge({ method }) {
  return <span className={`method-badge method-${method}`}>{method}</span>;
}

function StatusPill({ status }) {
  const cls = { known: 's-known', undocumented: 's-undocumented', deprecated: 's-deprecated' }[status] || 's-known';
  return <span className={`status-pill ${cls}`}>{status}</span>;
}

function RiskBar({ score }) {
  const color = riskColor(score);
  const pct = Math.min(score, 100);
  return (
    <div className="risk-bar-wrap">
      <div className="risk-bar">
        <div className="risk-bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
      <div className="risk-num" style={{ color }}>{score.toFixed(0)}</div>
    </div>
  );
}

export default function InventoryTable({ inventory, stats, activeFilter, onFilter }) {
  const coverage = stats?.inventory_coverage ?? 0;
  const pct = coverage.toFixed(1) + '%';

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-dot pd-cyan" />
          API Inventory
        </div>
        <span className="panel-badge">{inventory.length} routes</span>
      </div>

      {/* Filter tabs */}
      <div className="feed-tabs">
        {INV_FILTERS.map(f => (
          <button
            key={f.key}
            className={`feed-tab ${activeFilter === f.key ? 'active' : ''}`}
            onClick={() => onFilter(f.key)}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="table-wrap">
        {inventory.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">📡</div>
            <div className="empty-text">
              {activeFilter === 'ALL'
                ? 'No routes observed yet.\nTry a demo scenario above.'
                : `No ${activeFilter.toLowerCase()} routes found.`}
            </div>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Route</th>
                <th>Status</th>
                <th>Hits</th>
                <th>Risk</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {inventory.map((item, i) => (
                <tr key={`${item.method}-${item.route_template}-${i}`}>
                  <td><MethodBadge method={item.method} /></td>
                  <td><span className="route-text">{item.route_template}</span></td>
                  <td><StatusPill status={item.status} /></td>
                  <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12 }}>{item.request_count}</td>
                  <td><RiskBar score={item.risk_score_avg} /></td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {item.last_seen ? timeAgo(item.last_seen) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="coverage-section">
        <div className="coverage-label">
          <span>Contract Coverage</span>
          <span>{pct}</span>
        </div>
        <div className="coverage-track">
          <div className="coverage-fill" style={{ width: pct }} />
        </div>
      </div>
    </div>
  );
}
