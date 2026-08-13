import { timeAgo, riskColor, riskClass } from '../utils';

const FEED_FILTERS = [
  { key: 'ALL',        label: 'All' },
  { key: 'BOLA',       label: 'BOLA' },
  { key: 'SHADOW_API', label: 'Shadow' },
  { key: 'BLOCKED',    label: 'Blocked' },
  { key: 'DEPRECATED', label: 'Deprecated' },
];

function AlertBadge({ type }) {
  return <span className={`alert-badge ab-${type}`}>{type.replace('_', ' ')}</span>;
}

function SeverityBadge({ score }) {
  let sev = 'LOW';
  if (score >= 80) sev = 'CRITICAL';
  else if (score >= 60) sev = 'HIGH';
  else if (score >= 35) sev = 'MEDIUM';
  return <span className={`sev-badge sev-${sev}`}>{sev}</span>;
}

export default function ThreatFeed({ alerts, allAlerts, activeFilter, onFilter, onSelect }) {
  const total = allAlerts?.length ?? alerts.length;

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <span className="panel-dot pd-red" />
          Live Threat Feed
        </div>
        <span className="panel-badge">{total} total</span>
      </div>

      {/* Filter tabs */}
      <div className="feed-tabs">
        {FEED_FILTERS.map(f => (
          <button
            key={f.key}
            className={`feed-tab ${activeFilter === f.key ? 'active' : ''}`}
            onClick={() => onFilter(f.key)}
          >
            {f.label}
            {f.key !== 'ALL' && allAlerts && (
              <span className="feed-tab-count">
                {allAlerts.filter(a => {
                  if (f.key === 'BOLA')       return a.alert_type === 'BOLA' || a.alert_type === 'ENUMERATION';
                  if (f.key === 'SHADOW_API') return a.alert_type === 'SHADOW_API';
                  if (f.key === 'BLOCKED')    return a.decision === 'BLOCK';
                  if (f.key === 'DEPRECATED') return a.alert_type === 'DEPRECATED';
                  return false;
                }).length}
              </span>
            )}
          </button>
        ))}
      </div>

      <div className="feed-list">
        {alerts.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔒</div>
            <div className="empty-text">
              {activeFilter === 'ALL'
                ? 'No threats yet.\nTry a demo scenario above.'
                : `No ${activeFilter.replace('_', ' ')} alerts yet.`}
            </div>
          </div>
        ) : (
          alerts.map((a, i) => (
            <div
              key={a.id ?? `${a.timestamp}-${i}`}
              className="feed-item"
              onClick={() => onSelect(a)}
            >
              <div className="feed-top">
                <AlertBadge type={a.alert_type} />
                <div className="feed-right">
                  <SeverityBadge score={a.risk_score} />
                  <span className={`feed-score ${riskClass(a.risk_score)}`}>
                    {a.risk_score.toFixed(0)}
                  </span>
                </div>
              </div>
              <div className="feed-route">{a.method} {a.route_template}</div>
              <div className="feed-meta">
                👤 {a.principal_id}
                {a.object_id ? ` → ${a.object_type}:${a.object_id}` : ''}
                {a.evidence?.client_ip && a.evidence.client_ip !== '127.0.0.1' && (
                  <span style={{ marginLeft: 6, color: 'var(--cyan)', fontSize: 10 }}>
                    🌐 {a.evidence.client_ip}
                  </span>
                )}
              </div>
              <div className="feed-bottom-row">
                <div className="feed-signals">
                  {(a.signals || []).slice(0, 2).map(s => (
                    <span key={s} className="mini-signal">{s.replace(/_/g, ' ')}</span>
                  ))}
                </div>
                <span className={`feed-dec feed-dec-${a.decision}`}>{a.decision}</span>
              </div>
              <div className="feed-time">{timeAgo(a.timestamp)}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
