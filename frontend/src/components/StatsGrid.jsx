import { useState, useEffect, useRef } from 'react';
import { timeAgo, riskColor, riskClass } from '../utils';

/* ── Animated counter ─────────────────────────────────────────────── */
function AnimatedNumber({ value }) {
  const elRef = useRef(null);
  const prevRef = useRef(0);
  useEffect(() => {
    if (value == null) return;
    const el = elRef.current;
    if (!el) return;
    const to = typeof value === 'number' ? value : parseFloat(value) || 0;
    const from = prevRef.current;
    prevRef.current = to;
    if (to === from) { el.textContent = to; return; }
    const steps = 28, stepVal = (to - from) / steps;
    let cur = from, i = 0;
    const t = setInterval(() => {
      cur += stepVal; i++;
      el.textContent = Math.round(cur);
      if (i >= steps) { el.textContent = to; clearInterval(t); }
    }, 16);
    return () => clearInterval(t);
  }, [value]);
  return <span ref={elRef}>{value ?? '—'}</span>;
}

/* ── History Drawer ───────────────────────────────────────────────── */
function HistoryDrawer({ card, alerts, onClose }) {
  const filtered = alerts.filter(a => {
    if (!card) return false;
    if (card.filter === 'BOLA')       return a.alert_type === 'BOLA' || a.alert_type === 'ENUMERATION';
    if (card.filter === 'SHADOW_API') return a.alert_type === 'SHADOW_API';
    if (card.filter === 'BLOCKED')    return a.decision === 'BLOCK';
    if (card.filter === 'ALL')        return true;
    return true;
  });

  useEffect(() => {
    const onKey = e => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className={`drawer-overlay ${card ? 'open' : ''}`} onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="drawer">
        {/* Header */}
        <div className="drawer-header" style={{ borderColor: card?.color }}>
          <div className="drawer-title">
            <span className="drawer-icon">{card?.icon}</span>
            <div>
              <div className="drawer-name">{card?.label} History</div>
              <div className="drawer-sub">{filtered.length} records found</div>
            </div>
          </div>
          <button className="drawer-close" onClick={onClose}>✕</button>
        </div>

        {/* Stats summary bar */}
        <div className="drawer-summary">
          {['BLOCK', 'ALERT', 'ALLOW'].map(dec => {
            const count = filtered.filter(a => a.decision === dec).length;
            return (
              <div key={dec} className={`dsummary-pill dsummary-${dec}`}>
                <span className="dsummary-num">{count}</span>
                <span className="dsummary-label">{dec}</span>
              </div>
            );
          })}
        </div>

        {/* List */}
        <div className="drawer-list">
          {filtered.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">🔒</div>
              <div className="empty-text">No {card?.label} events yet.<br />Trigger a demo scenario.</div>
            </div>
          ) : (
            filtered.map((a, i) => (
              <div key={a.id ?? i} className="drawer-item">
                <div className="di-top">
                  <span className={`alert-badge ab-${a.alert_type}`}>{a.alert_type.replace('_', ' ')}</span>
                  <div className="di-right">
                    <span className={`di-decision di-dec-${a.decision}`}>{a.decision}</span>
                    <span className={`feed-score ${riskClass(a.risk_score)}`} style={{ fontSize: 13 }}>
                      {a.risk_score.toFixed(0)}
                    </span>
                  </div>
                </div>
                <div className="di-route">{a.method} {a.route_template}</div>
                <div className="di-meta">
                  <span>👤 {a.principal_id}</span>
                  {a.object_id && <span> → {a.object_type}:{a.object_id}</span>}
                  {a.evidence?.client_ip && <span className="di-ip">🌐 {a.evidence.client_ip}</span>}
                </div>
                <div className="di-signals">
                  {(a.signals || []).map(s => (
                    <span key={s} className="signal-tag" style={{ fontSize: 9 }}>{s}</span>
                  ))}
                </div>
                <div className="di-time">{timeAgo(a.timestamp)}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Card config ──────────────────────────────────────────────────── */
const CARDS = [
  {
    key: 'total_events', label: 'Total Intercepted', icon: '📡',
    color: '#38bdf8', valClass: 'val-cyan',
    sub: s => `${(s?.events_per_minute ?? 0).toFixed(1)} req/min`,
    filter: 'ALL', clickable: true,
    hint: 'Click to view all events',
  },
  {
    key: 'bola_alerts', label: 'BOLA / IDOR Alerts', icon: '🚨',
    color: '#f87171', valClass: 'val-red',
    sub: () => 'ownership violations',
    filter: 'BOLA', clickable: true,
    hint: 'Click to view BOLA history',
  },
  {
    key: 'shadow_apis', label: 'Shadow APIs Found', icon: '👻',
    color: '#fbbf24', valClass: 'val-amber',
    sub: () => 'undocumented routes',
    filter: 'SHADOW_API', clickable: true,
    hint: 'Click to view shadow API alerts',
  },
  {
    key: 'blocked_requests', label: 'Blocked Attacks', icon: '🛑',
    color: '#fb7185', valClass: 'val-red',
    sub: () => 'HTTP 403 responses',
    filter: 'BLOCKED', clickable: true,
    hint: 'Click to view blocked requests',
  },
  {
    key: 'inventory_coverage', label: 'API Coverage', icon: '📋',
    color: '#34d399', valClass: 'val-green',
    sub: () => 'of declared routes seen',
    pct: true, clickable: false,
    hint: null,
  },
  {
    key: 'total_alerts', label: 'Total Alerts', icon: '⚠️',
    color: '#a78bfa', valClass: 'val-purple',
    sub: () => 'across all types',
    filter: 'ALL', clickable: true,
    hint: 'Click to view all alerts',
  },
];

/* ── Main Component ───────────────────────────────────────────────── */
export default function StatsGrid({ stats, alerts }) {
  const [activeCard, setActiveCard] = useState(null);

  function handleCardClick(card) {
    if (!card.clickable) return;
    setActiveCard(prev => prev?.key === card.key ? null : card);
  }

  return (
    <>
      <div className="stats-grid" style={{ marginBottom: 28 }}>
        {CARDS.map(card => {
          const raw = stats?.[card.key];
          const numVal = raw != null ? (typeof raw === 'number' ? raw : parseFloat(raw) || 0) : null;
          const isActive = activeCard?.key === card.key;

          return (
            <div
              key={card.key}
              className={`stat-card2 ${card.clickable ? 'clickable' : ''} ${isActive ? 'active' : ''}`}
              style={{ '--card-color': card.color }}
              onClick={() => handleCardClick(card)}
              title={card.hint || ''}
            >
              {/* Top row */}
              <div className="sc2-top">
                <div className="sc2-label">{card.label}</div>
                <span className="sc2-icon">{card.icon}</span>
              </div>

              {/* Value */}
              <div className={`sc2-value ${card.valClass}`}>
                {numVal != null ? <AnimatedNumber value={numVal} /> : '—'}
                {card.pct && numVal != null ? '%' : ''}
              </div>

              {/* Sub */}
              <div className="sc2-bottom">
                <div className="sc2-sub">{stats ? card.sub(stats) : '…'}</div>
              </div>

              {/* Active indicator */}
              {isActive && <div className="sc2-active-bar" style={{ background: card.color }} />}

              {/* Corner glow */}
              <div className="sc2-glow" style={{ background: card.color }} />
            </div>
          );
        })}
      </div>

      {/* History Drawer */}
      <HistoryDrawer
        card={activeCard}
        alerts={alerts}
        onClose={() => setActiveCard(null)}
      />
    </>
  );
}
