import { useState } from 'react';

const SCENARIOS = [
  { key: 'normal',     label: '✅ Legitimate Access',  sub: 'user_101 → order/101',        cls: 'btn-normal' },
  { key: 'bola',       label: '🚨 BOLA Attack',         sub: 'user_101 → billing/202',       cls: 'btn-attack' },
  { key: 'shadow',     label: '👻 Shadow API',           sub: 'GET /api/admin/debug',         cls: 'btn-shadow' },
  { key: 'enum',       label: '🔍 Enumeration',          sub: 'Scan orders 101–110',          cls: 'btn-enum' },
  { key: 'deprecated', label: '⚠️ Deprecated Route',     sub: 'GET /api/v1/legacy/orders',   cls: 'btn-deprecated' },
  { key: 'refresh',    label: '🔄 Refresh Dashboard',    sub: 'Pull latest data',             cls: 'btn-refresh' },
];

export default function DemoControls({ onDemo, onRefresh }) {
  const [loading, setLoading] = useState(false);

  async function handle(key) {
    if (loading) return;
    setLoading(true);
    try {
      if (key === 'refresh') await onRefresh();
      else await onDemo(key);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="demo-panel">
      <div className="section-label">⚡ Demo Scenarios</div>
      <div className="demo-grid">
        {SCENARIOS.map(s => (
          <button
            key={s.key}
            className={`demo-btn ${s.cls}`}
            disabled={loading}
            onClick={() => handle(s.key)}
          >
            <span className="btn-label">{s.label}</span>
            <span className="btn-sub">{s.sub}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
