import { useEffect } from 'react';
import { riskColor } from '../utils';

export default function Modal({ alert, onClose }) {
  useEffect(() => {
    function onKey(e) { if (e.key === 'Escape') onClose(); }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  function handleOverlayClick(e) {
    if (e.target === e.currentTarget) onClose();
  }

  if (!alert) return null;

  const ev = alert.evidence || {};
  const color = riskColor(alert.risk_score);

  return (
    <div
      className={`modal-overlay ${alert ? 'open' : ''}`}
      onClick={handleOverlayClick}
    >
      <div className="modal">
        <div className="modal-header">
          <div className="modal-title">
            <span className={`alert-badge ab-${alert.alert_type}`}>
              {alert.alert_type.replace('_', ' ')}
            </span>
            Alert Detail
          </div>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>

        <div className="evidence-grid">
          <div className="evidence-row">
            <div className="ev-label">Risk Score</div>
            <div className="ev-value" style={{ color, fontWeight: 700 }}>
              {alert.risk_score.toFixed(1)} / 100
            </div>
          </div>
          <div className="evidence-row">
            <div className="ev-label">Decision</div>
            <div className="ev-value">{alert.decision}</div>
          </div>
          <div className="evidence-row">
            <div className="ev-label">Principal</div>
            <div className="ev-value">{alert.principal_id}</div>
          </div>
          <div className="evidence-row">
            <div className="ev-label">Endpoint</div>
            <div className="ev-value">{alert.method} {alert.route_template}</div>
          </div>
          {alert.object_id && (
            <div className="evidence-row">
              <div className="ev-label">Object</div>
              <div className="ev-value">{alert.object_type} / {alert.object_id}</div>
            </div>
          )}
          {alert.expected_owner && (
            <div className="evidence-row">
              <div className="ev-label">Expected Owner</div>
              <div className="ev-value">{alert.expected_owner}</div>
            </div>
          )}
          {Object.entries(ev).map(([k, v]) => (
            <div key={k} className="evidence-row">
              <div className="ev-label">{k.replace(/_/g, ' ')}</div>
              <div className="ev-value">
                {typeof v === 'object' ? JSON.stringify(v) : String(v)}
              </div>
            </div>
          ))}
        </div>

        {(alert.signals?.length > 0) && (
          <div className="signals-wrap">
            {alert.signals.map(s => (
              <span key={s} className="signal-tag">{s}</span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
