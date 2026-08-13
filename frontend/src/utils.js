// Utility helpers
export function fmt(dt) {
  if (!dt) return '—';
  return new Date(dt).toLocaleTimeString('en-GB', { hour12: false });
}

export function timeAgo(dt) {
  if (!dt) return '';
  const diff = Math.floor((Date.now() - new Date(dt)) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export function riskColor(score) {
  if (score >= 80) return '#fb7185';
  if (score >= 60) return '#f87171';
  if (score >= 35) return '#fbbf24';
  return '#5a6a82';
}

export function riskClass(score) {
  if (score >= 80) return 'score-critical';
  if (score >= 60) return 'score-high';
  if (score >= 35) return 'score-medium';
  return 'score-low';
}

export function severityLabel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 35) return 'MEDIUM';
  return 'LOW';
}

export async function apiCall(url, headers = {}, method = 'GET', body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json', ...headers } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  return { status: r.status, data: await r.json().catch(() => ({})) };
}
