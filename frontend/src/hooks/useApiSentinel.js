import { useState, useEffect, useRef, useCallback } from 'react';

const BASE = import.meta.env.VITE_API_URL || '';

export function useApiSentinel() {
  const [stats, setStats] = useState(null);
  const [inventory, setInventory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [enforcement, setEnforcement] = useState(true);
  const [sseConnected, setSseConnected] = useState(false);
  const [toasts, setToasts] = useState([]);
  const sseRef = useRef(null);

  const addToast = useCallback((msg, type = 'info') => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 3800);
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const r = await fetch(`${BASE}/api/v1/stats`);
      if (!r.ok) return;
      const s = await r.json();
      setStats(s);
    } catch (e) { console.error('stats', e); }
  }, []);

  const loadInventory = useCallback(async () => {
    try {
      const r = await fetch(`${BASE}/api/v1/inventory`);
      if (!r.ok) return;
      const items = await r.json();
      const order = { undocumented: 0, deprecated: 1, known: 2 };
      items.sort((a, b) =>
        (order[a.status] - order[b.status]) || (b.risk_score_avg - a.risk_score_avg)
      );
      setInventory(items);
    } catch (e) { console.error('inventory', e); }
  }, []);

  const loadAlerts = useCallback(async () => {
    try {
      const r = await fetch(`${BASE}/api/v1/alerts?limit=50`);
      if (!r.ok) return;
      const data = await r.json();
      setAlerts(data);
    } catch (e) { console.error('alerts', e); }
  }, []);

  const checkHealth = useCallback(async () => {
    try {
      const r = await fetch(`${BASE}/health`);
      const h = await r.json();
      setEnforcement(!!h.enforcement);
    } catch (_) {}
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadStats(), loadInventory(), loadAlerts()]);
  }, [loadStats, loadInventory, loadAlerts]);

  const connectSSE = useCallback(() => {
    if (sseRef.current) sseRef.current.close();

    const source = new EventSource(`${BASE}/api/v1/stream`);
    sseRef.current = source;

    source.addEventListener('alert', e => {
      const alert = JSON.parse(e.data);
      setAlerts(prev => {
        const next = [alert, ...prev].slice(0, 50);
        return next;
      });
      addToast(
        `🚨 ${alert.alert_type.replace('_', ' ')} — ${alert.route_template} [${alert.risk_score.toFixed(0)}]`,
        'error'
      );
      loadStats();
      loadInventory();
    });

    source.addEventListener('heartbeat', () => { });

    source.onopen = () => setSseConnected(true);
    source.onerror = () => {
      setSseConnected(false);
      source.close();
      setTimeout(connectSSE, 3000);
    };
  }, [addToast, loadStats, loadInventory]);

  const runDemo = useCallback(async (scenario) => {
    try {
      const headers = { 'X-User-ID': '101' };

      if (scenario === 'normal') {
        const r = await fetch(`${BASE}/api/orders/101`, { headers });
        addToast(`✅ Legitimate access → HTTP ${r.status}`, r.status === 200 ? 'success' : 'warn');

      } else if (scenario === 'bola') {
        const r = await fetch(`${BASE}/api/billing/202`, { headers });
        const data = await r.json().catch(() => ({}));
        if (r.status === 403) {
          addToast(`🚨 BOLA blocked! HTTP 403 — ${data.reason || 'unauthorized'}`, 'error');
        } else {
          addToast('⚠️ Request passed (enforcement off) — check alerts', 'warn');
        }

      } else if (scenario === 'shadow') {
        const r = await fetch(`${BASE}/api/admin/debug`, { headers });
        addToast(`👻 Shadow API triggered — HTTP ${r.status} (check feed)`, 'info');

      } else if (scenario === 'enum') {
        addToast('🔍 Starting enumeration scan (orders 101–110)…', 'warn');
        for (let i = 101; i <= 110; i++) {
          await fetch(`${BASE}/api/orders/${i}`, { headers });
          await new Promise(res => setTimeout(res, 120));
        }
        addToast('🔍 Enumeration complete — check threat feed', 'warn');

      } else if (scenario === 'deprecated') {
        const r = await fetch(`${BASE}/api/v1/legacy/orders`, { headers });
        addToast(`⚠️ Deprecated route accessed — HTTP ${r.status}`, 'info');
      }
    } catch (err) {
      addToast(`Error: ${err.message}`, 'error');
    }
    setTimeout(refreshAll, 800);
  }, [addToast, refreshAll]);

  // Init
  useEffect(() => {
    checkHealth();
    connectSSE();
    refreshAll();
    const s1 = setInterval(loadStats, 10_000);
    const s2 = setInterval(loadInventory, 15_000);
    return () => {
      clearInterval(s1);
      clearInterval(s2);
      if (sseRef.current) sseRef.current.close();
    };
  }, []);

  return {
    stats, inventory, alerts, enforcement, sseConnected,
    toasts, runDemo, refreshAll
  };
}
