import { useState } from 'react';
import { useApiSentinel } from './hooks/useApiSentinel';
import Header from './components/Header';
import DemoControls from './components/DemoControls';
import StatsGrid from './components/StatsGrid';
import InventoryTable from './components/InventoryTable';
import ThreatFeed from './components/ThreatFeed';
import Modal from './components/Modal';
import ToastContainer from './components/Toast';

export default function App() {
  const {
    stats, inventory, alerts, enforcement, sseConnected,
    toasts, runDemo, refreshAll
  } = useApiSentinel();

  const [selectedAlert, setSelectedAlert] = useState(null);
  const [feedFilter, setFeedFilter] = useState('ALL');
  const [invFilter, setInvFilter]  = useState('ALL');

  // Filter threat feed
  const filteredAlerts = alerts.filter(a => {
    if (feedFilter === 'ALL')        return true;
    if (feedFilter === 'BOLA')       return a.alert_type === 'BOLA' || a.alert_type === 'ENUMERATION';
    if (feedFilter === 'SHADOW_API') return a.alert_type === 'SHADOW_API';
    if (feedFilter === 'BLOCKED')    return a.decision === 'BLOCK';
    if (feedFilter === 'DEPRECATED') return a.alert_type === 'DEPRECATED';
    return true;
  });

  // Filter inventory
  const filteredInventory = inventory.filter(i => {
    if (invFilter === 'ALL')         return true;
    if (invFilter === 'KNOWN')       return i.status === 'known';
    if (invFilter === 'SHADOW')      return i.status === 'undocumented';
    if (invFilter === 'DEPRECATED')  return i.status === 'deprecated';
    return true;
  });

  return (
    <>
      {/* Animated background */}
      <div className="bg-canvas">
        <div className="bg-orb bg-orb-1" />
        <div className="bg-orb bg-orb-2" />
        <div className="bg-orb bg-orb-3" />
        <div className="bg-orb bg-orb-4" />
      </div>
      <div className="bg-grid" />

      <div className="layout">
        <Header enforcement={enforcement} sseConnected={sseConnected} />

        <main className="main">
          <DemoControls onDemo={runDemo} onRefresh={refreshAll} />

          {/* Clickable stat cards — pass alerts for drawer */}
          <StatsGrid stats={stats} alerts={alerts} />

          <div className="content-grid">
            {/* Inventory with filter tabs */}
            <InventoryTable
              inventory={filteredInventory}
              stats={stats}
              activeFilter={invFilter}
              onFilter={setInvFilter}
            />

            {/* Threat feed with filter tabs */}
            <ThreatFeed
              alerts={filteredAlerts}
              allAlerts={alerts}
              activeFilter={feedFilter}
              onFilter={setFeedFilter}
              onSelect={setSelectedAlert}
            />
          </div>
        </main>
      </div>

      {/* Detail Modal */}
      {selectedAlert && (
        <Modal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}

      {/* Toasts */}
      <ToastContainer toasts={toasts} />
    </>
  );
}
