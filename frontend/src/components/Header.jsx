export default function Header({ enforcement, sseConnected }) {
  return (
    <header className="header">
      <div className="logo">
        <div className="logo-mark">🛡️</div>
        <div>
          <div className="logo-text">API <span className="accent">Sentinel</span></div>
          <div className="logo-sub">Zero-Trust API Security</div>
        </div>
      </div>

      <div className="header-right">
        <span className="live-badge">
          <span className="live-dot" />
          {sseConnected ? 'Live' : 'Connecting…'}
        </span>
        <span className={`enforcement-badge ${enforcement ? 'enforcement-on' : 'enforcement-off'}`}>
          {enforcement ? 'Enforcement ON' : 'Passive Mode'}
        </span>
      </div>
    </header>
  );
}
