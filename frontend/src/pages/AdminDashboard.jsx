import { useState, useEffect } from 'react';
import { Routes, Route, useNavigate, Navigate, useLocation } from 'react-router-dom';
import useStore from '../store/useStore';

import AlertFeed from '../components/AlertFeed';
import UserRiskTable from '../components/UserRiskTable';
import PQCLog from '../components/PQCLog';
import RiskChart from '../components/RiskChart';

const AdminDashboard = () => {
  const { user, token, logout, alerts, activityEvents, connectWebSocket } = useStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [threatBanner, setThreatBanner] = useState(null);

  // Connect WebSocket on mount — persists across page navigation
  useEffect(() => {
    if (token) {
      connectWebSocket(token, 'admin', user?.id);
      if ('Notification' in window) Notification.requestPermission();

      // Fetch persisted alerts from DB on page load
      const API_URL = import.meta.env.VITE_API_URL || '';
      fetch(`${API_URL}/api/alerts/`, {
        headers: { 'Authorization': `Bearer ${token}` }
      })
        .then(r => r.ok ? r.json() : [])
        .then(dbAlerts => {
          if (dbAlerts.length > 0) {
            const { alerts: existingAlerts, setAlerts } = useStore.getState();
            const existingIds = new Set(existingAlerts.map(a => a.alert_id || a.id));
            const newAlerts = dbAlerts
              .filter(a => !existingIds.has(a.id))
              .map(a => ({
                event: a.type === 'baseline_breach' ? 'baseline_breach' : a.type === 'threat' ? 'threat_alert' : 'watch_alert',
                alert_id: a.id,
                user: a.user_name,
                user_id: a.user_id,
                risk_score: a.risk_score,
                message: a.message,
                type: a.type,
                resolved: a.resolved,
                timestamp: a.created_at,
                pqc: { sig_seed: a.id.length * 31415, enc_seed: a.id.length * 27182 },
              }));
            if (newAlerts.length > 0) {
              setAlerts([...newAlerts, ...existingAlerts]);
            }
          }
        })
        .catch(() => {});
    }
  }, [token]);

  // Watch for new threat alerts to show the banner
  const lastAlert = alerts[0];
  useEffect(() => {
    if (lastAlert && (lastAlert.event === 'threat_alert') && lastAlert.risk_score >= 99) {
      setThreatBanner(lastAlert);
      const t = setTimeout(() => setThreatBanner(null), 10000);
      return () => clearTimeout(t);
    }
  }, [lastAlert?.alert_id]);

  const handleLogout = () => { logout(); navigate('/login'); };

  const navItems = [
    { path: 'overview', icon: '📊', label: 'Overview' },
    { path: 'live',     icon: '🔴', label: 'Live Activity', badge: true },
    { path: 'alerts',   icon: '🔔', label: 'Alert Feed' },
    { path: 'users',    icon: '👥', label: 'User Monitor' },
    { path: 'pqc',      icon: '🔐', label: 'PQC Log' },
    { path: 'charts',   icon: '📈', label: 'Analytics' },
  ];

  const high = alerts.filter(a => a.risk_score >= 99).length;
  const med  = alerts.filter(a => a.risk_score >= 50 && a.risk_score < 99).length;
  const threatEvents = activityEvents.filter(e => e.event === 'threat_alert' || e.event === 'watch_alert' || e.event === 'baseline_breach' || e.event === 'blocked_access_attempt');

  return (
    <div className="app-screen">
      {/* TOP NAV */}
      <div className="topnav">
        <div className="nav-logo">
          <div className="nav-logo-badge">🛡</div>
          Vigil<span>AI</span>
        </div>
        <div className="nav-sep" />
        <div className="nav-user">{user?.name}</div>
        <span className="nav-role admin">Security Admin</span>

        {threatBanner && (
          <div className="banner banner-red si" style={{ margin: '0 12px', padding: '6px 14px', marginBottom: 0, fontSize: '13px' }}>
            🚨 <strong>{threatBanner.user}</strong>: {(threatBanner.message || '').slice(0, 55)}... ({threatBanner.risk_score}%)
          </div>
        )}

        <div className="nav-actions">
          {alerts.length > 0 && (
            <button className="nav-btn accent-btn" onClick={() => navigate('/admin/alerts')}>
              Alerts <span className="notif-dot" />
            </button>
          )}
          <button className="nav-btn danger" onClick={handleLogout}>Sign Out</button>
        </div>
      </div>

      {/* LAYOUT */}
      <div className="app-layout">
        {/* SIDEBAR */}
        <div className="sidebar">
          <div className="sidebar-section">
            <div className="sidebar-label">Command Center</div>
            {navItems.map(item => {
              const isActive = location.pathname.includes(`/admin/${item.path}`);
              return (
                <div key={item.path} className={`sidebar-item ${isActive ? 'active' : ''}`}
                  onClick={() => navigate(`/admin/${item.path}`)}>
                  <span className="sidebar-icon">{item.icon}</span>
                  {item.label}
                  {item.badge && threatEvents.length > 0 && (
                    <span className="sidebar-badge sb-red">{threatEvents.length}</span>
                  )}
                </div>
              );
            })}
          </div>
          {/* Live indicator */}
          <div style={{ margin: '12px 20px', padding: '10px 12px', background: 'rgba(193, 123, 63, 0.08)', borderRadius: '9px', border: '1px solid rgba(193, 123, 63, 0.2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '7px', marginBottom: '4px' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--safe)', display: 'inline-block', animation: 'pulse-red 1.5s infinite' }} />
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', fontWeight: 600, color: 'var(--safe)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Live Monitoring</span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>{activityEvents.length} events captured</div>
          </div>
        </div>

        {/* MAIN */}
        <div className="main">
          <Routes>
            <Route path="/" element={<Navigate to="overview" replace />} />

            {/* ── OVERVIEW ── */}
            <Route path="overview" element={
              <div>
                <div className="page-title">Security Overview</div>
                <div className="page-sub">Real-time insider threat monitoring — VigilAI Quantum-Safe Platform</div>

                <div className="stat-grid">
                  <div className="stat-card blue">
                    <div className="stat-label">Total Events</div>
                    <div className="stat-value blue">{activityEvents.length}</div>
                    <div className="stat-sub">All activity this session</div>
                  </div>
                  <div className="stat-card red">
                    <div className="stat-label">Critical Threats</div>
                    <div className="stat-value red">{high}</div>
                    <div className="stat-sub">Risk ≥ 99%</div>
                  </div>
                  <div className="stat-card amber">
                    <div className="stat-label">Suspicious</div>
                    <div className="stat-value amber">{med}</div>
                    <div className="stat-sub">Risk 50–98%</div>
                  </div>
                  <div className="stat-card green">
                    <div className="stat-label">PQC Secured</div>
                    <div className="stat-value green">{alerts.length}</div>
                    <div className="stat-sub">Kyber + Dilithium</div>
                  </div>
                </div>

                <div className="two-col">
                  <div className="card">
                    <div className="card-header">
                      <span className="card-title">Recent Alerts</span>
                      {alerts.length > 0 && <span className="badge badge-red">{alerts.length}</span>}
                    </div>
                    <AlertFeed limit={4} />
                  </div>
                  <div className="card">
                    <div className="card-header">
                      <span className="card-title">User Risk Status</span>
                      <span className="badge badge-blue">Live</span>
                    </div>
                    <UserRiskTable minimal />
                  </div>
                </div>
              </div>
            } />

            {/* ── LIVE ACTIVITY ── */}
            <Route path="live" element={
              <div>
                <div className="page-title">Live Activity Monitor</div>
                <div className="page-sub">Real-time stream of employee actions — every file access appears here instantly via WebSocket</div>

                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Activity Stream</span>
                    <span className="badge badge-blue" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                      <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--safe)', display: 'inline-block', animation: 'pulse-red 1s infinite' }} />
                      LIVE
                    </span>
                  </div>
                  {activityEvents.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', padding: '20px 0', textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
                      Waiting for employee activity...
                    </div>
                  ) : (
                    activityEvents.map((entry, i) => {
                      const evtType = entry.event;
                      const isBaseline = evtType === 'baseline_breach';
                      const isThreat = evtType === 'threat_alert';
                      const isWatch = evtType === 'watch_alert';
                      const isFileAccess = evtType === 'file_access';
                      const cls = isThreat ? 'sus' : (isWatch || isBaseline) ? 'warn' : 'ok';
                      const icon = isThreat ? '🚨' : isBaseline ? '🧠' : isWatch ? '⚠' : '→';

                      // File type badge
                      const fileTypeBadge = entry.file_type === 'critical'
                        ? '🔴 CRITICAL' : entry.file_type === 'research'
                        ? '🟡 RESEARCH' : entry.file_type === 'general'
                        ? '🟢 GENERAL' : '';
                      const fileTypeColor = entry.file_type === 'critical'
                        ? 'var(--threat)' : entry.file_type === 'research'
                        ? 'var(--watch)' : 'var(--safe)';

                      let msg;
                      if (isFileAccess) {
                        const delta = entry.risk_delta || 0;
                        const deltaStr = delta > 0 ? ` (+${delta}%)` : '';
                        msg = (
                          <span>
                            <strong>{entry.user}</strong> accessed <strong>{entry.file_name}</strong>
                            {fileTypeBadge && <span style={{ marginLeft: '6px', padding: '1px 7px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)', background: `${fileTypeColor}18`, color: fileTypeColor, border: `1px solid ${fileTypeColor}40` }}>{fileTypeBadge}</span>}
                            {entry.denied && <span style={{ marginLeft: '6px', padding: '1px 7px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)', background: 'var(--threat-bg)', color: 'var(--threat)', border: '1px solid var(--threat)' }}>⛔ DENIED</span>}
                            <span style={{ marginLeft: '8px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>Risk: {entry.risk_score}%{deltaStr}</span>
                          </span>
                        );
                      } else if (isBaseline) {
                        msg = <span>🧠 <strong>ML Baseline Breach</strong>: <strong>{entry.user}</strong> crossed 50% behavioral threshold — Risk: {entry.prev_score}% → {entry.risk_score}%</span>;
                      } else if (evtType === 'blocked_access_attempt') {
                        msg = (
                          <span>
                            🚫 <strong style={{ color: 'var(--threat)' }}>BLOCKED USER</strong> <strong>{entry.user}</strong> attempted to access <strong>{entry.file_name}</strong>
                            {entry.file_type && <span style={{ marginLeft: '6px', padding: '1px 7px', borderRadius: '4px', fontSize: '10px', fontWeight: 700, fontFamily: 'var(--font-mono)', background: 'var(--threat-bg)', color: 'var(--threat)', border: '1px solid var(--threat)' }}>⛔ RESTRICTED</span>}
                          </span>
                        );
                      } else if (evtType === 'risk_update') {
                        msg = `Risk update: ${entry.risk_score}% for user ${entry.user || entry.user_id}`;
                      } else if (evtType === 'status_change') {
                        msg = `Status change: ${entry.message}`;
                      } else {
                        msg = entry.message || JSON.stringify(entry);
                      }

                      return (
                        <div key={i} className={`log-entry ${cls} si`}>
                          <span style={{ marginRight: '8px' }}>{entry._ts}</span>
                          {icon} {msg}
                        </div>
                      );
                    })
                  )}
                </div>

                <div className="card" style={{ marginTop: '4px' }}>
                  <div className="card-header">
                    <span className="card-title">User Risk Status</span>
                  </div>
                  <UserRiskTable />
                </div>
              </div>
            } />

            {/* ── ALERTS ── */}
            <Route path="alerts" element={
              <div>
                <div className="page-title">Alert Feed</div>
                <div className="page-sub">All VigilAI alerts — PQC-signed with Dilithium-3, encrypted with Kyber-768</div>
                <AlertFeed />
              </div>
            } />

            {/* ── USERS ── */}
            <Route path="users" element={
              <div>
                <div className="page-title">User Risk Monitor</div>
                <div className="page-sub">Live behavioral baseline tracking — risk bars update in real-time via WebSocket</div>
                <UserRiskTable />
              </div>
            } />

            {/* ── PQC ── */}
            <Route path="pqc" element={
              <div>
                <div className="page-title">PQC Security Layer</div>
                <div className="page-sub">Post-quantum cryptography verification ledger</div>
                <div className="two-col" style={{ marginBottom: '16px' }}>
                  <div className="card" style={{ marginBottom: 0 }}>
                    <div className="card-title" style={{ marginBottom: '10px' }}>Dilithium-3 Signatures</div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                      Every alert is <strong style={{ color: 'var(--accent-primary)' }}>digitally signed</strong> using the Dilithium-3 lattice-based signature scheme (NIST PQC finalist).
                    </div>
                  </div>
                  <div className="card" style={{ marginBottom: 0 }}>
                    <div className="card-title" style={{ marginBottom: '10px' }}>Kyber-768 Encryption</div>
                    <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
                      Alert payloads are <strong style={{ color: 'var(--pqc)' }}>KEM-encapsulated</strong> using Kyber-768 for quantum-safe transmission.
                    </div>
                  </div>
                </div>
                <div className="card">
                  <div className="card-header"><span className="card-title">Verification Log</span></div>
                  <PQCLog />
                </div>
              </div>
            } />

            {/* ── ANALYTICS ── */}
            <Route path="charts" element={
              <div>
                <div className="page-title">Risk Analytics</div>
                <div className="page-sub">Time-series behavioral analytics</div>
                <div className="card"><RiskChart /></div>
              </div>
            } />
          </Routes>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
