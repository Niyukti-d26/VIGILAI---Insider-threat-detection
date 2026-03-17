import { useState, useEffect } from 'react';
import { Routes, Route, useNavigate, Navigate, useLocation } from 'react-router-dom';
import useStore from '../store/useStore';

import FileSystem from '../components/FileSystem';
import RiskProfile from '../components/RiskProfile';

const EmployeeDashboard = () => {
  const { user, token, logout, setAuth, connectWebSocket, isBlocked, userRiskScores } = useStore();
  const navigate = useNavigate();
  const location = useLocation();

  // Get live risk from the store's real-time map, falling back to user object
  const storedScore = userRiskScores[user?.id];
  const [liveRisk, setLiveRisk] = useState(storedScore ?? user?.risk_score ?? 5);
  const [liveStatus, setLiveStatus] = useState(user?.status || 'normal');

  // Connect employee WebSocket on mount
  useEffect(() => {
    if (token && user?.id) {
      connectWebSocket(token, 'employee', user.id);
    }
  }, [token, user?.id]);

  // Update liveRisk whenever store's userRiskScores changes for this user
  useEffect(() => {
    if (storedScore !== undefined) {
      setLiveRisk(storedScore);
    }
  }, [storedScore]);

  // Poll the user's own risk every 5s as fallback
  useEffect(() => {
    const API_URL = import.meta.env.VITE_API_URL || '';
    const poll = async () => {
      try {
        if (!token) return;
        const res = await fetch(`${API_URL}/api/users/me`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setLiveRisk(data.risk_score);
          setLiveStatus(data.status);
          if (data.status === 'blocked') setAuth(token, data.role, data);
        }
      } catch (e) { /* silently ignore */ }
    };
    poll();
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, [token]);

  const handleLogout = () => { logout(); navigate('/login'); };

  const navItems = [
    { path: 'files',    icon: '📁', label: 'File System' },
    { path: 'activity', icon: '📋', label: 'My Activity' },
    { path: 'profile',  icon: '🛡', label: 'Risk Profile' },
  ];

  const riskColor = liveRisk >= 99 ? 'var(--threat)' : liveRisk >= 50 ? 'var(--watch)' : 'var(--safe)';
  const riskLabel = liveRisk >= 99 ? 'Critical' : liveRisk >= 50 ? 'Watch' : 'Normal';
  const effectiveBlocked = isBlocked || liveStatus === 'blocked' || liveRisk >= 99;
  const isWatch = !effectiveBlocked && (liveStatus === 'watch' || liveRisk >= 50);

  return (
    <div className="app-screen">
      {/* ACCOUNT SUSPENDED POPUP */}
      {effectiveBlocked && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 9999,
          background: 'rgba(0,0,0,0.5)',
          backdropFilter: 'blur(12px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          animation: 'fadeIn 0.3s ease-out',
        }}>
          <div style={{
            background: 'var(--bg-card)',
            border: '2px solid rgba(192,57,43,0.4)',
            borderRadius: '24px',
            padding: '48px 56px',
            maxWidth: '500px',
            textAlign: 'center',
            boxShadow: '0 25px 60px rgba(192,57,43,0.25), var(--shadow-lg)',
            animation: 'popIn 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
          }}>
            <div style={{ fontSize: '64px', marginBottom: '16px', animation: 'pulse 1.5s infinite' }}>🚫</div>
            <h1 style={{
              fontFamily: 'var(--font-head)', fontSize: '28px', fontWeight: 800,
              color: 'var(--threat)', marginBottom: '8px', letterSpacing: '-0.02em',
            }}>Account Suspended</h1>
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: '11px', fontWeight: 700,
              color: 'var(--threat)', background: 'var(--threat-bg)',
              padding: '4px 14px', borderRadius: '6px', display: 'inline-block',
              marginBottom: '18px', letterSpacing: '0.08em',
            }}>RISK SCORE: {Math.round(liveRisk)}% — THRESHOLD EXCEEDED</div>
            <p style={{
              fontFamily: 'var(--font-body)', fontSize: '14px',
              color: 'var(--text-secondary)', lineHeight: 1.8, marginBottom: '10px',
            }}>
              Your account has been <strong style={{ color: 'var(--threat)' }}>automatically suspended</strong> by VigilAI's behavioral anomaly detection system due to severe policy violations.
            </p>
            <p style={{
              fontFamily: 'var(--font-body)', fontSize: '13px',
              color: 'var(--text-muted)', lineHeight: 1.7, marginBottom: '28px',
            }}>
              All file access is now restricted. Please contact your <strong>Security Administrator</strong> to review your activity and restore access.
            </p>
            <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
              <button className="btn-primary" style={{
                width: 'auto', padding: '14px 40px', fontSize: '14px', fontWeight: 700,
                background: 'var(--threat)', borderColor: 'var(--threat)',
              }} onClick={handleLogout}>Sign Out</button>
            </div>
            <div className="pqc-row" style={{ marginTop: '20px', justifyContent: 'center' }}>
              <span className="pqc-chip chip-di" style={{ fontSize: '9px' }}>DILITHIUM-3 SIGNED</span>
              <span className="pqc-chip chip-ky" style={{ fontSize: '9px' }}>KYBER-768 ENCRYPTED</span>
            </div>
          </div>
          <style>{`
            @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
            @keyframes popIn { from { opacity: 0; transform: scale(0.8); } to { opacity: 1; transform: scale(1); } }
            @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.15); } }
          `}</style>
        </div>
      )}

      {/* TOP NAV */}
      <div className="topnav">
        <div className="nav-logo">
          <div className="nav-logo-badge">🛡</div>
          Vigil<span>AI</span>
        </div>
        <div className="nav-sep" />
        <div className="nav-user">{user?.name}</div>
        <span className="nav-role employee">Employee</span>
        <div className="nav-actions">
          <button className="nav-btn danger" onClick={handleLogout}>Sign Out</button>
        </div>
      </div>

      {/* APP LAYOUT */}
      <div className="app-layout">
        {/* SIDEBAR */}
        <div className="sidebar">
          {/* Mini risk score */}
          <div style={{ margin: '6px 14px 16px', padding: '14px', background: 'var(--bg-card)', borderRadius: '12px', border: '1.5px solid var(--border)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <span style={{ fontFamily: 'var(--font-body)', fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Risk Score</span>
              <span style={{ fontFamily: 'var(--font-head)', fontSize: '18px', fontWeight: 700, color: riskColor }}>{Math.round(liveRisk)}%</span>
            </div>
            <div className="risk-track">
              <div className="risk-fill" style={{ width: `${Math.min(100, liveRisk)}%`, background: riskColor }} />
            </div>
            <div style={{ textAlign: 'center', marginTop: '8px', fontFamily: 'var(--font-body)', fontSize: '11px', fontWeight: 700, color: riskColor, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {riskLabel}
            </div>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-label">Workspace</div>
            {navItems.map(item => {
              const isActive = location.pathname.includes(`/employee/${item.path}`);
              return (
                <div key={item.path} className={`sidebar-item ${isActive ? 'active' : ''}`}
                  onClick={() => navigate(`/employee/${item.path}`)}>
                  <span className="sidebar-icon">{item.icon}</span>
                  {item.label}
                </div>
              );
            })}
          </div>
        </div>

        {/* MAIN CONTENT */}
        <div className="main">
          {isWatch && !effectiveBlocked && (
            <div className="banner banner-amber si">
              ⚠ <strong>Watch Mode Active</strong> — Elevated activity detected. Your access is being closely monitored by VigilAI. Current risk: {Math.round(liveRisk)}%
            </div>
          )}
          <Routes>
            <Route path="/"        element={<Navigate to="files" replace />} />
            <Route path="files"    element={<FileSystem liveRisk={liveRisk} setLiveRisk={setLiveRisk} />} />
            <Route path="activity" element={<MyActivity />} />
            <Route path="profile"  element={<RiskProfile liveRisk={liveRisk} />} />
          </Routes>
        </div>
      </div>
    </div>
  );
};

const MyActivity = () => {
  const { token, activityEvents } = useStore();
  const [logs, setLogs] = useState([]);
  const API_URL = import.meta.env.VITE_API_URL || '';

  const load = async () => {
    try {
      const r = await fetch(`${API_URL}/api/users/me/activity`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) {
        const d = await r.json();
        setLogs(d);
      }
    } catch(e) {}
  };

  useEffect(() => {
    load();
  }, [token]);

  // Reload whenever activityEvents change (new WS event came in)
  useEffect(() => {
    if (activityEvents.length > 0) load();
  }, [activityEvents.length]);

  const criticalCount = logs.filter(l => l.file_type === 'critical' || (l.risk_delta && l.risk_delta >= 20)).length;
  const deniedCount = logs.filter(l => l.denied).length;

  return (
    <div>
      <div className="page-title">My Activity</div>
      <div className="page-sub">All file access events this session — logged and PQC-secured</div>
      <div className="two-col">
        {/* Left: Access Log */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Access Log ({logs.length} events)</span>
          </div>
          {logs.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', textAlign: 'center', padding: '28px 0', fontFamily: 'var(--font-mono)' }}>
              No activity yet this session.
            </div>
          ) : (
            [...logs].reverse().map((log, i) => {
              const cls = log.denied ? 'sus' : (log.file_type === 'critical' || log.risk_delta >= 10) ? 'warn' : 'ok';
              return (
                <div key={i} className={`log-entry ${cls} si`}>
                  {new Date(log.accessed_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false })}
                  {' — '}
                  {log.denied ? '⛔ DENIED: ' : '✓ '}
                  {log.file_name || log.file_id}
                  <span style={{ color: 'var(--text-muted)', marginLeft: '6px' }}>
                    · +{log.risk_delta}%
                  </span>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Session Summary */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Session Summary</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '12px' }}>
            <div style={{ background: 'var(--bg-elevated, var(--bg-card, #f5f0eb))', borderRadius: '8px', padding: '12px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-body)' }}>Critical accessed</div>
              <div style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--threat)' }}>{criticalCount}</div>
            </div>
            <div style={{ background: 'var(--bg-elevated, var(--bg-card, #f5f0eb))', borderRadius: '8px', padding: '12px', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '4px', fontFamily: 'var(--font-body)' }}>Denied attempts</div>
              <div style={{ fontSize: '22px', fontWeight: 700, fontFamily: 'var(--font-head)', color: 'var(--watch)' }}>{deniedCount}</div>
            </div>
          </div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
            Every access event is hashed with <strong>SHA3-256</strong>, signed with <strong>Dilithium-3</strong>,
            and encrypted with <strong>Kyber-768</strong> before transmission to the security log.
          </div>
          <div className="pqc-row" style={{ marginTop: '12px' }}>
            <span className="pqc-chip chip-ky">KYBER-768</span>
            <span className="pqc-chip chip-di">DILITHIUM-3</span>
            <span className="pqc-chip chip-ok">✓ SHA3-256</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EmployeeDashboard;
