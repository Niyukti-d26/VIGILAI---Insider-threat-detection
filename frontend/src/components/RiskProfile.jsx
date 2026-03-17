import { useState, useEffect } from 'react';
import useStore from '../store/useStore';

const RiskProfile = ({ liveRisk }) => {
  const { user, token, activityEvents } = useStore();
  const [logs, setLogs] = useState([]);

  if (!user) return null;

  const score = Math.round(liveRisk ?? user?.risk_score ?? 5);
  const riskClass = score >= 99 ? 'red' : score >= 50 ? 'amber' : 'green';
  const riskBarColor = score >= 99 ? 'var(--threat)' : score >= 50 ? 'var(--watch)' : 'var(--safe)';
  const riskLabel = score >= 99 ? 'Critical Threat' : score >= 50 ? 'Suspicious' : 'Low Risk';
  const isBlocked = user?.status === 'blocked' || score >= 99;
  const isWatch = user?.status === 'watch' || (score >= 50 && score < 99);

  const API_URL = import.meta.env.VITE_API_URL || '';

  const loadLogs = async () => {
    try {
      const r = await fetch(`${API_URL}/api/users/me/activity?limit=10`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (r.ok) setLogs(await r.json());
    } catch (_) {}
  };

  useEffect(() => { loadLogs(); }, [token]);
  useEffect(() => { if (activityEvents.length > 0) loadLogs(); }, [activityEvents.length]);

  const factors = [
    { label: 'Critical file access',   riskEach: '+12% per file',    threshold: 'Level 3 files' },
    { label: 'Denied access attempts', riskEach: '+8% per attempt',  threshold: 'Clearance violations' },
    { label: 'Research file access',   riskEach: '+3% per file',     threshold: 'Level 2 files' },
    { label: 'General file access',    riskEach: '0% (no impact)',   threshold: 'Open access — safe' },
    { label: 'Bulk access pattern',    riskEach: '+10–15% bonus',    threshold: '4+ / 7+ sensitive files' },
    { label: 'Off-hours login',        riskEach: '+12% flat',        threshold: 'Outside 07:00–21:00' },
  ];

  return (
    <div>
      <div className="page-title">My Risk Profile</div>
      <div className="page-sub">VigilAI behavioral baseline and current risk assessment</div>

      {/* Hero: Score Ring */}
      <div className="card">
        <div className="score-ring-wrap">
          <div className={`score-ring ${riskClass}`}>{score}%</div>
          <div>
            <div style={{ fontFamily: 'var(--font-head)', fontSize: 'var(--text-xl)', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
              {riskLabel}
            </div>
            <div style={{ fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', marginBottom: '10px' }}>
              {isBlocked ? '🔴 Account restricted — contact your administrator' : isWatch ? '⚠ Your activity is under elevated monitoring' : '✓ Behavioral baseline within normal parameters'}
            </div>
            <div className="pqc-row">
              <span className="pqc-chip chip-ky">KYBER-768</span>
              <span className="pqc-chip chip-di">DILITHIUM-3</span>
              <span className="pqc-chip chip-ok">✓ PQC Verified</span>
            </div>
          </div>
        </div>

        <div className="risk-bar-wrap">
          <div className="risk-label-row"><span>Current Risk Score</span><span>{score}%</span></div>
          <div className="risk-track">
            <div className="risk-fill" style={{ width: `${Math.min(100, score)}%`, background: riskBarColor }} />
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)', marginTop: '5px' }}>
          <span>0% — Normal</span><span>50% — Watch</span><span>99% — Blocked</span>
        </div>
      </div>

      <div className="two-col">
        {/* Behavioral Baseline */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Behavioral Baseline</span>
          </div>
          <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', lineHeight: 1.8 }}>
            {[
              ['👤 User', user.name],
              ['🏢 Department', user.department],
              ['🔑 Clearance', `Level ${user.clearance_level}`],
              ['📊 Status', isBlocked ? 'Blocked' : isWatch ? 'Watch Mode' : 'Normal'],
              ['⏰ Normal Hours', '07:00 – 21:00'],
            ].map(([k, v]) => (
              <div key={k} style={{ padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
                {k}: <strong style={{ color: k.includes('Status') ? riskBarColor : 'var(--text-primary)' }}>{v}</strong>
              </div>
            ))}
          </div>
        </div>

        {/* Risk Factor Breakdown */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Risk Factors</span>
            <span className="badge badge-gray">ML Engine</span>
          </div>
          <table className="tbl">
            <thead>
              <tr><th>Factor</th><th>Weight</th><th>Threshold</th></tr>
            </thead>
            <tbody>
              {factors.map((f, i) => (
                <tr key={i}>
                  <td style={{ fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)' }}>{f.label}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--watch)' }}>{f.riskEach}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>{f.threshold}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Activity Timeline */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Recent Activity Timeline</span>
          {logs.length > 0 && <span className="badge badge-blue">{logs.length} events</span>}
        </div>
        {logs.length === 0 ? (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', padding: '18px 0', textAlign: 'center' }}>
            No recent access events.
          </div>
        ) : (
          logs.map((log, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: '14px',
              padding: '10px 0', borderBottom: '1px solid var(--border)',
            }}>
              <div style={{
                width: '32px', height: '32px', borderRadius: '50%', flexShrink: 0,
                background: log.denied ? 'var(--threat-bg)' : 'var(--safe-bg)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px',
              }}>
                {log.denied ? '🔒' : '📄'}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontFamily: 'var(--font-head)', fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {log.file_name}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                  {new Date(log.accessed_at).toLocaleString()}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span className={`badge ${log.denied ? 'badge-red' : 'badge-green'}`}>
                  {log.denied ? 'DENIED' : 'OK'}
                </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: log.risk_delta > 0 ? 'var(--watch)' : 'var(--safe)' }}>
                  +{log.risk_delta}%
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default RiskProfile;
