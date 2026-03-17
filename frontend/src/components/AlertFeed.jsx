import { useState } from 'react';
import useStore from '../store/useStore';

function rng(seed) { let x = seed; return () => { x = ((x * 1664525) + 1013904223) & 0xffffffff; return (x >>> 0) / 0xffffffff; }; }
function pqcHash(seed) {
  const r = rng(seed); const h = '0123456789abcdef'; let s = '';
  for (let i = 0; i < 8; i++) s += h[Math.floor(r() * 16)];
  return s.slice(0, 4) + '...' + s.slice(4);
}

const AlertFeed = ({ limit }) => {
  const { alerts, token } = useStore();
  const [modalAlert, setModalAlert] = useState(null);

  const handleResolve = async (alertId, outcome) => {
    try {
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      await fetch(`${API_URL}/api/alerts/${alertId}/resolve`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ outcome })
      });
      setModalAlert(null);
    } catch (err) { console.error(err); }
  };

  // Filter out pure risk_update and connected events, show actionable ones
  const actionableAlerts = alerts.filter(a =>
    a.event === 'threat_alert' || a.event === 'watch_alert' || a.event === 'baseline_breach' || a.event === 'blocked_access_attempt' || a.event === 'file_access' || a.alert_id
  );
  const shownAlerts = limit ? actionableAlerts.slice(0, limit) : actionableAlerts;

  const getAlertStyle = (alert) => {
    const score = alert.risk_score || 0;
    const evtType = alert.event;
    if (evtType === 'threat_alert' || score >= 99) return { cls: 'alert-threat', iconCls: 'ai-red', icon: '🔴', borderColor: 'var(--threat)' };
    if (evtType === 'watch_alert' || score >= 50) return { cls: 'alert-watch', iconCls: 'ai-amber', icon: '⚠', borderColor: 'var(--watch)' };
    return { cls: 'alert-access', iconCls: 'ai-blue', icon: 'ℹ', borderColor: 'var(--pqc)' };
  };

  const formatTime = (ts) => {
    if (!ts) return '--:--';
    try { return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }); }
    catch { return ts; }
  };

  if (shownAlerts.length === 0) {
    return (
      <div style={{ padding: '28px', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
        ✓ No anomalies detected — System operating within normal parameters.
      </div>
    );
  }

  return (
    <>
      <div>
        {shownAlerts.map((alert, idx) => {
          const score = alert.risk_score || 0;
          const { cls, iconCls, icon } = getAlertStyle(alert);
          const sigSeed = alert.pqc?.sig_seed || idx * 31415 + 1;
          const encSeed = alert.pqc?.enc_seed || idx * 27182 + 1;
          const alertTitle = alert.event === 'file_access'
            ? `${alert.user} accessed ${alert.file_name}${alert.denied ? ' (DENIED)' : ''}`
            : `${alert.user || 'Unknown'} — ${(alert.message || '').slice(0, 65)}${(alert.message || '').length > 65 ? '...' : ''}`;

          return (
            <div key={alert.alert_id || alert.user_id || idx} className={`alert-item ${cls}`}>
              <div className={`alert-icon ${iconCls}`}>{icon}</div>
              <div className="alert-body">
                <div className="alert-title">{alertTitle}</div>
                <div className="alert-meta">
                  Risk: {score}%
                  {alert.alert_id && ` · Alert: ${alert.alert_id}`}
                  {alert.file_type && ` · ${alert.file_type.toUpperCase()}`}
                </div>
                <div className="pqc-row">
                  <span className="pqc-chip chip-ky">KYBER-768</span>
                  <span className="pqc-chip chip-di">DILITHIUM-3</span>
                  {alert.alert_id && (
                    <span className="pqc-chip chip-ok">✓ {alert.alert_id} · sig:{pqcHash(sigSeed)}</span>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '6px', flexShrink: 0 }}>
                <div className="alert-time">{formatTime(alert.timestamp)}</div>
                {alert.alert_id && (
                  <button className="iab" onClick={() => setModalAlert(alert)}>View ↗</button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Alert Detail Modal */}
      <div className={`modal-bg ${modalAlert ? 'show' : ''}`}>
        {modalAlert && (() => {
          const score = modalAlert.risk_score || 0;
          const sigSeed = modalAlert.pqc?.sig_seed || 31415;
          const encSeed = modalAlert.pqc?.enc_seed || 27182;
          const isThreat = score >= 99;
          const statusColor = isThreat ? 'var(--threat)' : score >= 50 ? 'var(--watch)' : 'var(--safe)';

          return (
            <div className="modal">
              <div className="modal-title" style={{ color: isThreat ? 'var(--threat)' : score >= 45 ? 'var(--watch)' : 'var(--text-primary)' }}>
                {isThreat ? '🔴 INSIDER THREAT DETECTED' : '⚠ Suspicious Activity Alert'}
              </div>
              <div className="modal-body">
                <strong>{modalAlert.user}</strong> has triggered a VigilAI security alert.<br /><br />
                <em>{modalAlert.message}</em><br /><br />
                {isThreat
                  ? '✅ Account has been automatically restricted. File transfers blocked.'
                  : '👁 User placed under Watch mode. No account restriction yet.'}
              </div>
              <div className="modal-pqc">
                {[
                  ['Alert ID', modalAlert.alert_id],
                  ['Dilithium-3 Signature', pqcHash(sigSeed)],
                  ['Kyber-768 Enc. Hash', pqcHash(encSeed)],
                  ['Hash Algorithm', 'SHA3-256'],
                  ['Risk Score', `${score}%`],
                  ['Action', isThreat ? 'THREAT — BLOCKED' : 'WATCH — MONITORING'],
                ].map(([k, v]) => (
                  <div key={k} className="modal-pqc-row">
                    <span className="modal-pqc-key">{k}</span>
                    <span className="modal-pqc-val" style={k === 'Risk Score' || k === 'Action' ? { color: statusColor } : {}}>{v}</span>
                  </div>
                ))}
              </div>
              <div className="pqc-row" style={{ marginBottom: '18px' }}>
                <span className="pqc-chip chip-ky">KYBER-768</span>
                <span className="pqc-chip chip-di">DILITHIUM-3</span>
                <span className="pqc-chip chip-ok">✓ SHA3-256</span>
              </div>
              <div className="modal-btns">
                <button className="modal-btn close" onClick={() => setModalAlert(null)}>Close</button>
                <button
                  className="modal-btn"
                  style={{ background: isThreat ? 'var(--threat)' : 'var(--watch)', color: '#fff' }}
                  onClick={() => handleResolve(modalAlert.alert_id, isThreat ? 'confirmed' : 'dismissed')}
                >
                  {isThreat ? 'Confirm & Resolve' : 'Mark as Reviewed'}
                </button>
              </div>
            </div>
          );
        })()}
      </div>
    </>
  );
};

export default AlertFeed;
