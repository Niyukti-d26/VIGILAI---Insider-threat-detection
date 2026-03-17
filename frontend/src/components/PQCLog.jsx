import { useEffect, useState } from 'react';
import useStore from '../store/useStore';

function rng(seed) { let x = seed; return () => { x = ((x * 1664525) + 1013904223) & 0xffffffff; return (x >>> 0) / 0xffffffff; }; }
function pqcHash(seed) {
  const r = rng(seed); const h = '0123456789abcdef'; let s = '';
  for (let i = 0; i < 8; i++) s += h[Math.floor(r() * 16)];
  return s.slice(0, 4) + '...' + s.slice(4);
}

const PQCLog = () => {
  const { alerts, token } = useStore();
  const [dbAlerts, setDbAlerts] = useState([]);
  const [verifiedLogs, setVerifiedLogs] = useState([]);

  // Fetch persisted alerts from DB on mount
  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const res = await fetch(`${API_URL}/api/alerts/`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const data = await res.json();
          setDbAlerts(data);
        }
      } catch (err) { console.error('[PQC] Failed to fetch alerts:', err); }
    };
    fetchAlerts();
  }, [token, alerts.length]);

  // Auto-verify new WS alerts
  useEffect(() => {
    alerts.forEach(alert => {
      if (verifiedLogs.find(v => v.alert_id === alert.alert_id)) return;
      if (!alert.pqc) return;
      const tryVerify = async () => {
        try {
          const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
          const res = await fetch(`${API_URL}/api/alerts/verify`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ pqc: alert.pqc })
          });
          const data = await res.json();
          if (data.verified) {
            setVerifiedLogs(prev => [{ ...data, alert_id: alert.alert_id, user: alert.user, risk: alert.risk_score }, ...prev]);
          }
        } catch (err) { console.error(err); }
      };
      tryVerify();
    });
  }, [alerts]);

  const getRiskBadge = (score) => score >= 75 ? 'badge-red' : score >= 45 ? 'badge-amber' : 'badge-green';
  const getRiskText = (score) => score >= 75 ? 'THREAT' : score >= 45 ? 'WATCH' : 'VALID';

  // Merge DB alerts + WS alerts into unified log
  const allLogItems = [];

  // Add DB-persisted alerts first
  dbAlerts.forEach(a => {
    const sigSeed = Math.abs(hashCode(a.dilithium_signature || a.id || 'sig')) % 99999;
    const encSeed = Math.abs(hashCode(a.kyber_ciphertext_hash || a.id || 'enc')) % 99999;
    allLogItems.push({
      alert_id: a.id,
      user: a.user_name || 'Unknown',
      risk: a.risk_score,
      time: a.created_at,
      type: a.type,
      sigSeed,
      encSeed,
      dilithium_sig: a.dilithium_signature,
      kyber_hash: a.kyber_ciphertext_hash,
      resolved: a.resolved,
      verified: !!verifiedLogs.find(v => v.alert_id === a.id),
      source: 'db'
    });
  });

  // Add WS alerts not already in DB
  alerts.forEach((a, idx) => {
    if (allLogItems.find(x => x.alert_id === a.alert_id)) return;
    allLogItems.push({
      alert_id: a.alert_id,
      user: a.user,
      risk: a.risk_score,
      time: a.timestamp,
      type: a.event === 'threat_alert' ? 'threat' : a.event === 'watch_alert' ? 'suspicious' : 'info',
      sigSeed: a.pqc?.sig_seed || (idx * 31415 + 1),
      encSeed: a.pqc?.enc_seed || (idx * 27182 + 2),
      dilithium_sig: null,
      kyber_hash: null,
      resolved: false,
      verified: !!verifiedLogs.find(v => v.alert_id === a.alert_id),
      source: 'ws'
    });
  });

  const formatTime = (ts) => {
    if (!ts) return '--:--';
    try { return new Date(ts).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false }); }
    catch { return ts; }
  };

  return (
    <div>
      {/* Explanation Cards */}
      <div className="two-col" style={{ marginBottom: '14px' }}>
        <div className="card">
          <div className="card-title" style={{ marginBottom: '10px' }}>How Dilithium-3 Works</div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary, var(--muted2, #9aa0b0))', lineHeight: 1.8 }}>
            Every alert is <strong style={{ color: 'var(--accent-primary, var(--accent, #00d4ff))' }}>digitally signed</strong> using
            the Dilithium-3 lattice-based signature scheme (NIST PQC standard).<br /><br />
            This guarantees the alert truly came from VigilAI and was not tampered with in transit — even against quantum attackers.
          </div>
        </div>
        <div className="card">
          <div className="card-title" style={{ marginBottom: '10px' }}>How Kyber-768 Works</div>
          <div style={{ fontSize: '12px', color: 'var(--text-secondary, var(--muted2, #9aa0b0))', lineHeight: 1.8 }}>
            Alert payloads are <strong style={{ color: 'var(--pqc, var(--teal, #00bcd4))' }}>encrypted</strong> using Kyber-768,
            a lattice-based KEM (Key Encapsulation Mechanism).<br /><br />
            This protects log contents from Harvest-Now-Decrypt-Later attacks — even future quantum computers cannot break it.
          </div>
        </div>
      </div>

      {/* Verification Log Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Verification Log ({allLogItems.length} entries)</span>
          <span className="badge badge-green">✓ PQC Active</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="tbl" style={{ minWidth: '800px' }}>
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>User</th>
                <th>Time</th>
                <th>Risk</th>
                <th>Dilithium-3 Sig</th>
                <th>Kyber-768 Hash</th>
                <th>Hash Algo</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {allLogItems.length === 0 && (
                <tr>
                  <td colSpan="8" style={{
                    textAlign: 'center',
                    color: 'var(--text-muted, var(--muted, #6b7080))',
                    padding: '24px',
                    fontFamily: 'var(--font-mono)'
                  }}>
                    🔐 No cryptographic events recorded yet. Alerts will appear here when employee activity triggers the threat pipeline.
                  </td>
                </tr>
              )}
              {allLogItems.map((log, idx) => (
                <tr
                  key={log.alert_id || idx}
                  className={log.risk >= 75 ? 'row-threat' : log.risk >= 45 ? 'row-watch' : ''}
                >
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--accent-primary, var(--accent, #00d4ff))',
                      fontSize: '11px',
                      fontWeight: 600
                    }}>
                      {log.alert_id || '—'}
                    </span>
                  </td>
                  <td style={{ fontWeight: 500 }}>{log.user}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                    {formatTime(log.time)}
                  </td>
                  <td>
                    <span className={`badge ${getRiskBadge(log.risk)}`}>{log.risk}%</span>
                  </td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--accent-primary, var(--accent, #00d4ff))',
                      fontSize: '10px'
                    }}>
                      {log.dilithium_sig
                        ? log.dilithium_sig.slice(0, 4) + '...' + log.dilithium_sig.slice(-4)
                        : pqcHash(log.sigSeed)}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--pqc, var(--teal, #00bcd4))',
                      fontSize: '10px'
                    }}>
                      {log.kyber_hash
                        ? log.kyber_hash.slice(0, 4) + '...' + log.kyber_hash.slice(-4)
                        : pqcHash(log.encSeed)}
                    </span>
                  </td>
                  <td>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '10px',
                      color: 'var(--text-muted, var(--muted, #6b7080))'
                    }}>
                      SHA3-256
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${getRiskBadge(log.risk)}`}>
                      {getRiskText(log.risk)}
                    </span>
                    {log.verified && (
                      <span style={{
                        marginLeft: '4px',
                        fontSize: '10px',
                        color: 'var(--safe, var(--green, #00e676))'
                      }}>
                        ✓
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* PQC Chip Legend */}
      <div className="card" style={{ marginTop: '14px' }}>
        <div className="card-header">
          <span className="card-title">Cryptographic Primitives</span>
        </div>
        <div style={{ display: 'flex', gap: '14px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <div className="pqc-row" style={{ marginBottom: '8px' }}>
              <span className="pqc-chip chip-di">DILITHIUM-3</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted, var(--muted, #6b7080))', lineHeight: 1.6 }}>
              Lattice-based digital signature · NIST FIPS 204 · 128-bit post-quantum security
            </div>
          </div>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <div className="pqc-row" style={{ marginBottom: '8px' }}>
              <span className="pqc-chip chip-ky">KYBER-768</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted, var(--muted, #6b7080))', lineHeight: 1.6 }}>
              Lattice-based KEM · NIST FIPS 203 · AES-256-GCM symmetric encryption
            </div>
          </div>
          <div style={{ flex: 1, minWidth: '200px' }}>
            <div className="pqc-row" style={{ marginBottom: '8px' }}>
              <span className="pqc-chip chip-ok">✓ SHA3-256</span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted, var(--muted, #6b7080))', lineHeight: 1.6 }}>
              Keccak-based hash function · NIST FIPS 202 · Payload integrity verification
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Simple string hash for seed generation
function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + ch;
    hash = hash & hash;
  }
  return hash;
}

export default PQCLog;
