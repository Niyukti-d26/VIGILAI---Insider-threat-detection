import { useState, useEffect } from 'react';
import useStore from '../store/useStore';

function rngHash(seed, len = 8) {
  let x = seed; const h = '0123456789abcdef'; let s = '';
  for (let i = 0; i < len; i++) { x = ((x * 1664525) + 1013904223) & 0xffffffff; s += h[(x >>> 0) % 16]; }
  return s.slice(0, 4) + '...' + s.slice(4);
}

const FileSystem = ({ liveRisk = 5, setLiveRisk }) => {
  const { token, user, updateUserRisk } = useStore();
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState(null);
  const [modal, setModal] = useState(null);
  const [accessing, setAccessing] = useState(null);

  useEffect(() => {
    const API_URL = import.meta.env.VITE_API_URL || '';
    fetch(`${API_URL}/api/files/`, { headers: { 'Authorization': `Bearer ${token}` } })
      .then(r => r.json()).then(d => setFiles(d)).catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const showToast = (type, msg) => {
    setToast({ type, msg });
    setTimeout(() => setToast(null), 4000);
  };

  const handleAccess = async (file) => {
    if (liveRisk >= 95) { showToast('red', 'Account restricted — access suspended'); return; }
    setAccessing(file.id);
    try {
      const API_URL = import.meta.env.VITE_API_URL || '';
      const res = await fetch(`${API_URL}/api/files/${file.id}/access`, {
        method: 'POST', headers: { 'Authorization': `Bearer ${token}` }
      });

      let data = {};
      try { data = await res.json(); } catch (_) {}

      if (!res.ok) {
        const seed = Date.now();
        setModal({
          title: '🔒 Access Denied',
          body: `Insufficient clearance (Level ${file.clearance_required}) to access <strong>${file.name}</strong>.<br/><br/>This attempt has been logged and your risk score has been updated.`,
          sigSeed: seed, encSeed: seed + 1,
          status: 'ACCESS DENIED — LOGGED',
          file,
          newScore: data?.risk_score || data?.detail?.match?.(/\d+/)?.[0],
        });
        // Update risk score in store even on denial
        if (data?.risk_score || data?.detail) {
          const score = data.risk_score || parseInt((data.detail || '').match(/\d+/)?.[0] || '0');
          if (score && user?.id) updateUserRisk(user.id, score);
          if (score && setLiveRisk) setLiveRisk(score);
        }
      } else {
        showToast('green', `✓ Opened: ${file.name}${data.risk_score ? ` — Risk: ${data.risk_score}%` : ''}`);
        if (data.risk_score && user?.id) updateUserRisk(user.id, data.risk_score);
        if (data.risk_score && setLiveRisk) setLiveRisk(data.risk_score);
      }
    } catch (err) {
      showToast('red', 'Request failed. Check your connection.');
    } finally {
      setAccessing(null);
    }
  };

  if (loading) return (
    <div style={{ padding: '28px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)' }}>
      Loading file system...
    </div>
  );

  const sections = [
    { type: 'critical', label: 'CRITICAL', sublabel: 'Level 3 Clearance Required', color: 'var(--threat)', icon: '💼', badgeClass: 'badge-red' },
    { type: 'research', label: 'RESEARCH', sublabel: 'Level 2 Clearance Required', color: 'var(--pqc)',   icon: '🧠', badgeClass: 'badge-blue' },
    { type: 'general',  label: 'GENERAL',  sublabel: 'Open Access',                color: 'var(--safe)',  icon: '📘', badgeClass: 'badge-green' },
  ];

  return (
    <div>
      <div className="page-title">File System</div>
      <div className="page-sub">
        All accesses are monitored in real-time. &nbsp;
        <span style={{ color: liveRisk >= 75 ? 'var(--threat)' : liveRisk >= 45 ? 'var(--watch)' : 'var(--safe)', fontWeight: 700 }}>
          Current risk: {Math.round(liveRisk)}%
        </span>
      </div>

      {liveRisk >= 99 ? (
        <div className="banner banner-red si">
          🔴 <strong>Account Restricted</strong> — VigilAI has detected a threat. All file access is suspended. Contact your administrator.
        </div>
      ) : liveRisk >= 50 ? (
        <div className="banner banner-amber si">
          ⚠ <strong>Watch Mode Active</strong> — Elevated activity detected. Your access is being closely monitored. Risk Score: {Math.round(liveRisk)}%
        </div>
      ) : (
        <div className="banner banner-blue si">
          ✓ Session secured with PQC (Kyber-768). Logged in as <strong>{user?.name}</strong> · Clearance Level: {user?.clearance_level || 1}
        </div>
      )}

      {sections.map(sec => {
        const sFiles = files.filter(f => f.type === sec.type);
        if (!sFiles.length) return null;
        return (
          <div key={sec.type} style={{ marginBottom: '28px' }}>
            {/* Section header with colored left bar */}
            <div className="section-header">
              <div className="section-header-bar" style={{ background: sec.color }} />
              <span className="section-header-label">{sec.label}</span>
              <span className="section-header-sub">{sec.sublabel}</span>
            </div>

            <div className="file-grid">
              {sFiles.map(f => {
                const canAccess = user?.clearance_level >= f.clearance_required;
                const isLoading = accessing === f.id;
                return (
                  <div
                    key={f.id}
                    className={`file-card ${f.type} ${!canAccess ? 'locked' : ''}`}
                    onClick={() => handleAccess(f)}
                    style={{ opacity: isLoading ? 0.7 : 1, cursor: isLoading ? 'wait' : 'pointer' }}
                  >
                    <div className="file-tag">
                      <span className={`badge ${!canAccess ? 'badge-red' : sec.badgeClass}`}>
                        {!canAccess ? '🔒 Locked' : sec.type === 'critical' ? 'CRITICAL' : sec.type === 'research' ? 'RESEARCH' : 'OPEN'}
                      </span>
                    </div>
                    <div className="file-icon-big">{isLoading ? '⌛' : sec.icon}</div>
                    <div className="file-name">{f.name}</div>
                    <div className="file-meta">{f.department} · {f.size_label}</div>
                    <div style={{ marginTop: '8px' }}>
                      {f.risk_weight > 0 ? (
                        <span style={{ fontSize: '11px', color: 'var(--watch)', fontFamily: 'var(--font-mono)' }}>⚠ +{f.risk_weight}% risk on access</span>
                      ) : (
                        <span style={{ fontSize: '11px', color: 'var(--safe)', fontFamily: 'var(--font-mono)' }}>✓ No risk impact</span>
                      )}
                    </div>

                    {/* Locked overlay */}
                    {!canAccess && !isLoading && (
                      <div className="file-card-locked-overlay">
                        <div className="lock-icon">🔒</div>
                        <div className="lock-text">Clearance Level {f.clearance_required} Required</div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* TOAST */}
      {toast && (
        <div className={`toast toast-${toast.type} si`}>
          <span>{toast.type === 'green' ? '✓' : '⚠'}</span>
          <span>{toast.msg}</span>
        </div>
      )}

      {/* ACCESS DENIED MODAL */}
      <div className={`modal-bg ${modal ? 'show' : ''}`}>
        {modal && (
          <div className="modal">
            <div className="modal-title">{modal.title}</div>
            <div className="modal-body" dangerouslySetInnerHTML={{ __html: modal.body }} />
            <div className="modal-pqc">
              <div className="modal-pqc-row">
                <span className="modal-pqc-key">Alert ID</span>
                <span className="modal-pqc-val">ALT-{modal.sigSeed.toString().slice(-4)}</span>
              </div>
              <div className="modal-pqc-row">
                <span className="modal-pqc-key">Dilithium-3 Sig</span>
                <span className="modal-pqc-val">{rngHash(modal.sigSeed)}</span>
              </div>
              <div className="modal-pqc-row">
                <span className="modal-pqc-key">Kyber-768 Hash</span>
                <span className="modal-pqc-val">{rngHash(modal.encSeed)}</span>
              </div>
              <div className="modal-pqc-row">
                <span className="modal-pqc-key">Your Risk Now</span>
                <span className="modal-pqc-val" style={{ color: 'var(--watch)' }}>
                  {modal.newScore ? `${modal.newScore}%` : '—'}
                </span>
              </div>
              <div className="modal-pqc-row">
                <span className="modal-pqc-key">Status</span>
                <span className="modal-pqc-val" style={{ color: 'var(--watch)' }}>{modal.status}</span>
              </div>
            </div>
            <div className="pqc-row" style={{ marginBottom: '18px' }}>
              <span className="pqc-chip chip-ky">KYBER-768</span>
              <span className="pqc-chip chip-di">DILITHIUM-3</span>
              <span className="pqc-chip chip-ok">✓ SHA3-256</span>
            </div>
            <div className="modal-btns">
              <button className="modal-btn close" onClick={() => setModal(null)}>Close</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FileSystem;
