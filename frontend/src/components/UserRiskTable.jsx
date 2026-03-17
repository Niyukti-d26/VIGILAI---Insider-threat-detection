import { useState, useEffect } from 'react';
import useStore from '../store/useStore';

const UserRiskTable = ({ minimal = false }) => {
  const { token, userRiskScores, updateUserRisk } = useStore();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchUsers = async () => {
    try {
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${API_URL}/api/users/`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      setUsers(data.filter(u => u.role !== 'admin'));
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
    const interval = setInterval(fetchUsers, 5000);
    return () => clearInterval(interval);
  }, []);

  // Re-fetch immediately when WS risk scores change (catches unblock events)
  useEffect(() => {
    if (Object.keys(userRiskScores).length > 0) fetchUsers();
  }, [JSON.stringify(userRiskScores)]);

  const updateStatus = async (userId, newStatus) => {
    try {
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${API_URL}/api/users/${userId}/status?status=${newStatus}`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        // Immediately update local store so UI reflects change before re-fetch
        if (newStatus === 'normal') {
          updateUserRisk(userId, 0);
        }
        await fetchUsers();
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Thresholds: 99% = threat/blocked, 50% = watch
  const getRiskColor = (score) => score >= 99 ? 'var(--threat)' : score >= 50 ? 'var(--watch)' : 'var(--safe)';
  const getRiskBadge = (score) => score >= 99 ? 'badge-red' : score >= 50 ? 'badge-amber' : 'badge-green';

  if (loading && users.length === 0) return (
    <div style={{ padding: '18px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', textAlign: 'center' }}>
      Loading user data...
    </div>
  );

  if (minimal) {
    return (
      <div style={{ overflowX: 'auto' }}>
        <table className="tbl" style={{ minWidth: '420px' }}>
          <thead>
            <tr><th>User</th><th>Risk</th><th>Status</th></tr>
          </thead>
          <tbody>
            {users.map(u => {
              const score = Math.round(userRiskScores[u.id] ?? u.risk_score);
              const statusClass = u.status === 'blocked' ? 'badge-red' : u.status === 'watch' ? 'badge-amber' : 'badge-green';
              return (
                <tr key={u.id} className={u.status === 'blocked' ? 'row-threat' : u.status === 'watch' ? 'row-watch' : ''}>
                  <td><strong style={{ fontFamily: 'var(--font-head)', fontSize: '15px' }}>{u.name}</strong></td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <div style={{ width: '70px' }}>
                        <div className="risk-track">
                          <div className="risk-fill" style={{ width: `${Math.min(100, score)}%`, background: getRiskColor(score) }} />
                        </div>
                      </div>
                      <span className={`badge ${getRiskBadge(score)}`}>{score}%</span>
                    </div>
                  </td>
                  <td><span className={`badge ${statusClass}`}>{u.status === 'blocked' ? 'Blocked' : u.status === 'watch' ? 'Watch' : 'Normal'}</span></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  }

  return (
    <div>
      {users.map(u => {
        const score = Math.round(userRiskScores[u.id] ?? u.risk_score);
        const isBlocked = u.status === 'blocked';
        const isWatch = u.status === 'watch';
        const cardClass = isBlocked ? 'card-threat' : isWatch ? 'card-watch' : '';
        const initials = u.name.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase();

        return (
          <div key={u.id} className={`user-card ${cardClass}`}>
            <div className="user-avatar">{initials}</div>
            <div style={{ flex: 1 }}>
              <div className="user-card-name">{u.name}</div>
              <div className="user-card-meta">
                {u.department} &nbsp;·&nbsp;
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{u.email}</span>
                &nbsp;·&nbsp; Clearance Level {u.clearance_level}
              </div>
              <div className="risk-bar-wrap" style={{ marginBottom: '8px' }}>
                <div className="risk-label-row">
                  <span>Risk Score</span>
                  <span style={{ color: getRiskColor(score), fontWeight: 700 }}>{score}%</span>
                </div>
                <div className="risk-track">
                  <div className="risk-fill" style={{ width: `${Math.min(100, score)}%`, background: getRiskColor(score) }} />
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                <span className={`badge ${isBlocked ? 'badge-red' : isWatch ? 'badge-amber' : 'badge-green'}`}>
                  {isBlocked ? '🔴 Blocked' : isWatch ? '⚠ Watch' : '✓ Normal'}
                </span>
                {!minimal && (
                  <>
                    <button
                      className="iab red"
                      onClick={() => updateStatus(u.id, 'blocked')}
                      disabled={isBlocked}
                      style={isBlocked ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
                    >
                      Block
                    </button>
                    <button
                      className="iab green"
                      onClick={() => updateStatus(u.id, 'normal')}
                      disabled={u.status === 'normal'}
                      style={u.status === 'normal' ? { opacity: 0.4, cursor: 'not-allowed' } : {}}
                    >
                      Unblock
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        );
      })}
      {users.length === 0 && (
        <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', textAlign: 'center', padding: '24px' }}>
          No employees found.
        </div>
      )}
    </div>
  );
};

export default UserRiskTable;
