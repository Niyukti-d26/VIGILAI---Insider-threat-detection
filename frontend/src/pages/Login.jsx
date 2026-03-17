import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import useStore from '../store/useStore';

const Login = () => {
  const [activeTab, setActiveTab] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [signupName, setSignupName] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupRole, setSignupRole] = useState('employee');
  const [signupDept, setSignupDept] = useState('Engineering');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const setAuth = useStore(state => state.setAuth);
  const navigate = useNavigate();
  const API_URL = import.meta.env.VITE_API_URL || '';

  const completeAuthFlow = async (access_token, givenRole) => {
    const profRes = await fetch(`${API_URL}/api/users/me`, {
      headers: { 'Authorization': `Bearer ${access_token}` }
    });
    const profData = await profRes.json();
    const authRole = profData.role || givenRole;
    setAuth(access_token, authRole, profData);
    // Connect WebSocket immediately after login
    const { connectWebSocket } = useStore.getState();
    connectWebSocket(access_token, authRole, profData.id);
    if (authRole === 'admin') {
      if ('Notification' in window) Notification.requestPermission();
      navigate('/admin');
    } else {
      navigate('/employee');
    }
  };

  const handleLogin = async (emailVal, passVal) => {
    const useEmail = emailVal ?? email;
    const usePass  = passVal  ?? password;
    if (!useEmail || !usePass) { setError('Please enter email and password.'); return; }
    setError(''); setLoading(true);
    try {
      const formData = new URLSearchParams();
      formData.append('username', useEmail);
      formData.append('password', usePass);
      const res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData,
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Login failed'); }
      const data = await res.json();
      await completeAuthFlow(data.access_token, data.role);
    } catch (err) {
      setError(err.message);
    } finally { setLoading(false); }
  };

  const handleSignup = async () => {
    if (!signupName || !signupEmail || signupPassword.length < 8) {
      setError('Fill all fields (min 8-char password)'); return;
    }
    setError(''); setLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: signupName, email: signupEmail, password: signupPassword, department: signupDept }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.detail || 'Signup failed'); }
      const data = await res.json();
      await completeAuthFlow(data.access_token, data.role);
    } catch (err) {
      setError(err.message);
    } finally { setLoading(false); }
  };

  const quickLogin = (e, p) => { setEmail(e); setPassword(p); handleLogin(e, p); };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        {/* Logo */}
        <div className="auth-logo">
          <div className="auth-logo-icon">🛡</div>
          <div>
            <div className="auth-logo-text">Vigil<span>AI</span></div>
            <div className="auth-subtitle">Quantum-Safe Insider Threat Detection</div>
          </div>
        </div>

        {/* Tabs */}
        <div className="auth-tabs">
          <div className={`auth-tab ${activeTab === 'login' ? 'active' : ''}`}
            onClick={() => { setActiveTab('login'); setError(''); }}>Sign In</div>
          <div className={`auth-tab ${activeTab === 'signup' ? 'active' : ''}`}
            onClick={() => { setActiveTab('signup'); setError(''); }}>Sign Up</div>
        </div>

        {error && (
          <div style={{ background: 'rgba(220,38,38,0.08)', border: '1.5px solid rgba(220,38,38,0.2)', color: '#dc2626', padding: '10px 14px', borderRadius: '9px', fontSize: '13px', marginBottom: '14px', fontWeight: 500 }}>
            {error}
          </div>
        )}

        {activeTab === 'login' && (
          <div>
            <div className="form-group">
              <label className="form-label">Email address</label>
              <input className="form-input" type="email" placeholder="you@company.com"
                value={email} onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLogin()} />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" placeholder="••••••••"
                value={password} onChange={e => setPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLogin()} />
            </div>
            <button className="btn-primary" onClick={() => handleLogin()} disabled={loading}>
              {loading ? 'Signing in...' : 'Sign In →'}
            </button>

            <div className="demo-accounts">
              <div className="demo-label">Quick demo access</div>
              <div className="demo-btns">
                <div className="demo-btn" onClick={() => quickLogin('admin@vigilai.io', 'admin123')}>
                  🔐 Admin <span className="role">admin@vigilai.io</span>
                </div>
                <div className="demo-btn" onClick={() => quickLogin('sarah@vigilai.io', 'sarah123')}>
                  👤 Sarah <span className="role">sarah@vigilai.io</span>
                </div>
                <div className="demo-btn" onClick={() => quickLogin('maya@vigilai.io', 'maya123')}>
                  👤 Maya <span className="role">maya@vigilai.io</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'signup' && (
          <div>
            <div className="form-group">
              <label className="form-label">Full name</label>
              <input className="form-input" type="text" placeholder="Sarah Chen" value={signupName} onChange={e => setSignupName(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Email address</label>
              <input className="form-input" type="email" placeholder="you@company.com" value={signupEmail} onChange={e => setSignupEmail(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Password</label>
              <input className="form-input" type="password" placeholder="Min. 8 characters" value={signupPassword} onChange={e => setSignupPassword(e.target.value)} />
            </div>
            <div className="form-group">
              <label className="form-label">Department</label>
              <select className="form-select" value={signupDept} onChange={e => setSignupDept(e.target.value)}>
                <option>Engineering</option>
                <option>Research &amp; Development</option>
                <option>Finance</option>
                <option>Human Resources</option>
                <option>Security Operations</option>
              </select>
            </div>
            <button className="btn-primary" onClick={handleSignup} disabled={loading}>
              {loading ? 'Creating...' : 'Create Account →'}
            </button>
            <div className="auth-note" style={{ marginTop: '14px' }}>By registering you consent to VigilAI behavioral monitoring per your organization's security policy.</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Login;
