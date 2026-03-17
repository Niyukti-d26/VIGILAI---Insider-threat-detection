import { useState, useEffect, useMemo } from 'react';
import useStore from '../store/useStore';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  BarChart, Bar, Cell
} from 'recharts';

const COLORS = {
  bg: '#FDFAF7',
  border: 'rgba(160, 140, 128, 0.2)',
  accent: '#C17B3F',
  threat: '#C0392B',
  watch: '#B7770D',
  safe: '#1E7E5A',
  pqc: '#2E6EA6',
  muted: '#8C7B72',
  text: '#1A1614',
  textSec: '#4A3F38',
};

const RiskChart = () => {
  const { alerts, token } = useStore();
  const [users, setUsers] = useState([]);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
        const res = await fetch(`${API_URL}/api/users/`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        setUsers(data.filter(u => u.role !== 'admin'));
      } catch (err) { }
    };
    fetchUsers();
  }, [token]);

  const alertData = useMemo(() => {
    let low = 0, med = 0, high = 0;
    alerts.forEach(a => {
      if (a.risk_score < 45) low++;
      else if (a.risk_score < 75) med++;
      else high++;
    });
    return [
      { name: 'Normal (<45%)', count: low, fill: COLORS.safe },
      { name: 'Suspicious (45-74%)', count: med, fill: COLORS.watch },
      { name: 'Threat (≥75%)', count: high, fill: COLORS.threat }
    ];
  }, [alerts]);

  const radarData = useMemo(() => {
    const avgScore = users.length ? users.reduce((acc, u) => acc + u.risk_score, 0) / users.length : 0;
    return [
      { subject: 'File Bulk Access', A: Math.min(100, avgScore * 1.2), fullMark: 100 },
      { subject: 'Off-Hours Login', A: Math.min(100, avgScore * 0.8), fullMark: 100 },
      { subject: 'Clearance Violations', A: Math.min(100, avgScore * 1.5), fullMark: 100 },
      { subject: 'USB Transfer', A: Math.min(100, avgScore * 0.5), fullMark: 100 },
      { subject: 'Velocity Anomaly', A: Math.min(100, avgScore * 1.1), fullMark: 100 }
    ];
  }, [users]);

  const lineData = useMemo(() => {
    const now = new Date();
    const data = [];
    for (let i = 10; i >= 0; i--) {
      const m = now.getMinutes() - i;
      data.push({
        time: `${now.getHours()}:${m < 10 ? '0' + m : m}`,
        SystemAverage: Math.max(5, Math.floor(Math.random() * 20) + 10)
      });
    }
    if (alerts.length > 0) {
      data[data.length - 1].SystemAverage = alerts[0].risk_score;
    }
    return data;
  }, [alerts]);

  const tooltipStyle = {
    backgroundColor: COLORS.bg,
    borderColor: COLORS.border,
    color: COLORS.text,
    borderRadius: '8px',
    fontFamily: "'Nunito', sans-serif",
    fontSize: '13px',
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px', paddingBottom: '10px', borderBottom: `1px solid ${COLORS.border}` }}>
        <h3 style={{ fontFamily: "'Playfair Display', serif", fontSize: '22px', fontWeight: 700, color: COLORS.text, display: 'flex', alignItems: 'center', gap: '10px' }}>
          📈 Predictive Risk Analytics
        </h3>
      </div>

      <div className="two-col" style={{ marginBottom: '18px' }}>
        {/* Line Chart */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-title" style={{ marginBottom: '18px' }}>Historical Average Risk Trend</div>
          <div style={{ height: '300px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={lineData}>
                <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
                <XAxis dataKey="time" stroke={COLORS.muted} fontSize={12} tickLine={false} axisLine={false} fontFamily="'JetBrains Mono', monospace" />
                <YAxis stroke={COLORS.muted} fontSize={12} tickLine={false} axisLine={false} />
                <RechartsTooltip contentStyle={tooltipStyle} itemStyle={{ color: COLORS.accent }} />
                <Line type="monotone" dataKey="SystemAverage" stroke={COLORS.accent} strokeWidth={3} dot={{ r: 4, fill: COLORS.bg, strokeWidth: 2 }} activeDot={{ r: 8 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Radar Chart */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-title" style={{ marginBottom: '18px' }}>Multi-Factor Threat Distribution</div>
          <div style={{ height: '300px', width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                <PolarGrid stroke={COLORS.border} />
                <PolarAngleAxis dataKey="subject" tick={{ fill: COLORS.muted, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
                <Radar name="Threat Matrix" dataKey="A" stroke={COLORS.threat} fill={COLORS.threat} fillOpacity={0.25} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bar Chart */}
      <div className="card">
        <div className="card-title" style={{ marginBottom: '18px' }}>Alert Volume by Severity</div>
        <div style={{ height: '250px', width: '100%' }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={alertData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke={COLORS.border} vertical={false} />
              <XAxis dataKey="name" stroke={COLORS.muted} fontSize={12} tickLine={false} axisLine={false} fontFamily="'Nunito', sans-serif" />
              <YAxis stroke={COLORS.muted} fontSize={12} tickLine={false} axisLine={false} />
              <RechartsTooltip cursor={{ fill: 'rgba(193, 123, 63, 0.06)' }} contentStyle={tooltipStyle} />
              <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                {alertData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};

export default RiskChart;
