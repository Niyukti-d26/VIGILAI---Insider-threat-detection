import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

const useStore = create(
  persist(
    (set, get) => ({
      // Auth State
      token: null,
      role: null,   // 'admin' | 'employee'
      user: null,   // full user object
      setAuth: (token, role, user) => set({ token, role, user }),
      logout: () => {
        get().disconnectWebSocket();
        set({ token: null, role: null, user: null, socket: null, isBlocked: false });
      },

      // WebSocket
      socket: null,
      isBlocked: false,

      connectWebSocket: (token, role, userId) => {
        const existing = get().socket;
        // Force close stale connections before reconnecting
        if (existing) {
          try { existing.onclose = null; existing.close(); } catch(_) {}
          set({ socket: null });
        }

        const endpoint = role === 'admin' ? 'admin' : 'employee';
        const url = `${WS_URL}/ws/${endpoint}?token=${token}`;
        const ws = new WebSocket(url);

        ws.onopen = () => {
          console.log(`[WS] ${role} WebSocket connected`);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            const { event: evtType } = data;

            if (evtType === 'connected') {
              console.log('[WS] Connected:', data.message);
              return;
            }

            // Events for admin
            if (evtType === 'file_access') {
              get().addActivityEvent(data);
              get().addAlert(data);
            }
            if (evtType === 'watch_alert') {
              get().addAlert(data);
              get().addActivityEvent(data);
            }
            if (evtType === 'threat_alert') {
              get().addAlert(data);
              get().addActivityEvent(data);
              if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
                new Notification('VigilAI Threat Alert', {
                  body: `${data.user}: ${data.message}`,
                });
              }
              playAlertSound();
            }
            if (evtType === 'baseline_breach') {
              get().addAlert(data);
              get().addActivityEvent(data);
              playAlertSound();
            }
            if (evtType === 'status_change') {
              get().addActivityEvent(data);
            }
            if (evtType === 'blocked_access_attempt') {
              get().addAlert(data);
              get().addActivityEvent(data);
              playAlertSound();
            }

            // Events for risk_update (admin sees table update, employee sees ring update)
            if (evtType === 'risk_update') {
              get().updateUserRisk(data.user_id, data.risk_score);
              // Also add to activity stream for Live Activity
              get().addActivityEvent(data);
            }

            // Events for employee
            if (evtType === 'account_blocked') {
              set({ isBlocked: true });
              get().updateUserRisk(data.user_id, data.risk_score);
              // Also update the local user object so the UI reflects blocked status
              const currentUser = get().user;
              if (currentUser && currentUser.id === data.user_id) {
                set({ user: { ...currentUser, status: 'blocked', risk_score: data.risk_score } });
              }
            }
            if (evtType === 'account_unblocked') {
              set({ isBlocked: false });
              get().updateUserRisk(data.user_id, 0);
              // Reset the local user object to normal status with 0 risk
              const currentUser = get().user;
              if (currentUser && currentUser.id === data.user_id) {
                set({ user: { ...currentUser, status: 'normal', risk_score: 0 } });
              }
            }

          } catch (e) {
            console.error('[WS] Parse error:', e);
          }
        };

        ws.onclose = () => {
          console.log('[WS] Disconnected. Reconnecting in 3s...');
          set({ socket: null });
          // Auto-reconnect after 3s
          setTimeout(() => {
            const { token: t, role: r, user: u } = get();
            if (t && r) get().connectWebSocket(t, r, u?.id);
          }, 3000);
        };

        ws.onerror = (err) => {
          console.error('[WS] Error:', err);
        };

        set({ socket: ws });
      },

      disconnectWebSocket: () => {
        const ws = get().socket;
        if (ws) {
          ws.onclose = null; // prevent auto-reconnect on intentional disconnect
          ws.close();
          set({ socket: null });
        }
      },

      // Dashboard State
      alerts: [],
      addAlert: (alert) => set((state) => ({
        alerts: [alert, ...state.alerts].slice(0, 200),
      })),
      setAlerts: (alerts) => set({ alerts }),

      // Live activity log (admin feed)
      activityEvents: [],
      addActivityEvent: (data) => set((state) => ({
        activityEvents: [{ ...data, _ts: new Date().toLocaleTimeString() }, ...state.activityEvents].slice(0, 100),
      })),

      // Per-user risk scores (keyed by user_id)
      userRiskScores: {},
      updateUserRisk: (userId, score) => set((state) => ({
        userRiskScores: { ...state.userRiskScores, [userId]: score },
      })),

      // PQC Logs
      pqcLogs: [],
      addPqcLog: (log) => set((state) => ({
        pqcLogs: [log, ...state.pqcLogs],
      })),

      // UI State
      sidebarOpen: true,
      toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
    }),
    {
      name: 'vigilai-auth',
      // Only persist auth state, not socket or runtime data
      partialize: (state) => ({ token: state.token, role: state.role, user: state.user }),
    }
  )
);

function playAlertSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.setValueAtTime(880, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.4);
    gain.gain.setValueAtTime(0.3, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.4);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.4);
  } catch (e) {}
}

export default useStore;
