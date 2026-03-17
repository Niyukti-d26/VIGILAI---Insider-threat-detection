# VigilAI — AI-Powered Insider Threat Detection System

## Problem Statement

Insider threats account for over 60% of data breaches in organizations. Traditional security systems focus on external attackers while neglecting the risk posed by authorized users — employees who misuse their access to sensitive files, intellectual property, and confidential data. Existing solutions rely on rigid rule-based thresholds that generate excessive false positives and fail to adapt to individual behavioral patterns.

Organizations lack a system that can:
- Monitor employee file access behavior in real time
- Learn individual baselines and detect anomalous deviations per user
- Automatically escalate, restrict, or block access based on evolving risk
- Provide administrators with actionable intelligence, not noise
- Secure the alert pipeline itself against quantum-era cryptographic threats

## Solution

VigilAI is a full-stack insider threat detection platform that combines real-time behavioral monitoring, machine learning anomaly detection, reinforcement learning from admin feedback, and post-quantum cryptography to detect, alert, and respond to insider threats autonomously.

### Core Architecture

```
Employee Dashboard          Admin Dashboard
       |                          |
       v                          v
   File Access API  <----->  WebSocket (Real-Time)
       |                          |
       v                          v
  Risk Scoring Engine       Live Activity Feed
       |                    Alert Feed (DB-persisted)
       v                          |
  ML Pipeline                     v
  (Isolation Forest +        Admin Actions
   MDP Q-Table +             (Block / Unblock /
   LangGraph Agents)          Resolve Alerts)
       |                          |
       v                          v
  PQC Layer                  RL Feedback Loop
  (Kyber-768 +               (Q-Table learns from
   Dilithium-3)               admin decisions)
```

### Key Components

**Behavioral Risk Scoring** — Every file access is scored based on file sensitivity, access patterns, and session context. Critical files contribute +12%, denied access attempts +8%, research files +3%. Bulk access patterns trigger additional penalties. General file access does not increase risk.

**ML Anomaly Detection** — An Isolation Forest model evaluates feature vectors (file counts by type, denied rates, session patterns) to detect behavioral outliers. The system establishes a personalized baseline for each user and triggers alerts when behavior deviates from their norm.

**Reinforcement Learning** — A Markov Decision Process (MDP) with a Q-table learns from administrator responses to alerts. When an admin confirms a threat, the system reinforces its detection; when an alert is dismissed as a false positive, it adjusts. This feedback loop reduces false positives over time.

**LangGraph Agent Orchestration** — A multi-agent pipeline powered by Google Gemini processes anomaly results through specialized agents (Anomaly Scorer, Context Enricher, Response Recommender) to generate human-readable, actionable alert descriptions.

**Post-Quantum Cryptography** — All alerts are signed with Dilithium-3 and encrypted with Kyber-768 (NIST PQC standards) before transmission, ensuring the integrity and confidentiality of the security pipeline against future quantum attacks.

**Real-Time Dashboards** — WebSocket-powered live activity feeds show every file access event (user, file, type, status) to administrators instantly. Alerts appear in a persistent feed with PQC verification badges and admin action buttons.

### Risk Thresholds

| Score | Status | Action |
|-------|--------|--------|
| 0–49% | Normal | Standard monitoring |
| 50–98% | Watch | Elevated monitoring, baseline breach alert generated |
| 99%+ | Blocked | Account auto-suspended, all access revoked |

### User Roles

- **Employee** — Accesses files, views personal risk profile and activity log. Receives real-time risk score updates. If blocked, sees full-screen suspension popup.
- **Admin** — Monitors all employees via live activity feed, alert feed, user risk table, and analytics charts. Can block/unblock users, resolve alerts, and provide feedback that trains the ML model.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy, Uvicorn |
| Frontend | React (Vite), Zustand, Recharts |
| ML/AI | Scikit-learn (Isolation Forest), MDP Q-Table, LangGraph, Google Gemini |
| Security | Kyber-768, Dilithium-3 (PQC), SHA3-256, AES-256-GCM, JWT, Bcrypt |
| Real-Time | WebSockets (native FastAPI + websockets) |
| Database | SQLite (dev), PostgreSQL-ready (prod) |

## Project Structure

```
vigilai/
├── backend/
│   ├── main.py                 # FastAPI application entry point
│   ├── database.py             # SQLAlchemy engine and session
│   ├── models.py               # User, File, AccessLog, Alert, PQCSession
│   ├── seed.py                 # Database seeding (demo users, files)
│   ├── requirements.txt        # Python dependencies
│   ├── Dockerfile              # Backend container
│   ├── routers/
│   │   ├── auth.py             # JWT auth, login, signup
│   │   ├── files.py            # File access, risk scoring, WS events
│   │   ├── users.py            # User management, block/unblock
│   │   ├── alerts.py           # Alert CRUD, PQC verification, resolve
│   │   └── ws.py               # WebSocket connection manager
│   ├── ml_engine/
│   │   ├── anomaly.py          # Isolation Forest + feature extraction
│   │   ├── baseline.py         # Per-user behavioral baseline computation
│   │   └── mdp.py              # MDP Q-table reinforcement learning
│   ├── agents/
│   │   ├── graph.py            # LangGraph agent pipeline
│   │   └── response.py         # Response recommendation agent
│   └── security/
│       └── pqc.py              # Kyber-768 + Dilithium-3 implementation
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Router and layout
│   │   ├── index.css           # Design system and global styles
│   │   ├── store/
│   │   │   └── useStore.js     # Zustand state management + WS handling
│   │   ├── pages/
│   │   │   ├── AdminDashboard.jsx
│   │   │   ├── EmployeeDashboard.jsx
│   │   │   └── Login.jsx
│   │   └── components/
│   │       ├── AlertFeed.jsx   # Alert display with PQC badges
│   │       ├── FileSystem.jsx  # File browser for employees
│   │       ├── RiskProfile.jsx # Employee risk breakdown
│   │       ├── RiskChart.jsx   # Analytics charts
│   │       └── UserRiskTable.jsx # Admin user monitoring table
│   └── package.json
├── docker-compose.yml
├── .env.example
└── .gitignore
```

## Setup

### Prerequisites
- Python 3.10+
- Node.js 18+

### Backend

```bash
cd backend

# Create virtual environment
python -m venv ../venv
source ../venv/bin/activate  # Linux/Mac
# ..\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Set environment variables (copy and edit)
cp ../.env.example ../.env
# Edit ../.env with your values

# Run the server
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Run dev server
npm run dev
```

The frontend runs at `http://localhost:5173` and the backend at `http://localhost:8000`.

### Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@vigilai.io | admin123 |
| Employee | sarah.chen@company.com | employee123 |
| Employee | james.wilson@company.com | employee123 |
| Employee | priya.patel@company.com | employee123 |

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `JWT_SECRET` | Secret key for JWT token signing | Yes |
| `GEMINI_API_KEY` / `GOOGLE_API_KEY` | Google Gemini API key for LangGraph agents | Optional (agents degrade gracefully) |
| `VITE_API_URL` | Backend API URL for frontend | No (defaults to same origin) |
| `VITE_WS_URL` | WebSocket URL for frontend | No (defaults to same origin) |

## How It Works

1. An employee logs in and accesses files through the file browser
2. Each file access is logged and scored based on file type (critical/research/general) and access outcome (granted/denied)
3. The risk score accumulates — general files don't increase risk, but critical (+12%) and research (+3%) files do
4. When the score crosses 50%, a baseline breach alert is generated, PQC-signed, and broadcast to the admin dashboard
5. The ML pipeline (Isolation Forest) evaluates the access pattern for anomalies
6. LangGraph agents generate a human-readable alert description using Gemini
7. The admin sees the alert in the Alert Feed with full details, PQC verification, and action buttons
8. The admin can confirm or dismiss the alert — this feedback trains the RL Q-table
9. At 99%, the account is automatically suspended and the employee sees a full-screen suspension popup
10. The admin can unblock the user, which resets their risk score to 0%

## License

This project is developed for academic and research purposes.
