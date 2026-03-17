import numpy as np
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User, AccessLog, File
from ml_engine.mdp import build_state_key, get_best_action, record_state_transition

def process_access_event(user_id: str, file_id: str, access_log_id: str):
    """
    Main entry point for evaluating risk after an access event.
    Uses the ML pipeline (Isolation Forest context + MDP Q-Table + LangGraph Agents)
    but does NOT overwrite the risk score — files.py is the source of truth for scoring.
    """
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user: return
        
        # 1. Compute Anomaly Features over last 20 events (for ML context only)
        recent_logs = db.query(AccessLog).filter(AccessLog.user_id == user_id)\
            .order_by(AccessLog.accessed_at.desc()).limit(20).all()
        
        critical_count = 0
        research_count = 0
        denied_count = 0
        sensitive_session_count = 0
        
        latest_log = recent_logs[0] if recent_logs else None
        is_off_hours = False
        if latest_log:
            h = latest_log.accessed_at.hour
            if h < 7 or h > 21:
                is_off_hours = True
        
        for log in recent_logs:
            f = db.query(File).filter(File.id == log.file_id).first()
            if log.denied:
                # Denied access ONLY counts as denied (no double-counting)
                denied_count += 1
            elif f:
                if f.type == "critical": critical_count += 1
                if f.type == "research": research_count += 1
            # Sensitive session count
            if f and f.type in ["critical", "research"] and latest_log and log.session_id == latest_log.session_id:
                sensitive_session_count += 1

        # 2. Anomaly features for agent context (NOT for scoring)
        anomaly_features = {
            "critical_count": critical_count,
            "denied_count": denied_count,
            "research_count": research_count,
            "sensitive_session_count": sensitive_session_count,
            "is_off_hours": is_off_hours
        }

        # NOTE: We do NOT recalculate or overwrite user.risk_score here.
        # The authoritative score is set by _compute_risk_score() in files.py.
        # This pipeline is for ML context, Q-table learning, and agent orchestration only.
        current_score = user.risk_score

        # 3. Q-Table lookup for action
        state_key = build_state_key(critical_count, denied_count, is_off_hours)
        best_mdp_action = get_best_action(state_key, db)
        
        # Save state for future RL feedback
        record_state_transition(user_id, state_key, best_mdp_action)

        # 4. Trigger LangGraph Orchestration
        from agents.graph import run_agent_workflow
        
        initial_state = {
            "user_id": user_id,
            "risk_score": int(current_score),
            "anomaly_features": anomaly_features,
            "recommended_action": best_mdp_action,
            "alert_payload": {},
            "pqc_signed": False,
            "pqc_encrypted": False,
            "final_action": ""
        }
        
        run_agent_workflow(initial_state)

    finally:
        db.close()
