import json
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from models import AccessLog, User, File

def get_user_baseline(db: Session, user_id: str, current_time: datetime = None) -> dict:
    """
    Computes a simplified baseline for the user over the past 30 events
    (Mocked pandas replacement for native execution)
    """
    if not current_time:
        current_time = datetime.utcnow()
        
    # Get last 30 events
    recent_logs = db.query(AccessLog).filter(AccessLog.user_id == user_id)\
        .order_by(AccessLog.accessed_at.desc()).limit(30).all()
        
    if not recent_logs:
        return {"mean_risk": 0.0, "std_risk": 0.0, "event_count": 0}
        
    risks = [log.risk_delta for log in recent_logs]
    denied = [1 if log.denied else 0 for log in recent_logs]
    
    mean_risk = sum(risks) / len(risks)
    std_risk = 0.0 # Mocked standard dev
        
    return {
        "mean_risk": round(mean_risk, 2),
        "std_risk": round(std_risk, 2),
        "event_count": len(risks),
        "denied_rate": round(sum(denied) / len(denied), 2)
    }
