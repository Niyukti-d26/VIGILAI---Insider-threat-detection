from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel

from database import get_db
from models import User, AccessLog, File
from .auth import get_current_user, get_current_admin

router = APIRouter()

class UserOut(BaseModel):
    id: str
    name: str
    email: str
    role: str
    department: str
    clearance_level: int
    risk_score: float
    status: str

    class Config:
        from_attributes = True

class ActivityOut(BaseModel):
    id: str
    file_id: str
    file_name: Optional[str] = None
    accessed_at: str
    denied: bool
    risk_delta: float
    ip_address: Optional[str] = None

    class Config:
        from_attributes = True


def _get_activity_logs(user_id: str, limit: int, db: Session):
    logs = (
        db.query(AccessLog)
        .filter(AccessLog.user_id == user_id)
        .order_by(AccessLog.accessed_at.desc())
        .limit(limit)
        .all()
    )
    result = []
    for log in logs:
        file_obj = db.query(File).filter(File.id == log.file_id).first()
        result.append({
            "id": log.id,
            "file_id": log.file_id,
            "file_name": file_obj.name if file_obj else log.file_id,
            "accessed_at": log.accessed_at.isoformat(),
            "denied": log.denied,
            "risk_delta": log.risk_delta,
            "ip_address": log.ip_address,
        })
    return result


@router.get("/me", response_model=UserOut)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/me/activity")
async def get_my_activity(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns the current user's last N file access events, enriched with file name."""
    return _get_activity_logs(current_user.id, limit, db)


@router.get("/risk-scores")
async def get_all_risk_scores(
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """Returns all employees with their current risk scores."""
    users = db.query(User).filter(User.role == "employee").all()
    return [
        {"id": u.id, "name": u.name, "department": u.department,
         "risk_score": u.risk_score, "status": u.status}
        for u in users
    ]


@router.get("/", response_model=List[UserOut])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@router.get("/{user_id}/activity")
async def get_user_activity(
    user_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    """Admin: Returns specific user's file access events."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _get_activity_logs(user_id, limit, db)


@router.post("/{user_id}/status")
async def update_user_status(
    user_id: str,
    status: str,
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    if status not in ["normal", "watch", "blocked"]:
        raise HTTPException(status_code=400, detail="Invalid status")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.status = status
    if status == "normal":
        # Reset risk score to 0 and clear access history so old logs don't re-inflate
        user.risk_score = 0.0
        db.query(AccessLog).filter(AccessLog.user_id == user_id).delete()

    db.commit()
    db.refresh(user)

    from datetime import datetime
    from routers.ws import manager
    import threading
    ts = datetime.utcnow().isoformat()

    if status == "blocked":
        # Notify employee in real-time
        blocked_msg = {
            "event": "account_blocked",
            "user_id": user_id,
            "risk_score": int(user.risk_score),
            "message": "Your account has been restricted by a security administrator.",
            "timestamp": ts,
        }
        threading.Thread(
            target=manager.send_to_employee_from_thread,
            args=(user_id, blocked_msg),
            daemon=True,
        ).start()
    elif status == "normal":
        # Notify employee they're unblocked with reset score
        unblocked_msg = {
            "event": "account_unblocked",
            "user_id": user_id,
            "risk_score": 0,
            "message": "Your account restrictions have been lifted. Risk score reset to 0%.",
            "timestamp": ts,
        }
        threading.Thread(
            target=manager.send_to_employee_from_thread,
            args=(user_id, unblocked_msg),
            daemon=True,
        ).start()

    # Broadcast status change to all admins (includes risk_update for table)
    admin_msg = {
        "event": "status_change",
        "user_id": user_id,
        "user": user.name,
        "status": status,
        "risk_score": int(user.risk_score),
        "message": f"Admin manually set {user.name}'s status to {status}",
        "timestamp": ts,
    }
    threading.Thread(
        target=manager.broadcast_from_thread,
        args=(admin_msg,),
        daemon=True,
    ).start()

    # Also send a risk_update event so admin tables reflect the new score
    risk_msg = {
        "event": "risk_update",
        "user_id": user_id,
        "risk_score": int(user.risk_score),
        "status": status,
        "timestamp": ts,
    }
    threading.Thread(
        target=manager.broadcast_from_thread,
        args=(risk_msg,),
        daemon=True,
    ).start()

    return {"message": f"User {user.email} status set to {status}", "user": UserOut.model_validate(user)}
