import asyncio
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from database import get_db, SessionLocal
from models import User, File, AccessLog, Alert
from .auth import get_current_user
from security.pqc import sign_alert, encrypt_alert

router = APIRouter()


def _compute_risk_score(user_id: str, db: Session) -> dict:
    """
    Computes updated risk score using last 20 access events.
    Returns score + anomaly feature vector.
    """
    recent_logs = (
        db.query(AccessLog)
        .filter(AccessLog.user_id == user_id)
        .order_by(AccessLog.accessed_at.desc())
        .limit(20)
        .all()
    )

    critical_count = 0
    research_count = 0
    denied_count = 0
    sensitive_session_count = 0
    is_off_hours = False

    latest_log = recent_logs[0] if recent_logs else None
    if latest_log:
        h = latest_log.accessed_at.hour
        is_off_hours = h < 7 or h > 21

    current_session = latest_log.session_id if latest_log else ""

    for log in recent_logs:
        f = db.query(File).filter(File.id == log.file_id).first()
        if log.denied:
            # Denied access ONLY counts as denied — do NOT also count as critical/research
            denied_count += 1
        elif f:
            # Only count actual successful accesses toward file-type risk
            if f.type == "critical":
                critical_count += 1
            if f.type == "research":
                research_count += 1
        # Sensitive session count (regardless of denied)
        if f and f.type in ["critical", "research"] and log.session_id == current_session:
            sensitive_session_count += 1

    # Risk scoring — only suspicious activity increases score
    # General file access does NOT increase risk
    score = 5.0
    score += critical_count * 12       # +12 per critical file accessed
    score += denied_count * 8          # +8 per denied attempt
    score += research_count * 3        # +3 per research file accessed

    if sensitive_session_count >= 7:
        score += 15
    elif sensitive_session_count >= 4:
        score += 10

    if is_off_hours:
        score += 12

    final_score = min(score, 98.0)

    return {
        "score": final_score,
        "features": {
            "critical_count": critical_count,
            "denied_count": denied_count,
            "research_count": research_count,
            "sensitive_session_count": sensitive_session_count,
            "is_off_hours": is_off_hours,
        },
    }


def _broadcast_all_events(
    user_id: str,
    user_name: str,
    score: float,
    features: dict,
    file_name: str,
    file_type: str,
    denied: bool,
    timestamp: str,
    prev_score: float = 0.0,
):
    """
    Called from a background thread after EVERY file access (any risk level).
    Broadcasts:
      - file_access      → all admins (always)
      - risk_update       → all admins + employee (always)
      - baseline_breach   → all admins (if score crosses 50% for first time)
      - watch_alert       → all admins (if 50 ≤ score < 99)
      - threat_alert      → all admins + employee blocked (if score ≥ 99)
    """
    from routers.ws import manager

    db2 = SessionLocal()
    try:
        user = db2.query(User).filter(User.id == user_id).first()
        if not user:
            return

        # 1. Always send file_access event to admins
        access_event = {
            "event": "file_access",
            "user": user_name,
            "user_id": user_id,
            "file_name": file_name,
            "file_type": file_type,
            "denied": denied,
            "risk_score": int(score),
            "prev_score": int(prev_score),
            "risk_delta": int(score - prev_score),
            "timestamp": timestamp,
        }
        manager.broadcast_from_thread(access_event)

        # 2. Always send risk_update to admins
        risk_event = {
            "event": "risk_update",
            "user_id": user_id,
            "user": user_name,
            "risk_score": int(score),
            "timestamp": timestamp,
        }
        manager.broadcast_from_thread(risk_event)
        # Also notify the employee themselves
        manager.send_to_employee_from_thread(user_id, risk_event)

        # 2.5. Baseline crossing detection — ML behavioral baseline at 50%
        if prev_score < 50 and score >= 50:
            alert_id = f"ALT-{str(uuid.uuid4().int)[:4]}"
            baseline_msg = f"ML Baseline Breach: {user_name}'s behavior has deviated from their normal pattern. Risk elevated from {int(prev_score)}% to {int(score)}%. Behavioral anomaly detected by Isolation Forest + Q-Table."
            payload_for_pqc = {
                "id": alert_id, "user_id": user_id, "user_name": user_name,
                "risk_score": int(score), "type": "baseline_breach", "message": baseline_msg,
                "timestamp": timestamp,
            }
            sign_data = sign_alert(payload_for_pqc)
            enc_data = encrypt_alert(payload_for_pqc, sign_data)

            db_alert = Alert(
                id=alert_id, user_id=user_id, risk_score=int(score),
                type="baseline_breach", message=baseline_msg,
            )
            db2.add(db_alert)
            db2.commit()

            baseline_event = {
                "event": "baseline_breach",
                "alert_id": alert_id,
                "user": user_name,
                "user_id": user_id,
                "risk_score": int(score),
                "prev_score": int(prev_score),
                "type": "baseline_breach",
                "message": baseline_msg,
                "pqc": enc_data,
                "timestamp": timestamp,
            }
            manager.broadcast_from_thread(baseline_event)
            print(f"[ML] Baseline breach → {user_name}. Score crossed 50%: {int(prev_score)}% → {int(score)}%")

        if score >= 99:
            # Block the user automatically if not already blocked
            if user.status != "blocked":
                user.status = "blocked"
                db2.commit()

            alert_type = "threat"
            action = "BLOCKED"
            if denied:
                msg = f"Unauthorized access attempt to '{file_name}'. Clearance violation. Risk elevated to {int(score)}%."
            else:
                what = "Critical" if features.get("critical_count", 0) > 1 else "Research"
                msg = f"Insider threat detected: elevated {what.lower()} file access. {features.get('sensitive_session_count', 0)} sensitive files in session. Risk: {int(score)}%."

            alert_id = f"ALT-{str(uuid.uuid4().int)[:4]}"
            payload_for_pqc = {
                "id": alert_id, "user_id": user_id, "user_name": user_name,
                "risk_score": int(score), "type": alert_type, "message": msg,
                "timestamp": timestamp,
            }
            sign_data = sign_alert(payload_for_pqc)
            enc_data = encrypt_alert(payload_for_pqc, sign_data)

            db_alert = Alert(
                id=alert_id, user_id=user_id, risk_score=int(score),
                type=alert_type, message=msg,
            )
            db2.add(db_alert)
            db2.commit()

            threat_event = {
                "event": "threat_alert",
                "alert_id": alert_id,
                "user": user_name,
                "user_id": user_id,
                "risk_score": int(score),
                "type": alert_type,
                "message": msg,
                "action": action,
                "pqc": enc_data,
                "timestamp": timestamp,
            }
            manager.broadcast_from_thread(threat_event)

            # Notify employee they're blocked
            blocked_event = {
                "event": "account_blocked",
                "user_id": user_id,
                "risk_score": int(score),
                "message": "Your account has been restricted due to high-risk behavior.",
                "timestamp": timestamp,
            }
            manager.send_to_employee_from_thread(user_id, blocked_event)
            print(f"[ALERT] Threat {alert_id} → {user_name} blocked. Score={int(score)}")

        elif score >= 50:
            # Update user status to watch if not already elevated
            if user.status == "normal":
                user.status = "watch"
                db2.commit()

            alert_type = "suspicious"
            action = "WATCH"
            if denied:
                msg = f"Unauthorized access attempt to '{file_name}'. Risk elevated to {int(score)}%."
            else:
                msg = f"Suspicious access pattern: elevated file access. Risk score: {int(score)}%."

            alert_id = f"ALT-{str(uuid.uuid4().int)[:4]}"
            payload_for_pqc = {
                "id": alert_id, "user_id": user_id, "user_name": user_name,
                "risk_score": int(score), "type": alert_type, "message": msg,
                "timestamp": timestamp,
            }
            sign_data = sign_alert(payload_for_pqc)
            enc_data = encrypt_alert(payload_for_pqc, sign_data)

            db_alert = Alert(
                id=alert_id, user_id=user_id, risk_score=int(score),
                type=alert_type, message=msg,
            )
            db2.add(db_alert)
            db2.commit()

            watch_event = {
                "event": "watch_alert",
                "alert_id": alert_id,
                "user": user_name,
                "user_id": user_id,
                "risk_score": int(score),
                "type": alert_type,
                "message": msg,
                "action": action,
                "pqc": enc_data,
                "timestamp": timestamp,
            }
            manager.broadcast_from_thread(watch_event)

            # Also notify employee of elevated status
            watch_emp_event = {
                "event": "risk_update",
                "user_id": user_id,
                "risk_score": int(score),
                "status": "watch",
                "timestamp": timestamp,
            }
            manager.send_to_employee_from_thread(user_id, watch_emp_event)
            print(f"[ALERT] Watch {alert_id} → {user_name}. Score={int(score)}")

    except Exception as e:
        print(f"[ALERT] Broadcast error: {e}")
    finally:
        db2.close()


@router.get("/")
def get_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return db.query(File).all()


@router.post("/{file_id}/access")
async def access_file(
    file_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    import threading

    file_obj = db.query(File).filter(File.id == file_id).first()
    if not file_obj:
        raise HTTPException(status_code=404, detail="File not found")

    timestamp = datetime.utcnow().isoformat()

    # If user is blocked, still broadcast an alert to admin and reject
    if current_user.status == "blocked":
        def _alert_blocked():
            from routers.ws import manager
            blocked_event = {
                "event": "blocked_access_attempt",
                "user": current_user.name,
                "user_id": current_user.id,
                "file_name": file_obj.name,
                "file_type": file_obj.type,
                "risk_score": int(current_user.risk_score or 0),
                "message": f"BLOCKED user {current_user.name} attempted to access {file_obj.name} ({file_obj.type})",
                "timestamp": timestamp,
            }
            print(f"[BROADCAST] Blocked user attempt: {current_user.name} → {file_obj.name}")
            manager.broadcast_from_thread(blocked_event)
        threading.Thread(target=_alert_blocked, daemon=True).start()
        raise HTTPException(status_code=403, detail="Account is blocked.")

    denied = current_user.clearance_level < file_obj.clearance_required
    risk_delta = file_obj.risk_weight if not denied else file_obj.risk_weight + 15
    client_host = request.client.host

    # Log the access
    log = AccessLog(
        user_id=current_user.id,
        file_id=file_obj.id,
        denied=denied,
        ip_address=client_host,
        risk_delta=risk_delta,
        session_id="session_" + current_user.id[:8],
    )
    db.add(log)
    db.commit()
    db.refresh(log)

    # Capture previous score for baseline crossing detection
    prev_score = current_user.risk_score or 0.0

    # Compute updated risk score
    result = _compute_risk_score(current_user.id, db)
    new_score = result["score"]
    features = result["features"]

    # Update user risk score in DB
    current_user.risk_score = new_score
    db.commit()

    print(f"[ACCESS] {current_user.name} → {file_obj.name} ({file_obj.type}) | denied={denied} | score: {int(prev_score)}% → {int(new_score)}%")

    # Broadcast ALL events in background (non-blocking)
    t = threading.Thread(
        target=_broadcast_all_events,
        args=(
            current_user.id,
            current_user.name,
            new_score,
            features,
            file_obj.name,
            file_obj.type,
            denied,
            timestamp,
            prev_score,
        ),
        daemon=True,
    )
    t.start()

    # Also run the full ML pipeline
    def _run_ml_pipeline():
        try:
            from ml_engine.anomaly import process_access_event
            process_access_event(current_user.id, file_obj.id, log.id)
        except Exception as e:
            print(f"[ML] Pipeline error (non-fatal): {e}")

    threading.Thread(target=_run_ml_pipeline, daemon=True).start()

    if denied:
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: Insufficient Clearance. Risk score updated to {int(new_score)}%.",
        )

    return {
        "message": f"Successfully accessed {file_obj.name}",
        "file": {"id": file_obj.id, "name": file_obj.name},
        "risk_score": int(new_score),
    }

