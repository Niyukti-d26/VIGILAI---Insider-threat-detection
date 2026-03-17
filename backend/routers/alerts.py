from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
import json

from database import get_db
from models import Alert, PQCSession, User
from .auth import get_current_admin

router = APIRouter()

class AlertOut(BaseModel):
    id: str
    user_id: str
    risk_score: float
    type: str
    message: str
    dilithium_signature: str
    kyber_ciphertext_hash: str
    hash_algorithm: str
    resolved: bool
    created_at: str

    class Config:
        from_attributes = True

class VerifyPayload(BaseModel):
    encrypted_payload: str
    kyber_public_key: str # In real scenario, client or PQC agent sends it

@router.get("/", response_model=List[dict])
async def list_alerts(db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(100).all()
    # Format to dict, include user
    res = []
    for a in alerts:
        res.append({
            "id": a.id,
            "user_id": a.user_id,
            "user_name": a.user.name if a.user else "Unknown",
            "risk_score": a.risk_score,
            "type": a.type,
            "message": a.message,
            "kyber_ciphertext_hash": a.kyber_ciphertext_hash,
            "dilithium_signature": a.dilithium_signature,
            "resolved": a.resolved,
            "created_at": a.created_at.isoformat()
        })
    return res

@router.post("/verify")
async def verify_alert(
    payload: dict, # expecting the web socket event payload
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    """
    Decapsulates the Kyber shared secret, decrypts the AES-GCM payload, 
    and verifies the Dilithium2 signature. Returns verified JSON.
    """
    # Import from security layer
    from security.pqc import verify_alert_payload
    verified_data = verify_alert_payload(payload)
    if not verified_data.get("verified"):
        raise HTTPException(status_code=400, detail="Signature verification failed")
    
    # Optionally store verification in PQCSession
    alert_id = verified_data["alert_id"]
    pqc_log = PQCSession(
        alert_id=alert_id,
        signature_verified=True,
        kyber_enc_hash=verified_data["kyber_enc_hash"],
        dilithium_sig_hash=verified_data["dilithium_sig_hash"]
    )
    db.add(pqc_log)
    db.commit()

    return verified_data

@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: str,
    payload: dict, # expects {"outcome": "confirmed"} or {"outcome": "dismissed"}
    db: Session = Depends(get_db),
    admin: User = Depends(get_current_admin)
):
    outcome = payload.get("outcome")
    if outcome not in ["confirmed", "dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid outcome, must be confirmed or dismissed")
    
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.resolved = True
    db.commit()

    # Trigger MDP RL Feedback Loop
    from ml_engine.mdp import rl_feedback_loop
    # Confirmed threat → reward +10, dismissed false positive → reward -5
    reward = 10 if outcome == "confirmed" else -5
    # The MDP gets updated based on the state sequence that led to this alert.
    # We pass the user id so it knows which recent context to update.
    rl_feedback_loop(alert.user_id, reward)

    return {"message": "Alert resolved", "outcome": outcome}
