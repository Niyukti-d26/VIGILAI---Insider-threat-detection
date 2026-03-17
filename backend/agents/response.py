from datetime import datetime
import uuid
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User, Alert
from langchain_core.messages import SystemMessage, HumanMessage

def execute_response_action(state: dict, llm) -> dict:
    score = state["risk_score"]
    user_id = state["user_id"]
    agent_msg = state.get("messages", ["Detected unexpected behavior."])[0]
    
    action = "watch"
    alert_type = "suspicious"
    if score >= 75:
        action = "blocked"
        alert_type = "threat"
    
    state["final_action"] = action
    
    # Execute action in DB
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            # We don't overwrite if already blocked unless we want to, but logically 
            # if we score >= 75 we definitively block them.
            user.status = action
            
            # Generate short alert message using LLM
            sys_msg = SystemMessage(content="You are the VigilAI Response Agent. Summarize the threat into a single concise sentence for the admin alert dashboard.")
            hum_msg = HumanMessage(content=f"Threat Detection output: {agent_msg}. Action taken: {action}.")
            response = llm.invoke([sys_msg, hum_msg])
            short_message = response.content.strip('"')
            
            # Create Alert in DB without PQC first, we'll generate ID
            alert_id = f"ALT-{str(uuid.uuid4().int)[:4]}"
            
            # We construct the payload here
            payload = {
                "id": alert_id,
                "user_id": user_id,
                "user_name": user.name,
                "risk_score": score,
                "type": alert_type,
                "message": short_message,
                "action": action.upper(),
                "timestamp": datetime.utcnow().isoformat()
            }
            state["alert_payload"] = payload
            
            # Wait to save Alert to DB until PQC is attached or just save it initially
            # We'll save it after PQC node in a real scenario, or save a draft here.
            # For simplicity, we save it here, then update it later, or just save it here with empty PQC fields.
            db_alert = Alert(
                id=alert_id,
                user_id=user_id,
                risk_score=score,
                type=alert_type,
                message=short_message
            )
            db.add(db_alert)
            db.commit()
            
    finally:
        db.close()
        
    return state
