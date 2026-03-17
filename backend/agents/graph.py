import os
import json
import asyncio
from typing import TypedDict
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import SystemMessage, HumanMessage
from langgraph.graph import StateGraph, START, END

from dotenv import load_dotenv
load_dotenv()

# Shared LLM - one instance as requested
llm = ChatGoogleGenerativeAI(
    model="gemini-1.5-flash", 
    google_api_key=os.getenv("GOOGLE_API_KEY", "mock-key-for-now")
)

class VigilState(TypedDict):
    user_id: str
    risk_score: int
    anomaly_features: dict
    recommended_action: str
    alert_payload: dict
    pqc_signed: bool
    pqc_encrypted: bool
    final_action: str
    messages: list

def detection_node(state: VigilState):
    """
    Detection Agent node. Analyzes the anomaly features and the MDP recommendation,
    classifies the threat, and decides if it really needs escalation.
    """
    score = state["risk_score"]
    features = state["anomaly_features"]
    
    # Simple prompt for the agent to review the stats
    sys_msg = SystemMessage(content="You are the VigilAI Detection Agent. Classify the threat level based on the risk score and features given. "
                                    "Provide a short summary message explaining the anomaly.")
    hum_msg = HumanMessage(content=f"Risk Score: {score}. Features: {json.dumps(features)}. Recommend Action from MDP: {state['recommended_action']}.")
    
    response = llm.invoke([sys_msg, hum_msg])
    
    state["messages"] = [response.content]
    
    return state

def routing_function(state: VigilState):
    """
    Conditional routing as requested:
    score < 45   → END (no alert)
    score 45–74  → response_node(action=watch)
    score ≥ 75   → response_node(action=block)
    """
    score = state["risk_score"]
    if score < 45:
        return END
    else:
        return "response_node"

def response_node(state: VigilState):
    """
    Response Agent node. Responsible for executing the action and generating the alert.
    We'll do this directly via Python functions imported from handlers.
    """
    from .response import execute_response_action
    
    # We must run this async or in background if it takes time, but LangGraph handles sync/async
    updated_state = execute_response_action(state, llm)
    return updated_state

def pqc_node(state: VigilState):
    """
    Passes the generated alert payload to the PQC Security Layer.
    """
    from security.pqc import sign_alert, encrypt_alert
    
    payload = state.get("alert_payload", {})
    if payload:
        sign_data = sign_alert(payload)
        enc_data = encrypt_alert(payload, sign_data)
        
        # Combine everything for the WebSocket broadcast
        final_ws_message = {
            "event": "threat_alert",
            "alert_id": payload["id"],
            "user": payload.get("user_name"),
            "risk_score": payload["risk_score"],
            "type": payload["type"],
            "message": payload["message"],
            "action": payload["action"],
            "pqc": enc_data,
            "timestamp": payload.get("timestamp")
        }
        
        # Broadcast via WebSockets
        from routers.ws import manager
        
        # manager.broadcast_alert is async, so we need to schedule it or run it in an event loop
        # Since run_agent_workflow might not be in an async context, we can use asyncio.run or create a task
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(manager.broadcast_alert(final_ws_message))
            else:
                loop.run_until_complete(manager.broadcast_alert(final_ws_message))
        except Exception:
            asyncio.run(manager.broadcast_alert(final_ws_message))

        state["pqc_signed"] = True
        state["pqc_encrypted"] = True
        
    return state

# Build Graph
builder = StateGraph(VigilState)
builder.add_node("detection_node", detection_node)
builder.add_node("response_node", response_node)
builder.add_node("pqc_node", pqc_node)

builder.add_edge(START, "detection_node")
builder.add_conditional_edges("detection_node", routing_function, {
    END: END,
    "response_node": "response_node"
})
builder.add_edge("response_node", "pqc_node")
builder.add_edge("pqc_node", END)

workflow = builder.compile()

def run_agent_workflow(initial_state: dict):
    """
    Runs the agent pipeline.
    """
    final_state = workflow.invoke(initial_state)
    return final_state
