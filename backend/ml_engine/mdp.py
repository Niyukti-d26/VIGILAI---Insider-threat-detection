import json
from sqlalchemy.orm import Session
from database import SessionLocal
from models import User

# Q-Table schema mapping state keys to action values
# State key format: "critical_high|denied_high|off_hours_yes"
# Actions: ["monitor", "watch", "block"]
DEFAULT_Q_TABLE = {
    # We will initialize it dynamically if state is missing
}

def get_q_value(state: str, action: str, db: Session) -> float:
    # MVP: store in a simple local JSON file to simulate RL persistence
    # In full production, this would be a real DB table QTableEntry
    try:
        with open("q_table.json", "r") as f:
            q_table = json.load(f)
    except FileNotFoundError:
        q_table = DEFAULT_Q_TABLE
        
    if state not in q_table:
        q_table[state] = {"monitor": 0.0, "watch": 0.0, "block": 0.0}
        
    return q_table[state].get(action, 0.0)

def set_q_value(state: str, action: str, value: float):
    try:
        with open("q_table.json", "r") as f:
            q_table = json.load(f)
    except FileNotFoundError:
        q_table = DEFAULT_Q_TABLE
        
    if state not in q_table:
        q_table[state] = {"monitor": 0.0, "watch": 0.0, "block": 0.0}
        
    q_table[state][action] = value
    
    with open("q_table.json", "w") as f:
        json.dump(q_table, f)

def get_best_action(state: str, db: Session) -> str:
    try:
        with open("q_table.json", "r") as f:
            q_table = json.load(f)
    except FileNotFoundError:
        q_table = DEFAULT_Q_TABLE
        
    if state not in q_table:
        return "monitor"
        
    actions = q_table[state]
    return max(actions, key=actions.get)

def build_state_key(critical_count: int, denied_count: int, is_off_hours: bool) -> str:
    c_level = "high" if critical_count >= 3 else "low"
    d_level = "high" if denied_count >= 2 else "low"
    off_level = "yes" if is_off_hours else "no"
    return f"crit_{c_level}|denied_{d_level}|off_{off_level}"

def update_q_value(state: str, action: str, reward: float, alpha=0.1, gamma=0.9):
    """
    Standard Q-Learning update rule
    Q(s, a) = Q(s, a) + alpha * [Reward + gamma * max(Q(s')) - Q(s, a)]
    For this simplified MVP, we assume terminal states so max(Q(s')) = 0
    """
    old_value = get_q_value(state, action, None)
    new_value = old_value + alpha * (reward - old_value)
    set_q_value(state, action, new_value)

def record_state_transition(user_id: str, state: str, action: str):
    """
    Temporarily store the last state-action pair for a user so we can apply 
    reward feedback when an admin resolves the alert later.
    """
    try:
        with open("state_history.json", "r") as f:
            history = json.load(f)
    except FileNotFoundError:
        history = {}
        
    history[user_id] = {"state": state, "action": action}
    
    with open("state_history.json", "w") as f:
        json.dump(history, f)

def rl_feedback_loop(user_id: str, reward: float):
    """
    Applies RL feedback from Admin Dashboard outcomes.
    """
    try:
        with open("state_history.json", "r") as f:
            history = json.load(f)
    except FileNotFoundError:
        return
        
    record = history.get(user_id)
    if not record:
        return
        
    state = record["state"]
    action = record["action"]
    update_q_value(state, action, reward)
