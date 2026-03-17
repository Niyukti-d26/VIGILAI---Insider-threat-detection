import asyncio
import os
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError, jwt
from typing import List, Dict, Optional

router = APIRouter()

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change-in-production")
ALGORITHM = "HS256"
if "BEGIN RSA" in SECRET_KEY or "BEGIN PRIVATE" in SECRET_KEY:
    ALGORITHM = "RS256"


class ConnectionManager:
    def __init__(self):
        self.admin_connections: List[WebSocket] = []
        self.employee_connections: Dict[str, WebSocket] = {}
        self._loop = None  # type: ignore

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    # ── ADMIN ──
    async def connect_admin(self, websocket: WebSocket):
        await websocket.accept()
        self.admin_connections.append(websocket)
        print(f"[WS] Admin connected. Total admins: {len(self.admin_connections)}")

    def disconnect_admin(self, websocket: WebSocket):
        if websocket in self.admin_connections:
            self.admin_connections.remove(websocket)
            print(f"[WS] Admin disconnected. Remaining: {len(self.admin_connections)}")

    # ── EMPLOYEE ──
    async def connect_employee(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        self.employee_connections[user_id] = websocket
        print(f"[WS] Employee {user_id} connected. Total employees: {len(self.employee_connections)}")

    def disconnect_employee(self, user_id: str):
        if user_id in self.employee_connections:
            self.employee_connections.pop(user_id, None)
            print(f"[WS] Employee {user_id} disconnected.")

    # ── BROADCASTS ──
    async def broadcast_to_admins(self, data: dict):
        """Broadcast JSON to all connected admin clients."""
        dead = []
        for ws in self.admin_connections:
            try:
                await ws.send_json(data)
            except Exception as e:
                print(f"[WS] Admin send failed: {e}")
                dead.append(ws)
        for ws in dead:
            self.disconnect_admin(ws)

    async def send_to_employee(self, user_id: str, data: dict):
        """Send JSON to a specific employee."""
        ws = self.employee_connections.get(user_id)
        if ws:
            try:
                await ws.send_json(data)
            except Exception as e:
                print(f"[WS] Employee {user_id} send failed: {e}")
                self.disconnect_employee(user_id)

    def broadcast_from_thread(self, data: dict):
        """Thread-safe broadcast to admins. Called from background threads."""
        loop = self._loop
        if loop is not None and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast_to_admins(data), loop)
        else:
            print("[WS] Event loop not available for broadcast")

    def send_to_employee_from_thread(self, user_id: str, data: dict):
        """Thread-safe send to employee. Called from background threads."""
        loop = self._loop
        if loop is not None and loop.is_running():
            asyncio.run_coroutine_threadsafe(self.send_to_employee(user_id, data), loop)
        else:
            print("[WS] Event loop not available for employee send")

    # Legacy: broadcast_alert = broadcast_to_admins for backward compat
    async def broadcast_alert(self, data: dict):
        await self.broadcast_to_admins(data)


manager = ConnectionManager()


def _get_user_id_from_token(token: str) -> Optional[dict]:
    """Decode JWT and return payload, or None if invalid."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        return None


# ── ADMIN WebSocket ──
@router.websocket("/admin")
async def admin_ws_endpoint(websocket: WebSocket, token: str = Query(...)):
    if manager._loop is None:
        manager.set_loop(asyncio.get_event_loop())

    payload = _get_user_id_from_token(token)
    if not payload or payload.get("role") != "admin":
        await websocket.close(code=4001)
        return

    await manager.connect_admin(websocket)
    try:
        # Send a welcome event so admin knows they're connected
        await websocket.send_json({"event": "connected", "role": "admin", "message": "WebSocket connected — monitoring all employee activity"})
        while True:
            data = await websocket.receive_text()
            # Admin can send pings or ack messages
            print(f"[WS/Admin] Received: {data}")
    except WebSocketDisconnect:
        manager.disconnect_admin(websocket)


# ── EMPLOYEE WebSocket ──
@router.websocket("/employee")
async def employee_ws_endpoint(websocket: WebSocket, token: str = Query(...)):
    if manager._loop is None:
        manager.set_loop(asyncio.get_event_loop())

    payload = _get_user_id_from_token(token)
    if not payload:
        await websocket.close(code=4001)
        return

    user_id = payload.get("user_id") or payload.get("sub")
    if not user_id:
        await websocket.close(code=4001)
        return

    await manager.connect_employee(websocket, user_id)
    try:
        await websocket.send_json({"event": "connected", "role": "employee", "user_id": user_id})
        while True:
            data = await websocket.receive_text()
            print(f"[WS/Employee/{user_id}] Received: {data}")
    except WebSocketDisconnect:
        manager.disconnect_employee(user_id)


# ── LEGACY /ws/alerts — backward compat alias for admin ──
@router.websocket("/alerts")
async def legacy_alerts_ws(websocket: WebSocket):
    if manager._loop is None:
        manager.set_loop(asyncio.get_event_loop())

    await manager.connect_admin(websocket)
    try:
        await websocket.send_json({"event": "connected", "role": "admin", "message": "Legacy WS connected — monitoring all employee activity"})
        while True:
            data = await websocket.receive_text()
            print(f"[WS/Legacy] Received: {data}")
    except WebSocketDisconnect:
        manager.disconnect_admin(websocket)
