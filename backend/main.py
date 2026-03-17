from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
import seed
from routers import auth, alerts, users, files, ws

app = FastAPI(title="VigilAI Backend")

# Allow CORS for development (Vite React app on port 3000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["Auth"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(files.router, prefix="/api/files", tags=["Files"])
app.include_router(ws.router, prefix="/ws", tags=["WebSockets"])

@app.on_event("startup")
async def startup_event():
    # Make sure DB is seeded
    seed.seed_db()

from fastapi.responses import FileResponse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "..", "frontend", "dist")

@app.get("/{catchall:path}")
def serve_react_app(catchall: str):
    if not catchall:
        catchall = "index.html"
    file_path = os.path.join(FRONTEND_DIR, catchall)
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
