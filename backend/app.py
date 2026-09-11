import asyncio
import os
import sys
from contextlib import asynccontextmanager

ROOT = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(ROOT)
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, ROOT)

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

try:
    from backend.database import init_db
    from backend.mlops_router import router as mlops_router
    from backend.pipeline_service import pipeline_service
    from backend.repository import edr_repo
    from backend.scan_router import router as scan_router
    from backend.websocket_manager import router as websocket_router, ws_manager
except ImportError:
    from database import init_db
    from mlops_router import router as mlops_router
    from pipeline_service import pipeline_service
    from repository import edr_repo
    from scan_router import router as scan_router
    from websocket_manager import router as websocket_router, ws_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Register running event loop with WebSocket manager and initialize relational DB."""
    loop = asyncio.get_running_loop()
    ws_manager.set_event_loop(loop)
    try:
        await init_db()
    except Exception as exc:
        import logging
        logging.getLogger("uvicorn.error").warning(f"Database init warning: {exc}")
    yield


app = FastAPI(
    title="Enterprise EDR Ransomware Detection Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# Secure CORS configuration supporting local dev and configurable origins
ALLOWED_ORIGINS = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount hardened routers
app.include_router(scan_router)
app.include_router(websocket_router)
app.include_router(mlops_router)


@app.get("/api/status")
def status():
    return pipeline_service.status_payload()


@app.get("/api/alerts")
async def alerts():
    db_alerts = await edr_repo.get_alerts(limit=50)
    mem_alerts = pipeline_service.get_alerts()
    # Deduplicate by alert id while preserving order
    seen_ids = set()
    combined = []
    for a in mem_alerts + db_alerts:
        if a["id"] not in seen_ids:
            seen_ids.add(a["id"])
            combined.append(a)
    return {"alerts": combined, "count": len(combined)}


@app.get("/api/reports")
async def reports():
    db_reports = await edr_repo.get_reports(limit=50)
    mem_reports = pipeline_service.get_reports()
    seen_ids = set()
    combined = []
    for r in mem_reports + db_reports:
        r_id = r.get("id") or r.get("incident_id")
        if r_id and r_id not in seen_ids:
            seen_ids.add(r_id)
            combined.append(r)
    return {"reports": combined}


@app.get("/api/reports/{report_id}")
async def report_detail(report_id: str):
    db_report = await edr_repo.get_report_by_id(report_id)
    if db_report:
        return {"report": db_report}
    report = pipeline_service.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report": report}


@app.get("/api/scans")
async def list_scans():
    db_scans = await edr_repo.get_scans(limit=50)
    mem_scans = pipeline_service.get_scans()
    seen_ids = set()
    combined = []
    for s in mem_scans + db_scans:
        s_id = s.get("id")
        if s_id and s_id not in seen_ids:
            seen_ids.add(s_id)
            combined.append(s)
    return {"scans": combined}


class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    ip_address: str
    os_platform: str


@app.post("/api/agents/register")
async def register_agent(req: AgentRegisterRequest):
    agent = await edr_repo.register_agent(
        agent_id=req.agent_id,
        hostname=req.hostname,
        ip_address=req.ip_address,
        os_platform=req.os_platform,
    )
    return {
        "status": "registered",
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "os_platform": agent.os_platform,
    }


class RunRequest(BaseModel):
    mode: str


@app.post("/api/run")
def run(request: RunRequest):
    if request.mode not in ("benign", "attack"):
        raise HTTPException(status_code=400, detail="mode must be 'benign' or 'attack'")
    try:
        return pipeline_service.start_run(request.mode)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


if __name__ == "__main__":
    uvicorn.run("backend.app:app", host="127.0.0.1", port=8000, reload=True)


