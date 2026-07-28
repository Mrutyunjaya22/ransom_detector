import os
import sys

ROOT = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(ROOT)
sys.path.insert(0, REPO_ROOT)

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from pipeline_service import pipeline_service

app = FastAPI(title="Ransomware Detection Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/status")
def status():
    return pipeline_service.status_payload()


@app.get("/api/alerts")
def alerts():
    return {"alerts": pipeline_service.get_alerts(), "count": len(pipeline_service.get_alerts())}


@app.get("/api/reports")
def reports():
    return {"reports": pipeline_service.get_reports()}


@app.get("/api/reports/{report_id}")
def report_detail(report_id: str):
    report = pipeline_service.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"report": report}


from pydantic import BaseModel


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
    uvicorn.run(app, host="127.0.0.1", port=8000)
