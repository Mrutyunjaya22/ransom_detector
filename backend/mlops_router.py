"""
MLOps API Router: Analyst Feedback Loop, Model Distribution, and Live Hot-Reload.

Provides REST endpoints for SOC analysts to submit triage ground truth (True/False Positives),
inspect real-time ML performance metrics, download production model artifacts,
and trigger automated retraining cycles.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(ROOT)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.repository import edr_repo
from backend.websocket_manager import ChannelType, ws_manager
from mlops.retrain_pipeline import DEFAULT_MODEL_PATH, retrain_pipeline

logger = logging.getLogger("edr.mlops_router")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [MLOPS_ROUTER] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

router = APIRouter(prefix="/api/ml", tags=["MLOps & Model Lifecycle"])


class FeedbackRequest(BaseModel):
    """Schema for analyst triage labeling."""

    target_type: str = Field(..., description="'alert' | 'incident' | 'scan'")
    target_id: str = Field(..., description="Unique identifier of the alert or incident")
    label: str = Field(..., description="'true_positive' | 'false_positive'")
    analyst_name: Optional[str] = "analyst"
    notes: Optional[str] = ""


class RetrainRequest(BaseModel):
    """Configuration for retraining cycle."""

    n_synthetic_samples: Optional[int] = 1500


@router.post("/feedback", status_code=status.HTTP_201_CREATED)
async def submit_feedback(req: FeedbackRequest):
    """Submits ground-truth validation from a SOC analyst."""
    if req.label not in ("true_positive", "false_positive"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Label must be 'true_positive' or 'false_positive'",
        )

    feedback_id = await edr_repo.save_analyst_feedback(
        target_type=req.target_type,
        target_id=req.target_id,
        label=req.label,
        analyst_name=req.analyst_name or "analyst",
        notes=req.notes or "",
    )

    logger.info(
        "Feedback recorded by %s: Target=%s:%s Label=%s (ID: %s)",
        req.analyst_name,
        req.target_type,
        req.target_id,
        req.label,
        feedback_id,
    )
    return {
        "status": "success",
        "message": "Analyst feedback recorded for continuous retraining",
        "feedback_id": feedback_id,
    }


@router.get("/feedback")
async def list_feedback():
    """Retrieves recent analyst feedback records."""
    records = await edr_repo.get_feedback_records()
    return {"feedback": records, "count": len(records)}


@router.get("/model/latest")
def get_model_metadata():
    """Returns metadata and evaluation metrics for the active production model."""
    meta = retrain_pipeline.load_metadata()
    return {"model": meta}


@router.get("/model/download")
def download_model_artifact():
    """Securely downloads the active production RandomForest model weights."""
    if not os.path.exists(DEFAULT_MODEL_PATH):
        raise HTTPException(status_code=404, detail="Model artifact not found.")
    return FileResponse(
        path=DEFAULT_MODEL_PATH,
        filename="rf_classifier.pkl",
        media_type="application/octet-stream",
    )


@router.post("/retrain")
async def trigger_retraining(req: RetrainRequest):
    """
    Executes automated model retraining using baseline distributions and analyst feedback.
    Promotes the new model and broadcasts update to connected clients.
    """
    try:
        feedback_records = await edr_repo.get_feedback_records()
        metadata = retrain_pipeline.train_and_promote(
            feedback_records=feedback_records,
            n_synthetic=req.n_synthetic_samples or 1500,
        )

        # Hot reload scanner ML Scorer if running in-process
        try:
            from backend.scan_router import ml_scorer
            import pickle
            with open(DEFAULT_MODEL_PATH, "rb") as f:
                ml_scorer.model = pickle.load(f)
            logger.info("Successfully hot-reloaded MLScorer weights in memory.")
        except Exception as exc:
            logger.warning("Could not hot-reload scanner scorer: %s", exc)

        # Broadcast model promotion to SOC dashboard
        ws_manager.broadcast_sync(
            ChannelType.SYSTEM,
            "model_promoted",
            metadata,
        )

        return {
            "status": "promoted",
            "message": "New model trained, validated, and promoted to production.",
            "metadata": metadata,
        }
    except Exception as exc:
        logger.error("Model retraining failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Retraining failed: {exc}",
        )
