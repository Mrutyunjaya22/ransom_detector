"""
Hardened Streaming File Scanner Route.

Provides asynchronous 1MB chunked streaming ingestion, bounded memory Shannon entropy
calculation (using an online 256-bin histogram), magic byte header identification,
and automated threat scoring up to a strict 50MB ceiling.
"""

from __future__ import annotations

import logging
import math
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

ROOT = os.path.dirname(__file__)
REPO_ROOT = os.path.dirname(ROOT)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

try:
    from backend.pipeline_service import pipeline_service
    from backend.websocket_manager import ChannelType, ws_manager
except ImportError:
    from pipeline_service import pipeline_service
    from websocket_manager import ChannelType, ws_manager

from core.engine import MLScorer
from core.features import ExtensionTracker

logger = logging.getLogger("edr.scanner")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [SCANNER] %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Operational Constants
CHUNK_SIZE_BYTES: int = 1024 * 1024  # 1 Megabyte chunk
MAX_ALLOWED_FILE_SIZE: int = 50 * 1024 * 1024  # 50 Megabytes strict ceiling
MODEL_FILE_PATH = os.path.join(REPO_ROOT, "models", "rf_classifier.pkl")

# Initialize persistent ML Scorer
ml_scorer = MLScorer(MODEL_FILE_PATH)

router = APIRouter(prefix="/api", tags=["File Scanner"])


class ScanFeatures(BaseModel):
    """Extracted structural and statistical features for a scanned file."""

    entropy: float
    sizeBytes: int
    ruleScore: float
    mlScore: float
    isSuspiciousExt: float
    detectedMimeOrMagic: str


class ScanResultItem(BaseModel):
    """Standardized response schema for scanned file artifacts."""

    id: str
    fileName: str
    sizeBytes: int
    entropy: float
    score: float
    verdict: str = Field(description="'clean' | 'suspicious' | 'malicious'")
    reasons: List[str]
    features: ScanFeatures
    scannedAt: str


class ScanHistoryResponse(BaseModel):
    """Collection wrapper for historical scans."""

    scans: List[Dict[str, Any]]


class StreamingEntropyCalculator:
    """
    Computes Shannon entropy across streaming chunks using an online 256-element histogram.
    Consumes O(1) auxiliary memory (only 256 integers) regardless of stream size.
    """

    def __init__(self):
        self.byte_counts: List[int] = [0] * 256
        self.total_bytes: int = 0
        self.header_bytes: bytes = b""

    def update(self, chunk: bytes) -> None:
        """Accumulates frequency counts from an incoming stream chunk."""
        if not chunk:
            return

        # Save the initial chunk's prefix for magic byte header analysis
        if not self.header_bytes:
            self.header_bytes = chunk[:64]

        self.total_bytes += len(chunk)
        for b in chunk:
            self.byte_counts[b] += 1

    def compute_entropy(self) -> float:
        """
        Calculates Shannon entropy in bits per byte (range: 0.00 to 8.00).
        H = -sum(p_i * log2(p_i))
        """
        if self.total_bytes == 0:
            return 0.0

        entropy = 0.0
        n = float(self.total_bytes)
        for count in self.byte_counts:
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def detect_magic_type(self) -> str:
        """Inspects file magic signature from captured initial bytes."""
        hdr = self.header_bytes
        if hdr.startswith(b"MZ"):
            return "Windows PE Executable / DLL"
        if hdr.startswith(b"\x7fELF"):
            return "Linux ELF Binary"
        if hdr.startswith(b"PK\x03\x04"):
            return "ZIP / OpenXML Archive (.docx/.xlsx/.jar)"
        if hdr.startswith(b"%PDF-"):
            return "Adobe Portable Document Format (PDF)"
        if hdr.startswith(b"\x1f\x8b"):
            return "GZIP Compressed Archive"
        if hdr.startswith(b"Rar!\x1a\x07"):
            return "RAR Archive"
        if hdr.startswith(b"7z\xbc\xaf\x27\x1c"):
            return "7-Zip Compressed Archive"
        return "Generic Binary / Data Stream"


@router.get("/scan", response_model=ScanHistoryResponse)
async def get_scans():
    """Returns the list of recent file scan triage records."""
    return {"scans": pipeline_service.get_scans()}


@router.post("/scan", response_model=Dict[str, ScanResultItem], status_code=status.HTTP_200_OK)
async def scan_file_stream(file: UploadFile = File(...)):
    """
    Streams file uploads in 1MB chunks, calculates Shannon entropy dynamically,
    enforces a hard 50MB ceiling, and evaluates risk using heuristics and Random Forest ML.
    """
    file_name = file.filename or "unknown_artifact"
    calculator = StreamingEntropyCalculator()
    bytes_read = 0

    try:
        # Stream read in 1MB increments to prevent memory ballooning
        while True:
            chunk = await file.read(CHUNK_SIZE_BYTES)
            if not chunk:
                break

            bytes_read += len(chunk)
            if bytes_read > MAX_ALLOWED_FILE_SIZE:
                logger.warning(
                    "Upload '%s' exceeded 50MB ceiling (%d bytes). Aborting stream.",
                    file_name,
                    bytes_read,
                )
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File exceeds maximum allowed upload size of {MAX_ALLOWED_FILE_SIZE // (1024*1024)} MB.",
                )

            calculator.update(chunk)

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Error reading upload stream for '%s': %s", file_name, exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read upload stream: {exc}",
        )
    finally:
        await file.close()

    entropy = calculator.compute_entropy()
    magic_type = calculator.detect_magic_type()
    _, ext = os.path.splitext(file_name.lower())
    is_suspicious_ext = (
        ext in ExtensionTracker.SUSPICIOUS_EXTENSIONS or ".locked" in file_name.lower()
    )

    reasons: List[str] = []
    rule_score = 0.0

    if bytes_read == 0:
        reasons.append("Empty file (0 bytes)")
    else:
        # Entropy-based heuristic grading
        if entropy >= 7.5:
            rule_score += 0.55
            reasons.append(
                f"High Shannon entropy ({entropy:.2f} bits/byte), strong indicator of encryption or obfuscation"
            )
        elif entropy >= 7.0:
            rule_score += 0.30
            reasons.append(
                f"Elevated Shannon entropy ({entropy:.2f} bits/byte), packed or compressed data"
            )
        elif entropy <= 3.5:
            reasons.append(f"Low entropy ({entropy:.2f} bits/byte), typical structured/plain text content")

        # Extension-based ransomware heuristic
        if is_suspicious_ext:
            rule_score += 0.45
            reasons.append(f"Known ransomware extension pattern detected ({ext})")

        # Plaintext format mismatch
        doc_exts = {".txt", ".csv", ".log", ".json", ".xml", ".md"}
        if ext in doc_exts and entropy > 6.0:
            rule_score += 0.25
            reasons.append(f"Anomalous high entropy for standard text/document format ({magic_type})")

    rule_score = min(rule_score, 1.0)

    # Prepare vector for RandomForestClassifier
    feat_vec = {
        "file_op_rate": 4.5 if is_suspicious_ext else 1.0,
        "mean_entropy": entropy,
        "high_entropy_fraction": 1.0 if entropy >= 7.5 else 0.0,
        "ext_change_rate": 2.0 if is_suspicious_ext else 0.0,
        "suspicious_ext_rate": 1.0 if is_suspicious_ext else 0.0,
        "cpu_percent": 60.0 if (entropy >= 7.5 and is_suspicious_ext) else 10.0,
        "children_spawned": 0,
        "io_bytes_per_s": float(bytes_read),
        "touched_file_count": 1,
    }

    ml_score = round(ml_scorer.score(feat_vec), 3) if bytes_read > 0 else 0.0
    combined_score = round(min(1.0, max(rule_score, ml_score * 0.7 + rule_score * 0.4)), 3)

    if combined_score >= 0.6 or (entropy >= 7.6 and is_suspicious_ext):
        verdict = "malicious"
    elif combined_score >= 0.35 or entropy >= 7.0:
        verdict = "suspicious"
    else:
        verdict = "clean"
        if not reasons:
            reasons.append(f"Nominal entropy and standard format ({magic_type})")

    scan_id = f"SCN-{int(time.time())}-{uuid.uuid4().hex[:6]}"
    scanned_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    features_model = ScanFeatures(
        entropy=entropy,
        sizeBytes=bytes_read,
        ruleScore=round(rule_score, 3),
        mlScore=ml_score,
        isSuspiciousExt=1.0 if is_suspicious_ext else 0.0,
        detectedMimeOrMagic=magic_type,
    )

    scan_result = ScanResultItem(
        id=scan_id,
        fileName=file_name,
        sizeBytes=bytes_read,
        entropy=entropy,
        score=combined_score,
        verdict=verdict,
        reasons=reasons,
        features=features_model,
        scannedAt=scanned_at,
    )

    # Store in recent scans ring buffer
    pipeline_service.add_scan(scan_result.model_dump())

    # Broadcast to SOC dashboard via WebSocket
    if verdict in ("suspicious", "malicious"):
        ws_manager.broadcast_sync(
            ChannelType.SCANS,
            "scan_completed",
            scan_result.model_dump(),
        )

    logger.info(
        "Scan complete for '%s' (ID: %s). Verdict=%s Score=%.3f Entropy=%.3f Size=%d bytes",
        file_name,
        scan_id,
        verdict,
        combined_score,
        entropy,
        bytes_read,
    )
    return {"scan": scan_result}
