"""
Two-Stage Inference Engine for the CSNet-IDA Intrusion Detection System.
Includes latency tracking, incident escalation, and aggregate session telemetry.
"""

import time
from collections import deque
from datetime import datetime
from typing import Dict, Any, Optional, List
import pandas as pd
import numpy as np

from src.config import (
    FEATURE_NAMES,
    ATTACK_FAMILY_DESCRIPTIONS
)
from src.model_loader import (
    get_preprocessor,
    get_stage1_model,
    get_stage1_threshold,
    get_stage2_model,
    get_stage2_labels
)
from src.schemas import (
    ConnectionFeatures,
    PredictionResponse,
    Stage1Output,
    Stage2Output
)
from src.incidents import create_incident

# In-memory history buffer (keeps up to 100 flow records)
_ANALYSIS_HISTORY: deque = deque(maxlen=100)

# Session Analytics Aggregator
_ANALYTICS_COUNTERS = {
    "total_flows": 0,
    "normal_flows": 0,
    "attack_flows": 0,
    "critical_alerts": 0,
    "total_latency_ms": 0.0,
    "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0},
    "services": {},
    "families": {"DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0},
    "severities": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "timeline": deque(maxlen=30)
}


def predict_connection(
    features: ConnectionFeatures | Dict[str, Any],
    custom_threshold: Optional[float] = None
) -> PredictionResponse:
    """
    Executes the two-stage inference pipeline for a single connection record.

    Stage 1: Binary classification (Normal vs. Attack) using tuned threshold (default: 0.40).
    Stage 2: Multiclass classification (DoS, Probe, R2L, U2R) for detected attacks.
    """
    t_start = time.perf_counter()

    # Convert Pydantic model to dictionary if necessary
    if isinstance(features, ConnectionFeatures):
        feature_dict = features.model_dump()
    elif isinstance(features, dict):
        feature_dict = features.copy()
    else:
        raise TypeError("features must be a ConnectionFeatures instance or dict")

    # Load models
    preprocessor = get_preprocessor()
    stage1_model = get_stage1_model()
    default_threshold = get_stage1_threshold()
    stage2_model = get_stage2_model()

    threshold = custom_threshold if custom_threshold is not None else default_threshold

    # Construct DataFrame ensuring strict column ordering of the 40 features
    ordered_data = {col: [feature_dict.get(col, 0)] for col in FEATURE_NAMES}
    input_df = pd.DataFrame(ordered_data)

    # Preprocess raw features -> 120 numerical features
    processed_features = preprocessor.transform(input_df)

    # Stage 1: Binary Classification
    stage1_prob = float(stage1_model.predict_proba(processed_features)[0, 1])
    is_attack = stage1_prob >= threshold
    stage1_decision = "Attack" if is_attack else "Normal"

    stage1_result = Stage1Output(
        attack_probability=round(stage1_prob, 4),
        threshold=round(threshold, 4),
        decision=stage1_decision,
        is_attack=is_attack
    )

    # Stage 2: Attack Family Classification (Triggered only if Stage 1 detects an attack)
    if is_attack:
        stage2_pred_raw = stage2_model.predict(processed_features)[0]
        final_prediction = str(stage2_pred_raw)

        stage2_probs_raw = stage2_model.predict_proba(processed_features)[0]
        stage2_probs = {
            cls_name: round(float(prob), 4)
            for cls_name, prob in zip(stage2_model.classes_, stage2_probs_raw)
        }

        # Determine alert severity
        if final_prediction in ("DoS", "U2R"):
            alert_severity = "critical"
        elif final_prediction == "R2L":
            alert_severity = "high"
        else:  # Probe
            alert_severity = "medium"

        stage2_result = Stage2Output(
            attack_family=final_prediction,
            description=ATTACK_FAMILY_DESCRIPTIONS.get(final_prediction, "Unknown attack family"),
            probabilities=stage2_probs
        )
    else:
        final_prediction = "Normal"
        alert_severity = "low"
        stage2_result = None

    t_end = time.perf_counter()
    latency_ms = round((t_end - t_start) * 1000.0, 2)

    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sample_id = f"CONN-{int(datetime.now().timestamp() * 1000) % 1000000:06d}"

    response = PredictionResponse(
        success=True,
        final_prediction=final_prediction,
        is_attack=is_attack,
        alert_severity=alert_severity,
        stage1=stage1_result,
        stage2=stage2_result,
        timestamp=timestamp_str,
        sample_id=sample_id,
        latency_ms=latency_ms
    )

    # Escalation: Create incident if an attack is classified
    incident_id = None
    if is_attack:
        inc_data = create_incident(response.model_dump(), feature_dict)
        incident_id = inc_data["id"]

    # Session History & Analytics update
    proto = str(feature_dict.get("protocol_type", "tcp")).upper()
    svc = str(feature_dict.get("service", "http"))

    history_item = {
        "sample_id": sample_id,
        "incident_id": incident_id,
        "timestamp": timestamp_str,
        "protocol": proto,
        "service": svc,
        "attack_prob": round(stage1_prob, 4),
        "stage1_decision": stage1_decision,
        "final_prediction": final_prediction,
        "alert_severity": alert_severity,
        "is_attack": is_attack,
        "latency_ms": latency_ms
    }
    _ANALYSIS_HISTORY.appendleft(history_item)

    # Update analytics aggregator
    _ANALYTICS_COUNTERS["total_flows"] += 1
    _ANALYTICS_COUNTERS["total_latency_ms"] += latency_ms
    if is_attack:
        _ANALYTICS_COUNTERS["attack_flows"] += 1
        if final_prediction in _ANALYTICS_COUNTERS["families"]:
            _ANALYTICS_COUNTERS["families"][final_prediction] += 1
        if alert_severity in ("critical", "high"):
            _ANALYTICS_COUNTERS["critical_alerts"] += 1
    else:
        _ANALYTICS_COUNTERS["normal_flows"] += 1

    if proto in _ANALYTICS_COUNTERS["protocols"]:
        _ANALYTICS_COUNTERS["protocols"][proto] += 1

    _ANALYTICS_COUNTERS["services"][svc] = _ANALYTICS_COUNTERS["services"].get(svc, 0) + 1
    _ANALYTICS_COUNTERS["severities"][alert_severity] = _ANALYTICS_COUNTERS["severities"].get(alert_severity, 0) + 1

    # Time series activity point
    _ANALYTICS_COUNTERS["timeline"].append({
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "is_attack": is_attack,
        "attack_prob": round(float(stage1_prob), 4),
        "family": final_prediction,
        "severity": alert_severity,
        "sample_id": sample_id
    })

    return response


def get_analytics_summary() -> Dict[str, Any]:
    """
    Computes summary telemetry and calculated security posture based on actual session events
    and current active unresolved incidents.
    """
    from src.incidents import get_active_incidents_counts

    total = _ANALYTICS_COUNTERS["total_flows"]
    attacks = _ANALYTICS_COUNTERS["attack_flows"]
    normals = _ANALYTICS_COUNTERS["normal_flows"]
    avg_lat = round(_ANALYTICS_COUNTERS["total_latency_ms"] / total, 2) if total > 0 else 0.0
    attack_rate = round((attacks / total) * 100, 1) if total > 0 else 0.0

    active_counts = get_active_incidents_counts()
    active_crit = active_counts["critical"]
    active_high = active_counts["high"]
    active_med = active_counts["medium"]
    active_low = active_counts["low"]
    total_active = active_counts["total_active"]

    # Security Posture derived directly from active unresolved incidents
    if total_active == 0:
        posture = "NOMINAL"
        posture_level = "low"
        posture_factors = [
            "No active security incidents requiring analyst intervention",
            "Network flow baseline operations normal"
        ]
        risk_score = 0.0
    elif active_crit > 0:
        posture = "CRITICAL"
        posture_level = "critical"
        posture_factors = [
            f"{active_crit} active Critical incident(s) (DoS flooding or U2R root access)",
            "Immediate SOC containment action required"
        ]
        risk_score = round(min(100.0, 75.0 + active_crit * 5.0), 1)
    elif active_high > 0:
        posture = "HIGH"
        posture_level = "high"
        posture_factors = [
            f"{active_high} active High incident(s) (R2L unauthorized penetration)",
            "Active adversary access attempts detected"
        ]
        risk_score = round(min(74.0, 50.0 + active_high * 6.0), 1)
    else:  # active medium / low incidents
        posture = "ELEVATED"
        posture_level = "medium"
        posture_factors = [
            f"{active_med + active_low} active reconnaissance / probe incident(s)",
            "Network port mapping or host sweep activity flagged"
        ]
        risk_score = round(min(49.0, 20.0 + (active_med + active_low) * 4.0), 1)

    sorted_services = sorted(_ANALYTICS_COUNTERS["services"].items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_flows": total,
        "normal_flows": normals,
        "attack_flows": attacks,
        "attack_rate_pct": attack_rate,
        "critical_alerts": active_crit,
        "total_active_incidents": total_active,
        "avg_latency_ms": avg_lat,
        "risk_score": risk_score,
        "posture": posture,
        "posture_level": posture_level,
        "posture_factors": posture_factors,
        "protocols": dict(_ANALYTICS_COUNTERS["protocols"]),
        "families": dict(_ANALYTICS_COUNTERS["families"]),
        "severities": dict(_ANALYTICS_COUNTERS["severities"]),
        "top_services": sorted_services,
        "timeline": list(_ANALYTICS_COUNTERS["timeline"])
    }


def get_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns the last N in-memory analyses."""
    return list(_ANALYSIS_HISTORY)[:limit]


def clear_history() -> None:
    """Clears the in-memory history and counters."""
    _ANALYSIS_HISTORY.clear()
    _ANALYTICS_COUNTERS["total_flows"] = 0
    _ANALYTICS_COUNTERS["normal_flows"] = 0
    _ANALYTICS_COUNTERS["attack_flows"] = 0
    _ANALYTICS_COUNTERS["critical_alerts"] = 0
    _ANALYTICS_COUNTERS["total_latency_ms"] = 0.0
    _ANALYTICS_COUNTERS["protocols"] = {"TCP": 0, "UDP": 0, "ICMP": 0}
    _ANALYTICS_COUNTERS["services"] = {}
    _ANALYTICS_COUNTERS["families"] = {"DoS": 0, "Probe": 0, "R2L": 0, "U2R": 0}
    _ANALYTICS_COUNTERS["severities"] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    _ANALYTICS_COUNTERS["timeline"].clear()
