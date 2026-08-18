"""
Incident Center and Investigation Manager for CSNet-IDA.
Manages detected security incidents in memory with lifecycle states and CSV export.
"""

import io
import csv
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import deque

# In-memory bounded store for detected incidents (max 200)
_INCIDENTS_STORE: deque = deque(maxlen=200)
_INCIDENT_COUNTER: int = 1000


def create_incident(
    prediction_result: Dict[str, Any],
    features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Creates and stores an incident record for a detected intrusion event.
    """
    global _INCIDENT_COUNTER
    _INCIDENT_COUNTER += 1
    incident_id = f"INC-{datetime.now().year}-{_INCIDENT_COUNTER}"

    family = prediction_result.get("final_prediction", "Unknown")
    severity = prediction_result.get("alert_severity", "medium")

    stage1 = prediction_result.get("stage1", {})
    stage2 = prediction_result.get("stage2") or {}

    incident_record = {
        "id": incident_id,
        "sample_id": prediction_result.get("sample_id", "CONN-UNKNOWN"),
        "timestamp": prediction_result.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "attack_family": family,
        "severity": severity,
        "attack_probability": stage1.get("attack_probability", 1.0),
        "stage1_decision": stage1.get("decision", "Attack"),
        "stage1_threshold": stage1.get("threshold", 0.40),
        "stage2_probabilities": stage2.get("probabilities", {}),
        "description": stage2.get("description", f"Detected {family} incursion event"),
        "protocol": str(features.get("protocol_type", "tcp")).upper(),
        "service": str(features.get("service", "http")),
        "flag": str(features.get("flag", "SF")),
        "src_bytes": float(features.get("src_bytes", 0.0)),
        "dst_bytes": float(features.get("dst_bytes", 0.0)),
        "features": features,
        "status": "New",  # New, Investigating, Confirmed, Resolved
        "notes": f"Automated two-stage detection: Stage 1 p={stage1.get('attack_probability', 1.0):.4f} >= threshold 0.40 -> Stage 2 {family}."
    }

    _INCIDENTS_STORE.appendleft(incident_record)
    return incident_record


def get_incidents(
    status: Optional[str] = None,
    family: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: Optional[str] = "timestamp_desc",
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """
    Retrieves filtered, sorted, and paginated incidents from in-memory registry.
    """
    all_records = list(_INCIDENTS_STORE)
    filtered = []

    for inc in all_records:
        if status and status.lower() != "all" and inc["status"].lower() != status.lower():
            continue
        if family and family.lower() != "all" and inc["attack_family"].lower() != family.lower():
            continue
        if severity and severity.lower() != "all" and inc["severity"].lower() != severity.lower():
            continue
        if search:
            s = search.lower()
            match = (
                s in inc["id"].lower()
                or s in inc["sample_id"].lower()
                or s in inc["attack_family"].lower()
                or s in inc["service"].lower()
                or s in inc["protocol"].lower()
                or s in inc.get("notes", "").lower()
            )
            if not match:
                continue
        filtered.append(inc)

    # Sorting
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if sort_by == "severity_desc":
        filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "low").lower(), 0), reverse=True)
    elif sort_by == "severity_asc":
        filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "low").lower(), 0), reverse=False)
    elif sort_by == "prob_desc":
        filtered.sort(key=lambda x: x.get("attack_probability", 0.0), reverse=True)
    elif sort_by == "prob_asc":
        filtered.sort(key=lambda x: x.get("attack_probability", 0.0), reverse=False)
    elif sort_by == "timestamp_asc":
        filtered.sort(key=lambda x: x.get("timestamp", ""))
    else:  # timestamp_desc (default)
        filtered.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    total_count = len(filtered)
    paginated = filtered[offset: offset + limit]

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "sort_by": sort_by or "timestamp_desc",
        "incidents": paginated
    }


def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieves a single incident by its ID.
    """
    for inc in _INCIDENTS_STORE:
        if inc["id"].lower() == incident_id.lower():
            return inc
    return None


def update_incident_status(
    incident_id: str,
    new_status: str,
    notes: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Updates the lifecycle status of an existing incident.
    Valid statuses: New, Investigating, Confirmed, Resolved
    """
    valid_statuses = ["New", "Investigating", "Confirmed", "Resolved"]
    normalized = next((s for s in valid_statuses if s.lower() == new_status.lower()), None)
    if not normalized:
        raise ValueError(f"Invalid status: {new_status}. Allowed: {valid_statuses}")

    for inc in _INCIDENTS_STORE:
        if inc["id"].lower() == incident_id.lower():
            inc["status"] = normalized
            if notes is not None:
                inc["notes"] = notes
            return inc
    return None


def get_active_incidents_counts() -> Dict[str, int]:
    """
    Computes real-time counts of active (unresolved) incidents grouped by severity.
    Resolved incidents are excluded from active threat posture calculations.
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total_active": 0}
    for inc in _INCIDENTS_STORE:
        if inc.get("status") != "Resolved":
            sev = str(inc.get("severity", "low")).lower()
            if sev in counts:
                counts[sev] += 1
            counts["total_active"] += 1
    return counts


def clear_incidents() -> None:
    """Clears all stored incident records."""
    _INCIDENTS_STORE.clear()


def export_incidents_csv() -> str:
    """
    Exports the current in-memory incident telemetry as CSV formatted text.
    """
    output = io.StringIO()
    fieldnames = [
        "incident_id", "sample_id", "timestamp", "status", "attack_family",
        "severity", "attack_probability", "protocol", "service", "flag",
        "src_bytes", "dst_bytes", "notes"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for inc in _INCIDENTS_STORE:
        writer.writerow({
            "incident_id": inc["id"],
            "sample_id": inc["sample_id"],
            "timestamp": inc["timestamp"],
            "status": inc["status"],
            "attack_family": inc["attack_family"],
            "severity": inc["severity"],
            "attack_probability": f"{inc['attack_probability']:.4f}",
            "protocol": inc["protocol"],
            "service": inc["service"],
            "flag": inc["flag"],
            "src_bytes": inc["src_bytes"],
            "dst_bytes": inc["dst_bytes"],
            "notes": inc["notes"]
        })

    return output.getvalue()
