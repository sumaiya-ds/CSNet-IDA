"""
Incident Center and SOC Investigation Workstation Manager for CSNet-IDA.
Manages detected security incidents in memory with lifecycle states, audit timelines,
analyst notes, related event correlation, contextual threat intel, and CSV export.
"""

import io
import csv
from datetime import datetime
from typing import Dict, Any, List, Optional
from collections import deque

from src.config import ATTACK_FAMILY_DESCRIPTIONS
from src.explainability import explain_single_sample, get_feature_importance_data

# In-memory bounded store for detected incidents (max 200)
_INCIDENTS_STORE: deque = deque(maxlen=200)
_INCIDENT_COUNTER: int = 1000

# Contextual threat intelligence definitions (non-fabricated, domain-accurate)
CONTEXTUAL_THREAT_INTEL: Dict[str, Dict[str, Any]] = {
    "DoS": {
        "family": "Denial of Service (DoS)",
        "behavior": "High-volume resource exhaustion, SYN flooding, ICMP broadcast amplification, or connection buffer starvation.",
        "common_vectors": ["Neptune (SYN Flood)", "Smurf (ICMP Echo Amplification)", "Teardrop", "Pod (Ping of Death)", "Land"],
        "recommended_playbook": [
            "Enable SYN flood cookies on perimeter firewalls.",
            "Enforce rate-limiting and connection throttling on destination ports.",
            "Blackhole malicious source IP ranges at border routers.",
            "Verify server memory and socket table utilization."
        ]
    },
    "Probe": {
        "family": "Reconnaissance & Probing",
        "behavior": "Host discovery sweeps, port scanning, and remote OS/service enumeration to identify vulnerable endpoints.",
        "common_vectors": ["IPSweep (ICMP Sweep)", "PortScan", "Nmap", "Satan", "Mscan"],
        "recommended_playbook": [
            "Block source IP addresses conducting systematic sequential port sweeps.",
            "Review firewall access control lists (ACLs) to ensure unnecessary ports are closed.",
            "Inspect honeypot hits to evaluate attacker reconnaissance patterns.",
            "Enable aggressive TCP RST response filtering on perimeter sensors."
        ]
    },
    "R2L": {
        "family": "Remote-to-Local (R2L) Unauthorized Access",
        "behavior": "Remote adversary attempting unauthorized local access via password brute-forcing, buffer overflow exploits, or rogue protocol commands.",
        "common_vectors": ["Warezclient", "Warezmaster", "Guess_Passwd", "Ftp_write", "Imap", "Phf"],
        "recommended_playbook": [
            "Terminate active unauthorized sessions immediately.",
            "Enforce mandatory multi-factor authentication (MFA) and rotate compromised user credentials.",
            "Inspect FTP/Telnet/HTTP daemon logs for shell payload injection attempts.",
            "Isolate affected services into demilitarized subnets (DMZ)."
        ]
    },
    "U2R": {
        "family": "User-to-Root (U2R) Privilege Escalation",
        "behavior": "Local unprivileged user or compromised service attempting root/administrator privilege escalation via buffer overflow or rootkits.",
        "common_vectors": ["Rootkit", "Buffer_overflow", "Loadmodule", "Perl"],
        "recommended_playbook": [
            "Quarantine host immediately from the local enterprise network.",
            "Audit setuid/setgid binaries, root shell executions, and system log modifications.",
            "Execute memory forensics and integrity checks on kernel modules.",
            "Preserve system image for deep forensic investigation and reconstruct from golden image."
        ]
    }
}


def create_incident(
    prediction_result: Dict[str, Any],
    features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Creates and stores an incident record for a detected intrusion event.
    Extracts all authentic model telemetry and 40-feature connection attributes.
    """
    global _INCIDENT_COUNTER
    _INCIDENT_COUNTER += 1
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    incident_id = f"INC-{datetime.now().year}-{_INCIDENT_COUNTER}"

    family = prediction_result.get("final_prediction", "Unknown")
    severity = prediction_result.get("alert_severity", "medium")

    stage1 = prediction_result.get("stage1", {})
    stage2 = prediction_result.get("stage2") or {}
    prob = float(stage1.get("attack_probability", 1.0))

    # Key observed features
    protocol = str(features.get("protocol_type", "tcp")).upper()
    service = str(features.get("service", "http"))
    flag = str(features.get("flag", "SF"))
    duration = float(features.get("duration", 0.0))
    src_bytes = float(features.get("src_bytes", 0.0))
    dst_bytes = float(features.get("dst_bytes", 0.0))
    count = float(features.get("count", 1.0))
    srv_count = float(features.get("srv_count", 1.0))
    serror_rate = float(features.get("serror_rate", 0.0))
    srv_serror_rate = float(features.get("srv_serror_rate", 0.0))
    same_srv_rate = float(features.get("same_srv_rate", 1.0))
    diff_srv_rate = float(features.get("diff_srv_rate", 0.0))
    dst_host_srv_count = float(features.get("dst_host_srv_count", 255.0))
    dst_host_same_srv_rate = float(features.get("dst_host_same_srv_rate", 1.0))
    dst_host_serror_rate = float(features.get("dst_host_serror_rate", 0.0))

    sample_id = prediction_result.get("sample_id", "CONN-UNKNOWN")

    incident_record = {
        "id": incident_id,
        "sample_id": sample_id,
        "timestamp": prediction_result.get("timestamp", now_str),
        "attack_family": family,
        "severity": severity,
        "attack_probability": prob,
        "stage1_decision": stage1.get("decision", "Attack"),
        "stage1_threshold": stage1.get("threshold", 0.40),
        "stage2_probabilities": stage2.get("probabilities", {}),
        "description": stage2.get("description", f"Detected {family} incursion event"),
        "protocol": protocol,
        "service": service,
        "flag": flag,
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "count": count,
        "srv_count": srv_count,
        "serror_rate": serror_rate,
        "srv_serror_rate": serror_rate,
        "same_srv_rate": same_srv_rate,
        "diff_srv_rate": diff_srv_rate,
        "dst_host_srv_count": dst_host_srv_count,
        "dst_host_same_srv_rate": dst_host_same_srv_rate,
        "dst_host_serror_rate": dst_host_serror_rate,
        "features": features,
        "status": "New",  # New -> Investigating -> Confirmed -> Resolved
        "notes": [
            {
                "id": "note-1",
                "text": f"Automated detection trigger: Stage 1 P(Attack) = {prob:.4f} (Threshold: 0.40) -> Routed to Stage 2 -> Classified as {family} ({severity.upper()}).",
                "timestamp": now_str,
                "analyst": "Detection Engine"
            }
        ],
        "lifecycle_history": [
            {
                "status": "New",
                "timestamp": now_str,
                "note": "Incident automatically registered by two-stage detection pipeline.",
                "actor": "Detection Engine"
            }
        ],
        "timeline_timestamps": {
            "detected_at": now_str,
            "investigating_at": None,
            "confirmed_at": None,
            "resolved_at": None
        }
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
            notes_str = " ".join([n.get("text", "") for n in inc.get("notes", [])]) if isinstance(inc.get("notes"), list) else str(inc.get("notes", ""))
            match = (
                s in inc["id"].lower()
                or s in inc["sample_id"].lower()
                or s in inc["attack_family"].lower()
                or s in inc["service"].lower()
                or s in inc["protocol"].lower()
                or s in inc.get("flag", "").lower()
                or s in notes_str.lower()
            )
            if not match:
                continue
        filtered.append(inc)

    # Sorting
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    if sort_by in ["severity_desc", "severity"]:
        filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "low").lower(), 0), reverse=True)
    elif sort_by == "severity_asc":
        filtered.sort(key=lambda x: sev_rank.get(x.get("severity", "low").lower(), 0), reverse=False)
    elif sort_by in ["prob_desc", "probability_desc", "probability"]:
        filtered.sort(key=lambda x: x.get("attack_probability", 0.0), reverse=True)
    elif sort_by in ["prob_asc", "probability_asc"]:
        filtered.sort(key=lambda x: x.get("attack_probability", 0.0), reverse=False)
    elif sort_by in ["timestamp_asc", "oldest"]:
        filtered.sort(key=lambda x: x.get("timestamp", ""))
    else:  # timestamp_desc / newest (default)
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
    notes: Optional[str] = None,
    analyst: str = "SOC Analyst"
) -> Optional[Dict[str, Any]]:
    """
    Updates the lifecycle status of an existing incident with strict transition validation.
    Valid lifecycle: NEW -> INVESTIGATING -> CONFIRMED -> RESOLVED.
    """
    valid_statuses = ["New", "Investigating", "Confirmed", "Resolved"]
    normalized = next((s for s in valid_statuses if s.lower() == new_status.lower()), None)
    if not normalized:
        raise ValueError(f"Invalid status: '{new_status}'. Allowed: {valid_statuses}")

    inc = get_incident_by_id(incident_id)
    if not inc:
        return None

    current_status = inc.get("status", "New")

    # If same status, update note if provided without error
    if current_status.lower() == normalized.lower():
        if notes:
            add_incident_note(incident_id, notes, analyst)
        return inc

    # Lifecycle state transition validation rules
    # Allowed:
    # New -> Investigating, Resolved
    # Investigating -> Confirmed, Resolved
    # Confirmed -> Resolved
    # Resolved -> Investigating (Reopening allowed with reason)
    # Disallowed:
    # Confirmed -> New
    # Investigating -> New
    # Resolved -> New
    # Resolved -> Confirmed
    if current_status == "New" and normalized not in ["Investigating", "Resolved"]:
        raise ValueError(f"Invalid transition from 'New' to '{normalized}'. Allowed: Investigating, Resolved.")
    elif current_status == "Investigating" and normalized not in ["Confirmed", "Resolved"]:
        raise ValueError(f"Invalid transition from 'Investigating' to '{normalized}'. Cannot revert to 'New'. Allowed: Confirmed, Resolved.")
    elif current_status == "Confirmed" and normalized not in ["Resolved"]:
        raise ValueError(f"Invalid transition from 'Confirmed' to '{normalized}'. Cannot revert to '{normalized}'. Allowed: Resolved.")
    elif current_status == "Resolved" and normalized not in ["Investigating"]:
        raise ValueError(f"Invalid transition from 'Resolved' to '{normalized}'. Resolved incidents can only be reopened to 'Investigating'.")

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    inc["status"] = normalized

    # Update lifecycle timestamp
    ts_dict = inc.setdefault("timeline_timestamps", {
        "detected_at": inc.get("timestamp", now_str),
        "investigating_at": None,
        "confirmed_at": None,
        "resolved_at": None
    })

    if normalized == "Investigating" and not ts_dict.get("investigating_at"):
        ts_dict["investigating_at"] = now_str
    elif normalized == "Confirmed" and not ts_dict.get("confirmed_at"):
        ts_dict["confirmed_at"] = now_str
    elif normalized == "Resolved" and not ts_dict.get("resolved_at"):
        ts_dict["resolved_at"] = now_str

    # Record in lifecycle history
    history = inc.setdefault("lifecycle_history", [])
    history.append({
        "status": normalized,
        "timestamp": now_str,
        "note": notes or f"Status transitioned from {current_status} to {normalized}.",
        "actor": analyst
    })

    # Record note if provided
    if notes:
        notes_list = inc.setdefault("notes", [])
        notes_list.append({
            "id": f"note-{len(notes_list) + 1}",
            "text": notes,
            "timestamp": now_str,
            "analyst": analyst
        })

    return inc


def add_incident_note(
    incident_id: str,
    text: str,
    analyst: str = "SOC Analyst"
) -> Optional[Dict[str, Any]]:
    """
    Adds a timestamped analyst note to an incident.
    """
    inc = get_incident_by_id(incident_id)
    if not inc:
        return None

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    notes_list = inc.setdefault("notes", [])
    note_id = f"note-{len(notes_list) + 1}"

    note_obj = {
        "id": note_id,
        "text": text,
        "timestamp": now_str,
        "analyst": analyst
    }
    notes_list.append(note_obj)
    return note_obj


def get_related_incidents(
    incident_id: str,
    max_count: int = 5
) -> List[Dict[str, Any]]:
    """
    Finds correlated incidents sharing the same attack family, service, or protocol.
    """
    target = get_incident_by_id(incident_id)
    if not target:
        return []

    related = []
    for inc in _INCIDENTS_STORE:
        if inc["id"].lower() == incident_id.lower():
            continue

        matches = []
        if inc.get("attack_family") == target.get("attack_family"):
            matches.append(f"Same Family ({inc.get('attack_family')})")
        if inc.get("service") == target.get("service"):
            matches.append(f"Same Service ({inc.get('service')})")
        if inc.get("protocol") == target.get("protocol"):
            matches.append(f"Same Protocol ({inc.get('protocol')})")

        if matches:
            related.append({
                "id": inc["id"],
                "sample_id": inc["sample_id"],
                "timestamp": inc["timestamp"],
                "attack_family": inc["attack_family"],
                "severity": inc["severity"],
                "status": inc["status"],
                "service": inc["service"],
                "protocol": inc["protocol"],
                "relationship_reason": ", ".join(matches)
            })

        if len(related) >= max_count:
            break

    return related


def get_incident_evidence(incident_id: str) -> Optional[Dict[str, Any]]:
    """
    Compiles complete investigation evidence package for an incident.
    Integrates Stage 1 decision, Stage 2 distribution, key observed features,
    global Random Forest feature importances, threat intelligence, and audit history.
    """
    inc = get_incident_by_id(incident_id)
    if not inc:
        return None

    features = inc.get("features", {})
    family = inc.get("attack_family", "Unknown")

    # Global Random Forest Feature Importances
    feature_contributions = explain_single_sample(features)

    # Contextual Threat Intelligence
    intel = CONTEXTUAL_THREAT_INTEL.get(family, {
        "family": family,
        "behavior": f"Observed anomaly matching {family} signature profile.",
        "common_vectors": ["General Intrusion Vector"],
        "recommended_playbook": ["Inspect network logs", "Verify host integrity", "Block suspicious sources"]
    })

    # Key Observed Features
    observed_summary = {
        "protocol": inc.get("protocol", "TCP"),
        "service": inc.get("service", "http"),
        "flag": inc.get("flag", "SF"),
        "duration": inc.get("duration", 0.0),
        "src_bytes": inc.get("src_bytes", 0.0),
        "dst_bytes": inc.get("dst_bytes", 0.0),
        "count": inc.get("count", 1.0),
        "srv_count": inc.get("srv_count", 1.0),
        "same_srv_rate": inc.get("same_srv_rate", 1.0),
        "diff_srv_rate": inc.get("diff_srv_rate", 0.0),
        "serror_rate": inc.get("serror_rate", 0.0),
        "dst_host_srv_count": inc.get("dst_host_srv_count", 255.0),
        "dst_host_same_srv_rate": inc.get("dst_host_same_srv_rate", 1.0),
        "dst_host_serror_rate": inc.get("dst_host_serror_rate", 0.0)
    }

    # Related events
    related = get_related_incidents(incident_id, max_count=5)

    return {
        "incident_id": inc["id"],
        "sample_id": inc["sample_id"],
        "timestamp": inc["timestamp"],
        "attack_family": inc["attack_family"],
        "severity": inc["severity"],
        "status": inc["status"],
        "stage1_probability": inc.get("attack_probability", 1.0),
        "stage1_threshold": inc.get("stage1_threshold", 0.40),
        "stage1_verdict": inc.get("stage1_decision", "Attack"),
        "stage2_probabilities": inc.get("stage2_probabilities", {}),
        "observed_features_summary": observed_summary,
        "features_snapshot": features,
        "global_feature_importance": feature_contributions if isinstance(feature_contributions, list) else feature_contributions.get("contributions", []),
        "importance_note": "Global Random Forest Gini feature importances extracted from trained model trees.",
        "threat_intelligence": intel,
        "lifecycle_history": inc.get("lifecycle_history", []),
        "timeline_timestamps": inc.get("timeline_timestamps", {}),
        "notes": inc.get("notes", []),
        "related_incidents": related
    }


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
    Exports all in-memory incident records as clean, standardized CSV formatted text.
    """
    output = io.StringIO()
    fieldnames = [
        "incident_id", "sample_id", "timestamp", "status", "attack_family",
        "severity", "stage1_probability", "protocol", "service", "flag",
        "duration", "src_bytes", "dst_bytes", "count", "srv_count",
        "same_srv_rate", "serror_rate", "detected_at", "investigating_at",
        "confirmed_at", "resolved_at", "notes_count"
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    for inc in _INCIDENTS_STORE:
        ts_dict = inc.get("timeline_timestamps", {})
        notes_list = inc.get("notes", [])
        notes_cnt = len(notes_list) if isinstance(notes_list, list) else 1

        writer.writerow({
            "incident_id": inc["id"],
            "sample_id": inc["sample_id"],
            "timestamp": inc["timestamp"],
            "status": inc["status"],
            "attack_family": inc["attack_family"],
            "severity": inc["severity"],
            "stage1_probability": f"{inc.get('attack_probability', 0.0):.4f}",
            "protocol": inc.get("protocol", "TCP"),
            "service": inc.get("service", "http"),
            "flag": inc.get("flag", "SF"),
            "duration": inc.get("duration", 0.0),
            "src_bytes": inc.get("src_bytes", 0.0),
            "dst_bytes": inc.get("dst_bytes", 0.0),
            "count": inc.get("count", 1.0),
            "srv_count": inc.get("srv_count", 1.0),
            "same_srv_rate": inc.get("same_srv_rate", 1.0),
            "serror_rate": inc.get("serror_rate", 0.0),
            "detected_at": ts_dict.get("detected_at", inc.get("timestamp", "")),
            "investigating_at": ts_dict.get("investigating_at", "") or "",
            "confirmed_at": ts_dict.get("confirmed_at", "") or "",
            "resolved_at": ts_dict.get("resolved_at", "") or "",
            "notes_count": notes_cnt
        })

    return output.getvalue()
