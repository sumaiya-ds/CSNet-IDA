"""
Deterministic Network Traffic Simulation Engine for CSNet-IDA.
Feeds authentic NSL-KDD benchmark feature vectors into the real two-stage inference engine.
"""

import random
from typing import Dict, Any, List, Optional
from src.presets import STREAM_SAMPLES, PRESETS
from src.inference import predict_connection

# Seeded / Deterministic scenario definitions
SCENARIOS: Dict[str, Dict[str, Any]] = {
    "mixed_enterprise": {
        "id": "mixed_enterprise",
        "name": "Enterprise Mixed Operations",
        "description": "Standard corporate network profile with background HTTP/SMTP/DNS traffic and intermittent threat incursions.",
        "distribution": {"normal": 0.65, "dos": 0.15, "probe": 0.10, "r2l": 0.07, "u2r": 0.03}
    },
    "baseline_normal": {
        "id": "baseline_normal",
        "name": "Normal Operations Baseline",
        "description": "Exclusively legitimate enterprise network communications (HTTP, SMTP, Domain DNS, FTP-Data).",
        "distribution": {"normal": 1.0, "dos": 0.0, "probe": 0.0, "r2l": 0.0, "u2r": 0.0}
    },
    "dos_syn_flood": {
        "id": "dos_syn_flood",
        "name": "DoS SYN Flood Campaign",
        "description": "High-volume resource exhaustion attacks (Neptune TCP SYN flood and Smurf ICMP broadcast amplification).",
        "distribution": {"normal": 0.15, "dos": 0.75, "probe": 0.10, "r2l": 0.0, "u2r": 0.0}
    },
    "port_reconnaissance": {
        "id": "port_reconnaissance",
        "name": "Reconnaissance & Port Sweep",
        "description": "Active network mapping, host discovery sweeps (IPSweep), and port scanning (Satan/Nmap).",
        "distribution": {"normal": 0.20, "dos": 0.0, "probe": 0.75, "r2l": 0.05, "u2r": 0.0}
    },
    "remote_compromise": {
        "id": "remote_compromise",
        "name": "R2L Brute-Force & Exploit",
        "description": "Remote unauthorized access attempts, telnet password guessing, and rogue FTP downloads.",
        "distribution": {"normal": 0.25, "dos": 0.0, "probe": 0.05, "r2l": 0.70, "u2r": 0.0}
    },
    "privilege_escalation": {
        "id": "privilege_escalation",
        "name": "U2R Rootkit Exploitation",
        "description": "Local privilege escalation attacks attempting root shell acquisition (Rootkit, Buffer Overflow).",
        "distribution": {"normal": 0.30, "dos": 0.0, "probe": 0.0, "r2l": 0.0, "u2r": 0.70}
    }
}


def get_scenario_list() -> List[Dict[str, Any]]:
    """Returns metadata for all available simulation scenarios."""
    return list(SCENARIOS.values())


def generate_simulation_step(
    scenario_id: str = "mixed_enterprise",
    step_index: Optional[int] = None,
    seed: Optional[int] = None
) -> Dict[str, Any]:
    """
    Generates a single deterministic simulation step for a chosen scenario.
    Evaluates the connection vector against the REAL two-stage inference model.
    """
    if seed is not None:
        rng = random.Random(seed + (step_index or 0))
    elif step_index is not None:
        rng = random.Random(step_index * 1337)
    else:
        rng = random.Random()

    scenario = SCENARIOS.get(scenario_id, SCENARIOS["mixed_enterprise"])
    dist = scenario["distribution"]

    # Choose category based on distribution
    categories = list(dist.keys())
    weights = list(dist.values())
    chosen_cat = rng.choices(categories, weights=weights, k=1)[0]

    # Select authentic vector from STREAM_SAMPLES matching category
    matched_samples = []
    for s in STREAM_SAMPLES:
        label = s["ground_truth_label"].lower()
        if chosen_cat == "normal" and label == "normal":
            matched_samples.append(s)
        elif chosen_cat == "dos" and label in ("neptune", "smurf", "pod", "back", "teardrop"):
            matched_samples.append(s)
        elif chosen_cat == "probe" and label in ("ipsweep", "satan", "nmap", "portsweep"):
            matched_samples.append(s)
        elif chosen_cat == "r2l" and label in ("warezclient", "guess_passwd", "ftp_write"):
            matched_samples.append(s)
        elif chosen_cat == "u2r" and label in ("rootkit", "buffer_overflow", "loadmodule"):
            matched_samples.append(s)

    if not matched_samples:
        # Fallback to preset if not found in stream samples
        preset_key = chosen_cat
        if preset_key in PRESETS:
            sample_data = PRESETS[preset_key]["data"]
            flow_hint = PRESETS[preset_key]["name"]
            ground_truth = PRESETS[preset_key]["label"]
        else:
            sample_data = PRESETS["normal"]["data"]
            flow_hint = "Normal Traffic"
            ground_truth = "normal"
    else:
        chosen_sample = rng.choice(matched_samples)
        sample_data = chosen_sample["data"]
        flow_hint = chosen_sample["flow_hint"]
        ground_truth = chosen_sample["ground_truth_label"]

    # Run REAL inference through the model
    prediction_result = predict_connection(sample_data)

    return {
        "scenario_id": scenario["id"],
        "scenario_name": scenario["name"],
        "step_index": step_index,
        "flow_hint": flow_hint,
        "ground_truth_label": ground_truth,
        "features": sample_data,
        "prediction": prediction_result.model_dump()
    }
