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
        "name": "Mixed Incursion (Controlled Sequence)",
        "description": "Standard sequence: Normal ➔ Normal ➔ Probe ➔ Probe ➔ DoS ➔ DoS ➔ R2L ➔ U2R.",
        "distribution": {"normal": 0.25, "probe": 0.25, "dos": 0.25, "r2l": 0.125, "u2r": 0.125},
        "sequence": ["normal", "normal", "probe", "probe", "dos", "dos", "r2l", "u2r"]
    },
    "baseline_normal": {
        "id": "baseline_normal",
        "name": "Normal Operations Baseline",
        "description": "Exclusively legitimate enterprise network communications (HTTP, SMTP, Domain DNS, FTP-Data).",
        "distribution": {"normal": 1.0, "dos": 0.0, "probe": 0.0, "r2l": 0.0, "u2r": 0.0},
        "sequence": ["normal", "normal", "normal", "normal", "normal", "normal"]
    },
    "port_reconnaissance": {
        "id": "port_reconnaissance",
        "name": "Port Reconnaissance & Host Sweep",
        "description": "Active network mapping, host discovery sweeps (IPSweep), and port scanning (Satan/Nmap).",
        "distribution": {"normal": 0.0, "probe": 1.0, "dos": 0.0, "r2l": 0.0, "u2r": 0.0},
        "sequence": ["probe", "probe", "probe", "probe", "probe"]
    },
    "dos_syn_flood": {
        "id": "dos_syn_flood",
        "name": "DoS Storm (SYN Flood Campaign)",
        "description": "High-volume resource exhaustion attacks (Neptune TCP SYN flood and Smurf ICMP broadcast amplification).",
        "distribution": {"normal": 0.0, "dos": 1.0, "probe": 0.0, "r2l": 0.0, "u2r": 0.0},
        "sequence": ["dos", "dos", "dos", "dos", "dos"]
    },
    "remote_compromise": {
        "id": "remote_compromise",
        "name": "R2L Intrusion Attempt (Warez / Password Guess)",
        "description": "Remote unauthorized access attempts, telnet password guessing, and rogue FTP downloads.",
        "distribution": {"normal": 0.0, "r2l": 1.0, "probe": 0.0, "dos": 0.0, "u2r": 0.0},
        "sequence": ["r2l", "r2l", "r2l", "r2l"]
    },
    "privilege_escalation": {
        "id": "privilege_escalation",
        "name": "U2R Rootkit Escalation",
        "description": "Local privilege escalation attacks attempting root shell acquisition (Rootkit, Buffer Overflow).",
        "distribution": {"normal": 0.0, "u2r": 1.0, "probe": 0.0, "dos": 0.0, "r2l": 0.0},
        "sequence": ["u2r", "u2r", "u2r", "u2r"]
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
    # Normalize scenario ID aliases
    alias_map = {
        "normal": "baseline_normal",
        "normal_baseline": "baseline_normal",
        "probe": "port_reconnaissance",
        "dos": "dos_syn_flood",
        "dos_storm": "dos_syn_flood",
        "r2l": "remote_compromise",
        "r2l_intrusion": "remote_compromise",
        "u2r": "privilege_escalation",
        "u2r_escalation": "privilege_escalation",
        "mixed": "mixed_enterprise",
        "mixed_incursion": "mixed_enterprise"
    }
    normalized_id = alias_map.get(scenario_id, scenario_id)
    scenario = SCENARIOS.get(normalized_id, SCENARIOS["mixed_enterprise"])

    if seed is not None:
        rng = random.Random(seed + (step_index or 0))
    elif step_index is not None:
        rng = random.Random(step_index * 1337)
    else:
        rng = random.Random()

    # Determine category
    seq = scenario.get("sequence", [])
    if seq and step_index is not None:
        chosen_cat = seq[step_index % len(seq)]
    else:
        dist = scenario["distribution"]
        categories = list(dist.keys())
        weights = list(dist.values())
        chosen_cat = rng.choices(categories, weights=weights, k=1)[0]

    # For deterministic scenarios, use the verified PRESET data directly
    preset_key = chosen_cat.lower()
    if preset_key in PRESETS:
        sample_data = PRESETS[preset_key]["data"]
        flow_hint = PRESETS[preset_key]["name"]
        ground_truth = PRESETS[preset_key]["label"]
    else:
        sample_data = PRESETS["normal"]["data"]
        flow_hint = "Normal Traffic"
        ground_truth = "normal"

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
