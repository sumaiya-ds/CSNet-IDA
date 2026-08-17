"""
Explainability and Feature Importance module for CSNet-IDA.
Extracts real feature importances directly from the trained Random Forest models.
"""

from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd

from src.config import FEATURE_NAMES, CATEGORICAL_FEATURES, NUMERICAL_FEATURES
from src.model_loader import get_preprocessor, get_stage1_model, get_stage2_model

_EXPLAINABILITY_CACHE: Dict[str, Any] = {}


def get_feature_importance_data() -> Dict[str, Any]:
    """
    Extracts and caches the actual feature importances from Stage 1 and Stage 2 Random Forest classifiers.
    Aggregates one-hot encoded categorical features back to the 40 original NSL-KDD attributes.
    """
    global _EXPLAINABILITY_CACHE
    if _EXPLAINABILITY_CACHE:
        return _EXPLAINABILITY_CACHE

    preprocessor = get_preprocessor()
    stage1_rf = get_stage1_model()
    stage2_rf = get_stage2_model()

    # Transformed feature names (120 features)
    transformed_feature_names = preprocessor.get_feature_names_out().tolist()
    stage1_importances = stage1_rf.feature_importances_.tolist()
    stage2_importances = stage2_rf.feature_importances_.tolist()

    # Build detailed 120-dim feature importance table
    stage1_transformed = [
        {"feature": name, "importance": round(float(imp), 6)}
        for name, imp in zip(transformed_feature_names, stage1_importances)
    ]
    stage1_transformed.sort(key=lambda x: x["importance"], reverse=True)

    stage2_transformed = [
        {"feature": name, "importance": round(float(imp), 6)}
        for name, imp in zip(transformed_feature_names, stage2_importances)
    ]
    stage2_transformed.sort(key=lambda x: x["importance"], reverse=True)

    # Aggregate transformed one-hot features back to the 40 original input features
    stage1_orig_agg: Dict[str, float] = {}
    stage2_orig_agg: Dict[str, float] = {}

    for name, imp1, imp2 in zip(transformed_feature_names, stage1_importances, stage2_importances):
        if name.startswith("categorical__"):
            clean = name.replace("categorical__", "")
            if clean.startswith("protocol_type_"):
                orig_name = "protocol_type"
            elif clean.startswith("service_"):
                orig_name = "service"
            elif clean.startswith("flag_"):
                orig_name = "flag"
            else:
                orig_name = clean
        elif name.startswith("numerical__"):
            orig_name = name.replace("numerical__", "")
        else:
            orig_name = name

        stage1_orig_agg[orig_name] = stage1_orig_agg.get(orig_name, 0.0) + float(imp1)
        stage2_orig_agg[orig_name] = stage2_orig_agg.get(orig_name, 0.0) + float(imp2)

    # Sort aggregated 40 features
    stage1_aggregated = [
        {"feature": name, "importance": round(imp, 6)}
        for name, imp in sorted(stage1_orig_agg.items(), key=lambda x: x[1], reverse=True)
    ]

    stage2_aggregated = [
        {"feature": name, "importance": round(imp, 6)}
        for name, imp in sorted(stage2_orig_agg.items(), key=lambda x: x[1], reverse=True)
    ]

    # Feature Group Aggregations
    groups = {
        "Protocols & Flags (Categorical)": ["protocol_type", "service", "flag"],
        "Connection Basics & Payload": ["duration", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent"],
        "Authentication & Privileges": ["hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells", "num_access_files", "is_host_login", "is_guest_login"],
        "Time-Window Traffic Rates": ["count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate"],
        "Destination Host Statistics": ["dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate"]
    }

    stage1_grouped = []
    for g_name, f_list in groups.items():
        g_imp = sum(stage1_orig_agg.get(f, 0.0) for f in f_list)
        stage1_grouped.append({"group": g_name, "importance": round(g_imp, 4), "feature_count": len(f_list)})
    stage1_grouped.sort(key=lambda x: x["importance"], reverse=True)

    _EXPLAINABILITY_CACHE = {
        "transformed_feature_count": len(transformed_feature_names),
        "original_feature_count": len(FEATURE_NAMES),
        "stage1_top20_transformed": stage1_transformed[:20],
        "stage2_top20_transformed": stage2_transformed[:20],
        "stage1_top15_aggregated": stage1_aggregated[:15],
        "stage2_top15_aggregated": stage2_aggregated[:15],
        "stage1_all_aggregated": stage1_aggregated,
        "stage2_all_aggregated": stage2_aggregated,
        "stage1_grouped": stage1_grouped
    }

    return _EXPLAINABILITY_CACHE


FEATURE_DESCRIPTIONS = {
    "src_bytes": "Number of data bytes transmitted from source to destination.",
    "dst_bytes": "Number of data bytes transmitted from destination back to source.",
    "flag": "Normal or error status of the TCP connection (e.g. SF, S0, REJ).",
    "service": "Network destination service/port requested (e.g. http, smtp, private).",
    "same_srv_rate": "Percentage of connections to the same service in the past 2 seconds.",
    "diff_srv_rate": "Percentage of connections to different services in the past 2 seconds.",
    "dst_host_diff_srv_rate": "Percentage of connections to different services across destination host history.",
    "dst_host_srv_serror_rate": "Percentage of connections with SYN errors to the same service on destination host.",
    "dst_host_serror_rate": "Percentage of connections with SYN errors on the destination host.",
    "count": "Number of connections to the same host as the current connection in the past 2 seconds.",
    "srv_count": "Number of connections to the same service as the current connection in the past 2 seconds.",
    "logged_in": "1 if successfully logged in; 0 if unauthenticated / guest.",
    "num_compromised": "Number of compromised conditions encountered on the system.",
    "root_shell": "1 if root shell access was obtained; 0 otherwise.",
    "hot": "Number of hot indicators (e.g., accessing system directories, executing programs)."
}


def explain_single_sample(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Computes transparent feature contributions for a specific connection vector.
    Pairs global Random Forest feature importance with the flow's specific observed values.
    Does not claim causal SHAP attribution; explicitly states model split importance + observed value.
    """
    imp_data = get_feature_importance_data()
    stage1_list = imp_data["stage1_all_aggregated"]

    # Priority features that are academically verified as key indicators in NSL-KDD
    priority_keys = [
        "src_bytes", "dst_bytes", "flag", "service", "same_srv_rate",
        "diff_srv_rate", "dst_host_diff_srv_rate", "dst_host_srv_serror_rate",
        "count", "logged_in"
    ]

    explanations = []
    for rank, item in enumerate(stage1_list, 1):
        feat_name = item["feature"]
        imp = item["importance"]
        val = features.get(feat_name, 0)

        # Generate technical context signal
        val_str = str(val)
        signal = "Within nominal operational baseline."

        if feat_name == "flag":
            if val == "S0":
                signal = "SYN without ACK (S0) — signature of TCP SYN flooding / resource exhaustion."
            elif val == "REJ":
                signal = "Connection rejected (REJ) — destination port closed / port scan indicator."
            elif val == "SF":
                signal = "Normal TCP establishment and termination (SF)."
        elif feat_name == "src_bytes" and float(val) == 0.0:
            signal = "Zero source payload — abnormal for non-handshake data streams."
        elif feat_name == "dst_bytes" and float(val) == 0.0:
            signal = "Zero destination response bytes — server unreachable or connection dropped."
        elif feat_name == "dst_host_srv_serror_rate" and float(val) > 0.5:
            signal = f"High SYN error rate ({float(val)*100:.0f}%) to target service across destination host."
        elif feat_name == "count" and float(val) > 50:
            signal = f"High burst velocity ({val} connections in 2s) to identical host."
        elif feat_name == "diff_srv_rate" and float(val) > 0.5:
            signal = f"High service diversity ({float(val)*100:.0f}%) — characteristic of port reconnaissance."
        elif feat_name == "logged_in" and int(val) == 0:
            signal = "Session unauthenticated (logged_in = 0)."
        elif feat_name == "root_shell" and int(val) == 1:
            signal = "CRITICAL: Root shell acquired on target system."
        elif feat_name == "num_compromised" and float(val) > 0:
            signal = f"ALERT: {val} compromised system files/indicators detected."

        explanations.append({
            "feature": feat_name,
            "rank": rank,
            "value": val_str,
            "flow_value": val_str,
            "global_importance": round(imp, 6),
            "global_importance_pct": round(imp * 100, 2),
            "description": FEATURE_DESCRIPTIONS.get(feat_name, "Network connection metric."),
            "detection_signal": signal,
            "is_priority": feat_name in priority_keys
        })

    # Return top 10 ranked features ensuring verified priority features are prominent
    explanations.sort(key=lambda x: (not x["is_priority"], x["rank"]))
    return explanations[:10]

