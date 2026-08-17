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


def explain_single_sample(features: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Computes transparent feature contributions for a specific connection vector.
    Calculates sample value prominence weighted by model feature importance.
    """
    imp_data = get_feature_importance_data()
    stage1_all = {x["feature"]: x["importance"] for x in imp_data["stage1_all_aggregated"]}

    explanations = []
    for feat_name, imp in stage1_all.items():
        val = features.get(feat_name, 0.0)
        # Determine deviation significance for numerical features
        if isinstance(val, (int, float)):
            score = float(val) * float(imp)
        else:
            score = float(imp)

        explanations.append({
            "feature": feat_name,
            "value": str(val),
            "global_importance": round(imp, 4),
            "impact_score": round(score, 4)
        })

    explanations.sort(key=lambda x: x["global_importance"], reverse=True)
    return explanations[:8]
