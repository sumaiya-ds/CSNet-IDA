"""
Model loader module with caching and integrity checks for CSNet-IDA artifacts.
"""

import os
from typing import Dict, Any, List
import joblib

from src.config import (
    PREPROCESSOR_PATH,
    STAGE1_MODEL_PATH,
    STAGE1_THRESHOLD_PATH,
    STAGE2_MODEL_PATH,
    STAGE2_LABELS_PATH,
    DEFAULT_STAGE1_THRESHOLD
)

_LOADED_MODELS: Dict[str, Any] = {}


def load_models() -> Dict[str, Any]:
    """
    Loads all required saved model artifacts from the models/ directory.
    Uses in-memory caching to avoid redundant file I/O.
    """
    global _LOADED_MODELS
    if _LOADED_MODELS:
        return _LOADED_MODELS

    # Verify all expected files exist
    required_files = {
        "preprocessor": PREPROCESSOR_PATH,
        "stage1_model": STAGE1_MODEL_PATH,
        "stage1_threshold": STAGE1_THRESHOLD_PATH,
        "stage2_model": STAGE2_MODEL_PATH,
        "stage2_labels": STAGE2_LABELS_PATH,
    }

    missing_files = [str(path) for name, path in required_files.items() if not path.exists()]
    if missing_files:
        raise FileNotFoundError(
            f"Missing required model artifact(s): {', '.join(missing_files)}"
        )

    # Load artifacts using joblib
    preprocessor = joblib.load(PREPROCESSOR_PATH)
    stage1_model = joblib.load(STAGE1_MODEL_PATH)
    
    try:
        stage1_threshold = float(joblib.load(STAGE1_THRESHOLD_PATH))
    except Exception:
        stage1_threshold = DEFAULT_STAGE1_THRESHOLD

    stage2_model = joblib.load(STAGE2_MODEL_PATH)
    stage2_labels = joblib.load(STAGE2_LABELS_PATH)

    # Convert stage2_labels to list if numpy array
    if hasattr(stage2_labels, "tolist"):
        stage2_labels = stage2_labels.tolist()

    _LOADED_MODELS = {
        "preprocessor": preprocessor,
        "stage1_model": stage1_model,
        "stage1_threshold": stage1_threshold,
        "stage2_model": stage2_model,
        "stage2_labels": stage2_labels,
    }

    return _LOADED_MODELS


def get_preprocessor():
    return load_models()["preprocessor"]


def get_stage1_model():
    return load_models()["stage1_model"]


def get_stage1_threshold() -> float:
    return load_models()["stage1_threshold"]


def get_stage2_model():
    return load_models()["stage2_model"]


def get_stage2_labels() -> List[str]:
    return load_models()["stage2_labels"]
