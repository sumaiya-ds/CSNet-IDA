"""
FastAPI application for CSNet-IDA Two-Stage Intrusion Detection & Security Intelligence Platform.
"""

from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request, Response, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from src.config import (
    STATIC_DIR,
    TEMPLATES_DIR,
    DEFAULT_STAGE1_THRESHOLD,
    FEATURE_NAMES,
    ATTACK_FAMILIES
)
from src.schemas import (
    ConnectionFeatures,
    PredictionResponse,
    PresetResponse,
    ModelInfoResponse,
    IncidentUpdateRequest,
    SimulationStepRequest
)
from src.inference import (
    predict_connection,
    get_history,
    clear_history,
    get_analytics_summary
)
from src.presets import (
    get_all_presets,
    get_preset_by_id
)
from src.incidents import (
    get_incidents,
    get_incident_by_id,
    update_incident_status,
    clear_incidents,
    export_incidents_csv
)
from src.explainability import (
    get_feature_importance_data,
    explain_single_sample
)
from src.evaluation import (
    get_evaluation_metrics
)
from src.simulation import (
    generate_simulation_step,
    get_scenario_list
)

START_TIME = datetime.now()

app = FastAPI(
    title="CSNet-IDA",
    description="Two-Stage Network Intrusion Detection & Security Intelligence Platform",
    version="2.0.0"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static file mount
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=FileResponse)
async def serve_dashboard():
    """Serves the CSNet-IDA Security Operations Center dashboard."""
    index_file = TEMPLATES_DIR / "index.html"
    return FileResponse(str(index_file))


# =========================================================================
# Prediction & Inference Endpoints
# =========================================================================

@app.post("/api/predict", response_model=PredictionResponse)
async def api_predict(features: ConnectionFeatures, threshold: Optional[float] = None):
    """
    Executes real two-stage intrusion detection on a 40-feature network connection record.
    Stage 1: Binary detection (Normal vs. Attack) using threshold.
    Stage 2: Attack-family classification (DoS, Probe, R2L, U2R) if Attack.
    """
    try:
        if threshold is not None and (threshold < 0.0 or threshold > 1.0):
            raise HTTPException(status_code=400, detail="Threshold must be between 0.0 and 1.0")

        result = predict_connection(features, custom_threshold=threshold)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference execution failed: {str(e)}")


@app.post("/api/explain")
async def api_explain_sample(features: ConnectionFeatures):
    """Computes feature contributions for a specific connection vector."""
    try:
        contributions = explain_single_sample(features.model_dump())
        return {"contributions": contributions}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explainability computation failed: {str(e)}")


# =========================================================================
# Incident Management Endpoints
# =========================================================================

@app.get("/api/incidents")
async def api_get_incidents(
    status: Optional[str] = Query(None),
    family: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("timestamp_desc"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """Returns filtered, sorted, and paginated detected security incidents."""
    return get_incidents(
        status=status,
        family=family,
        severity=severity,
        search=search,
        sort_by=sort_by,
        limit=limit,
        offset=offset
    )


@app.get("/api/incidents/{incident_id}")
async def api_get_incident_detail(incident_id: str):
    """Retrieves deep investigation details for a specific incident."""
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    
    # Compute feature contributions for this specific incident
    contributions = explain_single_sample(inc["features"])
    return {
        "incident": inc,
        "feature_contributions": contributions
    }


@app.patch("/api/incidents/{incident_id}")
async def api_update_incident(incident_id: str, update: IncidentUpdateRequest):
    """Updates the status and investigation notes of an incident."""
    try:
        updated = update_incident_status(incident_id, update.status, update.notes)
        if not updated:
            raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
        return {"success": True, "incident": updated}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.get("/api/incidents/export/csv")
async def api_export_incidents_csv():
    """Exports all stored incident telemetry as a CSV file."""
    csv_data = export_incidents_csv()
    filename = f"csnet_ida_incidents_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return PlainTextResponse(
        csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# =========================================================================
# Simulation Engine Endpoints
# =========================================================================

@app.get("/api/scenarios")
async def api_get_scenarios():
    """Returns list of all available simulation scenarios."""
    return {"scenarios": get_scenario_list()}


@app.post("/api/simulate-step")
async def api_simulate_step(req: SimulationStepRequest):
    """
    Executes a single simulation step for a chosen scenario and runs it
    through the actual two-stage model pipeline.
    """
    try:
        res = generate_simulation_step(
            scenario_id=req.scenario,
            step_index=req.step_index,
            seed=req.seed
        )
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation step failed: {str(e)}")


@app.get("/api/simulate-event")
async def api_simulate_event_legacy():
    """Single random simulation step for streaming monitor."""
    try:
        res = generate_simulation_step(scenario_id="mixed_enterprise")
        return {
            "flow_hint": res["flow_hint"],
            "ground_truth_label": res["ground_truth_label"],
            "features": res["features"],
            "prediction": res["prediction"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Simulation failed: {str(e)}")


# =========================================================================
# Telemetry, Analytics, Explainability & Evaluation Endpoints
# =========================================================================

@app.get("/api/analytics")
async def api_get_analytics():
    """Returns session-wide aggregated telemetry and calculated security posture."""
    return get_analytics_summary()


@app.get("/api/feature-importance")
async def api_get_feature_importance():
    """Returns true feature importances directly from Random Forest models."""
    return get_feature_importance_data()


@app.get("/api/evaluation")
async def api_get_evaluation():
    """Returns academic benchmark metrics (Internal Held-out vs KDDTest+)."""
    return get_evaluation_metrics()


@app.get("/api/presets", response_model=List[PresetResponse])
async def api_get_presets():
    """Returns curated benchmark presets for testing (Normal, DoS, Probe, R2L, U2R)."""
    return get_all_presets()


@app.get("/api/presets/{preset_id}", response_model=PresetResponse)
async def api_get_preset_by_id(preset_id: str):
    """Returns a specific preset by its identifier."""
    try:
        return get_preset_by_id(preset_id)
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/model-info", response_model=ModelInfoResponse)
async def api_model_info():
    """Returns information regarding the two-stage model pipeline and feature schema."""
    return ModelInfoResponse()


@app.get("/api/history")
async def api_get_history(limit: int = Query(50, ge=1, le=100)):
    """Returns the in-memory connection flow analyses."""
    return {"history": get_history(limit=limit), "count": len(get_history(limit=limit))}


@app.post("/api/history/clear")
async def api_clear_history():
    """Clears in-memory analysis history and counters."""
    clear_history()
    clear_incidents()
    return {"success": True, "message": "Analysis history and incident registry cleared"}


@app.get("/api/health")
async def api_health():
    """Comprehensive system and model health status check."""
    uptime_seconds = int((datetime.now() - START_TIME).total_seconds())
    analytics = get_analytics_summary()
    return {
        "status": "online",
        "system": "CSNet-IDA Two-Stage Network IDS",
        "uptime_seconds": uptime_seconds,
        "models": {
            "preprocessor": "Loaded (ColumnTransformer, 120 dims)",
            "stage1_model": "Loaded (RandomForestClassifier, 100 trees)",
            "stage1_threshold": 0.40,
            "stage2_model": "Loaded (RandomForestClassifier Balanced, 100 trees)",
            "attack_families": ATTACK_FAMILIES
        },
        "telemetry": {
            "total_flows_analyzed": analytics["total_flows"],
            "avg_latency_ms": analytics["avg_latency_ms"]
        }
    }
