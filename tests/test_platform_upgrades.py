"""
Platform Upgrades and SOC Workflow Verification Suite for CSNet-IDA.
Validates:
- Security risk score calculations and posture indexing
- Incident sorting and status lifecycle state machine
- CSV incident export
- Feature importance extraction
- Live simulation scenarios and model integrity
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.main import app
from src.incidents import clear_incidents
from src.inference import clear_history

client = TestClient(app)


def setup_function():
    """Reset session state before each test."""
    clear_history()
    clear_incidents()


def test_analytics_and_risk_score():
    """Validates real-time security posture and mathematical risk score computation."""
    # Initially idle
    r_init = client.get("/api/analytics")
    assert r_init.status_code == 200
    d_init = r_init.json()
    assert d_init["total_flows"] == 0
    assert d_init["risk_score"] == 0.0
    assert d_init["posture_level"] == "info"

    # Ingest Normal flow
    p_norm = client.get("/api/presets/normal").json()
    client.post("/api/predict", json=p_norm["data"])

    r_norm = client.get("/api/analytics").json()
    assert r_norm["total_flows"] == 1
    assert r_norm["normal_flows"] == 1
    assert r_norm["attack_flows"] == 0
    assert r_norm["risk_score"] == 0.0
    assert r_norm["posture_level"] == "low"

    # Ingest DoS (Critical) attack flow
    p_dos = client.get("/api/presets/dos").json()
    client.post("/api/predict", json=p_dos["data"])

    r_dos = client.get("/api/analytics").json()
    assert r_dos["total_flows"] == 2
    assert r_dos["attack_flows"] == 1
    assert r_dos["critical_alerts"] == 1
    assert r_dos["risk_score"] > 0.0
    assert 0.0 <= r_dos["risk_score"] <= 100.0


def test_incident_lifecycle_workflow():
    """Tests the full analyst lifecycle: New -> Investigating -> Confirmed -> Resolved."""
    # Ingest attack to generate incident
    p_probe = client.get("/api/presets/probe").json()
    pred_res = client.post("/api/predict", json=p_probe["data"]).json()
    assert pred_res["is_attack"] is True

    # List incidents
    inc_list = client.get("/api/incidents").json()
    assert inc_list["total"] >= 1
    target_inc = inc_list["incidents"][0]
    inc_id = target_inc["id"]
    assert target_inc["status"] == "New"

    # Step 1: Transition to Investigating
    r_inv = client.patch(f"/api/incidents/{inc_id}", json={
        "status": "Investigating",
        "notes": "Analyst assigned: verifying ICMP ping sweep velocity."
    })
    assert r_inv.status_code == 200
    assert r_inv.json()["incident"]["status"] == "Investigating"

    # Step 2: Transition to Confirmed
    r_conf = client.patch(f"/api/incidents/{inc_id}", json={
        "status": "Confirmed",
        "notes": "Confirmed malicious reconnaissance from external source."
    })
    assert r_conf.status_code == 200
    assert r_conf.json()["incident"]["status"] == "Confirmed"

    # Step 3: Transition to Resolved
    r_res = client.patch(f"/api/incidents/{inc_id}", json={
        "status": "Resolved",
        "notes": "Source IP rate-limited at perimeter firewall. Incident closed."
    })
    assert r_res.status_code == 200
    assert r_res.json()["incident"]["status"] == "Resolved"


def test_incident_sorting_and_filtering():
    """Tests multi-parameter incident sorting and search."""
    # Ingest multiple diverse attacks
    for p_id in ["dos", "probe", "r2l", "u2r"]:
        preset = client.get(f"/api/presets/{p_id}").json()
        client.post("/api/predict", json=preset["data"])

    # Test Severity Descending Sort
    r_sev_desc = client.get("/api/incidents?sort_by=severity_desc").json()
    assert r_sev_desc["total"] == 4
    first_sev = r_sev_desc["incidents"][0]["severity"]
    assert first_sev in ("critical", "high")

    # Test Probability Descending Sort
    r_prob_desc = client.get("/api/incidents?sort_by=prob_desc").json()
    probs = [x["attack_probability"] for x in r_prob_desc["incidents"]]
    assert probs == sorted(probs, reverse=True)

    # Test Family Filtering
    r_dos_only = client.get("/api/incidents?family=DoS").json()
    assert all(x["attack_family"] == "DoS" for x in r_dos_only["incidents"])

    # Test CSV Export
    r_csv = client.get("/api/incidents/export/csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]
    assert "id,sample_id,timestamp" in r_csv.text


def test_explainability_integrity():
    """Ensures feature importances are extracted directly from trained Random Forest models."""
    r_fi = client.get("/api/feature-importance")
    assert r_fi.status_code == 200
    data = r_fi.json()

    assert data["transformed_feature_count"] == 120
    assert data["original_feature_count"] == 40
    assert len(data["stage1_all_aggregated"]) == 40
    assert len(data["stage2_all_aggregated"]) == 40

    # Ensure importances sum close to 1.0
    stage1_sum = sum(x["importance"] for x in data["stage1_all_aggregated"])
    assert 0.95 <= stage1_sum <= 1.05


def test_simulation_scenarios():
    """Verifies that all 6 deterministic simulation scenarios evaluate correctly."""
    data = client.get("/api/scenarios").json()
    scenarios = data.get("scenarios", [])
    assert len(scenarios) == 6

    for sc in scenarios:
        step_res = client.post("/api/simulate-step", json={
            "scenario": sc["id"],
            "step_index": 1
        })
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert "prediction" in step_data
        assert "features" in step_data
        assert step_data["prediction"]["stage1"]["threshold"] == 0.40


if __name__ == "__main__":
    print("\n=======================================================")
    print("  CSNet-IDA Platform Upgrades Verification Suite")
    print("=======================================================")
    setup_function()
    test_analytics_and_risk_score()
    print("[PASS] 1. Analytics & Risk Score Calculation")
    setup_function()
    test_incident_lifecycle_workflow()
    print("[PASS] 2. Incident Lifecycle Workflow (New->Investigating->Confirmed->Resolved)")
    setup_function()
    test_incident_sorting_and_filtering()
    print("[PASS] 3. Incident Sorting, Filtering & CSV Export")
    test_explainability_integrity()
    print("[PASS] 4. Explainability & Random Forest Feature Importance")
    test_simulation_scenarios()
    print("[PASS] 5. Simulation Scenarios & Model Pipeline Execution")
    print("\n>>> ALL PLATFORM UPGRADE TESTS PASSED SUCCESSFULLY! <<<\n")
