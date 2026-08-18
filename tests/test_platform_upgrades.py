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
    assert d_init["posture"] == "NOMINAL"
    assert d_init["posture_level"] == "low"

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


def test_end_to_end_phase3_suite():
    """
    Comprehensive End-to-End Test Suite for Phase 3:
    1. Normal scenario
    2. Probe scenario
    3. DoS scenario
    4. R2L scenario
    5. U2R scenario
    6. Mixed scenario
    7. Incident creation
    8. Incident filtering
    9. Incident investigation
    10. Status transitions
    11. Incident resolution
    12. Posture recalculation
    13. Command Center KPI updates
    14. Chart updates
    15. Reset functionality
    16. Connection Inspector
    17. Five verified presets
    """
    clear_history()
    clear_incidents()

    # 15. Reset functionality check
    r_reset = client.post("/api/reset")
    assert r_reset.status_code == 200
    a_reset = client.get("/api/analytics").json()
    assert a_reset["total_flows"] == 0
    assert a_reset["posture"] == "NOMINAL"
    assert a_reset["critical_alerts"] == 0

    # 17. Five verified presets check
    presets = {
        "normal": ("Normal", "low", False),
        "dos": ("DoS", "critical", True),
        "probe": ("Probe", "medium", True),
        "r2l": ("R2L", "high", True),
        "u2r": ("U2R", "critical", True)
    }
    for p_name, (exp_verdict, exp_sev, exp_attack) in presets.items():
        preset_data = client.get(f"/api/presets/{p_name}").json()
        p_res = client.post("/api/predict", json=preset_data["data"]).json()
        assert p_res["final_prediction"] == exp_verdict, f"Preset {p_name} expected {exp_verdict}, got {p_res['final_prediction']}"
        assert p_res["alert_severity"] == exp_sev, f"Preset {p_name} expected {exp_sev}, got {p_res['alert_severity']}"
        assert p_res["is_attack"] == exp_attack

    # 1. Normal Scenario
    step_norm = client.post("/api/simulate-step", json={"scenario": "baseline_normal", "step_index": 0}).json()
    assert step_norm["prediction"]["final_prediction"] == "Normal"
    assert step_norm["prediction"]["alert_severity"] == "low"

    # 2. Probe Scenario
    step_probe = client.post("/api/simulate-step", json={"scenario": "port_reconnaissance", "step_index": 0}).json()
    assert step_probe["prediction"]["final_prediction"] == "Probe"
    assert step_probe["prediction"]["alert_severity"] == "medium"

    # 3. DoS Scenario
    step_dos = client.post("/api/simulate-step", json={"scenario": "dos_syn_flood", "step_index": 0}).json()
    assert step_dos["prediction"]["final_prediction"] == "DoS"
    assert step_dos["prediction"]["alert_severity"] == "critical"

    # 4. R2L Scenario
    step_r2l = client.post("/api/simulate-step", json={"scenario": "remote_compromise", "step_index": 0}).json()
    assert step_r2l["prediction"]["final_prediction"] == "R2L"
    assert step_r2l["prediction"]["alert_severity"] == "high"

    # 5. U2R Scenario
    step_u2r = client.post("/api/simulate-step", json={"scenario": "privilege_escalation", "step_index": 0}).json()
    assert step_u2r["prediction"]["final_prediction"] == "U2R"
    assert step_u2r["prediction"]["alert_severity"] == "critical"

    # 6. Mixed Scenario Sequence (Normal -> Normal -> Probe -> Probe -> DoS -> DoS -> R2L -> U2R)
    expected_seq = ["Normal", "Normal", "Probe", "Probe", "DoS", "DoS", "R2L", "U2R"]
    for i, exp in enumerate(expected_seq):
        step_mix = client.post("/api/simulate-step", json={"scenario": "mixed_enterprise", "step_index": i}).json()
        assert step_mix["prediction"]["final_prediction"] == exp, f"Step {i} expected {exp}, got {step_mix['prediction']['final_prediction']}"

    # 7. Incident Creation
    inc_res = client.get("/api/incidents").json()
    assert inc_res["total"] > 0
    test_inc = inc_res["incidents"][0]
    assert "id" in test_inc
    assert test_inc["status"] in ("New", "Investigating", "Confirmed", "Resolved")

    # 8. Incident Filtering
    r_dos_filt = client.get("/api/incidents?family=DoS").json()
    assert all(x["attack_family"] == "DoS" for x in r_dos_filt["incidents"])
    r_crit_filt = client.get("/api/incidents?severity=critical").json()
    assert all(x["severity"] == "critical" for x in r_crit_filt["incidents"])

    # 9. Incident Investigation Modal Data
    inc_detail = client.get(f"/api/incidents/{test_inc['id']}").json()
    assert "incident" in inc_detail
    assert "feature_contributions" in inc_detail
    assert len(inc_detail["feature_contributions"]) > 0

    # 10. Status Transitions & 11. Incident Resolution
    client.patch(f"/api/incidents/{test_inc['id']}", json={"status": "Investigating"})
    assert client.get(f"/api/incidents/{test_inc['id']}").json()["incident"]["status"] == "Investigating"

    client.patch(f"/api/incidents/{test_inc['id']}", json={"status": "Confirmed"})
    assert client.get(f"/api/incidents/{test_inc['id']}").json()["incident"]["status"] == "Confirmed"

    client.patch(f"/api/incidents/{test_inc['id']}", json={"status": "Resolved"})
    assert client.get(f"/api/incidents/{test_inc['id']}").json()["incident"]["status"] == "Resolved"

    # 12. Posture Recalculation Test
    # Clear all and test dynamic postures
    client.post("/api/reset")
    a0 = client.get("/api/analytics").json()
    assert a0["posture"] == "NOMINAL"

    # Ingest Probe -> Active Medium -> ELEVATED
    client.post("/api/predict", json=client.get("/api/presets/probe").json()["data"])
    a_med = client.get("/api/analytics").json()
    assert a_med["posture"] == "ELEVATED"

    # Ingest R2L -> Active High -> HIGH
    client.post("/api/predict", json=client.get("/api/presets/r2l").json()["data"])
    a_hi = client.get("/api/analytics").json()
    assert a_hi["posture"] == "HIGH"

    # Ingest DoS -> Active Critical -> CRITICAL
    client.post("/api/predict", json=client.get("/api/presets/dos").json()["data"])
    a_crit = client.get("/api/analytics").json()
    assert a_crit["posture"] == "CRITICAL"
    assert a_crit["critical_alerts"] == 1

    # Resolve all incidents -> Posture returns to NOMINAL
    active_incs = client.get("/api/incidents?status=New").json()["incidents"]
    for inc in active_incs:
        client.patch(f"/api/incidents/{inc['id']}", json={"status": "Resolved"})
    a_resolved = client.get("/api/analytics").json()
    assert a_resolved["posture"] == "NOMINAL"
    assert a_resolved["critical_alerts"] == 0

    # 13. Command Center KPI Updates
    assert a_resolved["total_flows"] == 3
    assert a_resolved["attack_flows"] == 3
    assert a_resolved["avg_latency_ms"] >= 0.0

    # 14. Chart Updates
    assert len(a_resolved["timeline"]) == 3
    for entry in a_resolved["timeline"]:
        assert "attack_prob" in entry
        assert "timestamp" in entry
        assert "is_attack" in entry

    # 16. Manual Connection Inspector
    man_res = client.post("/api/predict", json=client.get("/api/presets/dos").json()["data"]).json()
    assert man_res["stage1"]["threshold"] == 0.40
    assert man_res["stage1"]["attack_probability"] >= 0.40
    assert man_res["final_prediction"] == "DoS"


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
    test_end_to_end_phase3_suite()
    print("[PASS] 6. End-to-End Phase 3 Verification Suite (All 17 Checks)")

    print("\n>>> ALL PLATFORM UPGRADE TESTS PASSED SUCCESSFULLY! <<<\n")
