"""
Automated validation suite for CSNet-IDA Phase 2 Backend Architecture.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from app.main import app

def run_tests():
    client = TestClient(app)
    
    print("\n" + "=" * 65)
    print("  CSNet-IDA Phase 2 Backend Architecture Validation")
    print("=" * 65)

    # 1. Health / Home
    res = client.get("/")
    assert res.status_code == 200, f"GET / failed: {res.status_code}"
    print("[PASS] 1. Dashboard HTML Template Loaded")

    # 2. System Health
    res = client.get("/api/health")
    assert res.status_code == 200
    health_data = res.json()
    assert health_data["status"] == "online"
    print(f"[PASS] 2. System Health Status: {health_data['status']} (Uptime: {health_data['uptime_seconds']}s)")

    # 3. Model Info
    res = client.get("/api/model-info")
    assert res.status_code == 200
    model_info = res.json()
    assert model_info["input_feature_count"] == 40
    print(f"[PASS] 3. Model Info Schema: {model_info['input_feature_count']} features defined, arch='{model_info['architecture']}'")

    # 4. Presets
    res = client.get("/api/presets")
    assert res.status_code == 200
    presets = res.json()
    assert len(presets) >= 5
    print(f"[PASS] 4. Curated Presets: {len(presets)} benchmark presets loaded")

    # 5. Predict with each preset
    print("\n--- Testing Two-Stage ML Inference Pipeline ---")
    for p in presets:
        sample = p["data"]
        res = client.post("/api/predict", json=sample)
        assert res.status_code == 200, f"Prediction failed for {p['name']}"
        data = res.json()
        s1_dec = data["stage1"]["decision"]
        s2_fam = data["stage2"]["attack_family"] if data.get("stage2") else "N/A"
        print(f"  * [PASS] {p['name']:<25} -> Stage1: {s1_dec:<6} | Final: {data['final_prediction']:<8} | Severity: {data['alert_severity']:<8} | Latency: {data['latency_ms']:.2f}ms")

    # 6. Incident Registry & Status Lifecycle
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incidents_data = res.json()
    print(f"\n[PASS] 6. Incident Management Registry: {incidents_data['total']} incidents registered")

    if incidents_data["incidents"]:
        inc_id = incidents_data["incidents"][0]["id"]
        # Detail view
        res = client.get(f"/api/incidents/{inc_id}")
        assert res.status_code == 200
        print(f"  * [PASS] Incident Detail Retrieval: ID {inc_id}")

        # Patch status
        res = client.patch(f"/api/incidents/{inc_id}", json={"status": "Investigating", "notes": "SOC Tier 2 analysis initiated"})
        assert res.status_code == 200
        assert res.json()["incident"]["status"] == "Investigating"
        print(f"  * [PASS] Incident Status Update Workflow: changed to 'Investigating'")

    # 7. Real-Time Explainability
    sample_dos = presets[1]["data"]
    res = client.post("/api/explain", json=sample_dos)
    assert res.status_code == 200
    explain_data = res.json()
    assert "contributions" in explain_data
    top_contrib = explain_data["contributions"][:3]
    top_str = ", ".join([f"{c['feature']} (imp={c['global_importance']:.3f}, val={c['value']})" for c in top_contrib])
    print(f"[PASS] 7. Real-time Feature Attribution (Explainability): Top factors -> {top_str}")

    # 8. Evaluation Benchmarks
    res = client.get("/api/evaluation")
    assert res.status_code == 200
    eval_data = res.json()
    assert "stage1_internal" in eval_data and "external_validation" in eval_data
    s1_acc = eval_data["stage1_internal"]["accuracy"]
    ext_acc = eval_data["external_validation"]["overall_accuracy"]
    print(f"[PASS] 8. Academic Evaluation Data: Validation Acc: {s1_acc:.2%} | KDDTest+ Acc: {ext_acc:.2%}")

    # 9. Simulation Engine
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    scenarios = res.json()["scenarios"]
    print(f"[PASS] 9. Simulation Engine: {len(scenarios)} scenarios available")

    res = client.post("/api/simulate-step", json={"scenario": scenarios[0]["id"], "step_index": 1})
    assert res.status_code == 200
    sim_step = res.json()
    print(f"  * [PASS] Simulation Step Execution: Scenario '{scenarios[0]['name']}' -> Final: {sim_step['prediction']['final_prediction']}")

    # 10. Analytics Summary
    res = client.get("/api/analytics")
    assert res.status_code == 200
    analytics = res.json()
    print(f"[PASS] 10. Real-time Analytics & SOC Telemetry: Total Flows: {analytics['total_flows']}, Attack Flows: {analytics['attack_flows']}, Posture: {analytics['posture']} ({analytics['posture_level'].upper()})")

    print("\n" + "=" * 65)
    print("  >>> ALL 10 VALIDATION SUITES PASSED SUCCESSFULLY! <<<")
    print("=" * 65 + "\n")

if __name__ == "__main__":
    run_tests()
