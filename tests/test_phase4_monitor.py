"""
CSNet-IDA Phase 4 Verification Suite: Live Network Monitor & Simulation Engine.
Tests all simulation scenarios, streaming step execution, deterministic sequence progression,
incident ID linkages, rolling telemetry analytics, and reset lifecycle.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure root directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from src.model_loader import load_models
from src.inference import get_analytics_summary
from src.incidents import get_incidents, clear_incidents
from src.simulation import get_scenario_list, generate_simulation_step, SCENARIOS


class TestPhase4MonitorAndSimulation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        load_models()

    def setUp(self):
        # Reset state before each test
        clear_incidents()
        self.client.post("/api/reset")

    def test_01_all_scenarios_registered(self):
        """Test that all 6 deterministic scenarios are registered and available."""
        scenarios = SCENARIOS
        expected = [
            "mixed_enterprise",
            "baseline_normal",
            "port_reconnaissance",
            "dos_syn_flood",
            "remote_compromise",
            "privilege_escalation"
        ]
        for s_key in expected:
            self.assertIn(s_key, scenarios, f"Scenario '{s_key}' missing from registered scenarios.")
            meta = scenarios[s_key]
            self.assertIn("name", meta)
            self.assertIn("description", meta)
            self.assertIn("sequence", meta)
            self.assertGreater(len(meta["sequence"]), 0)

    def test_02_mixed_enterprise_sequence_progression(self):
        """
        Verify that mixed_enterprise follows the deterministic progression:
        Normal -> Normal -> Probe -> Probe -> DoS -> DoS -> R2L -> U2R
        """
        expected_verdicts = ["Normal", "Normal", "Probe", "Probe", "DoS", "DoS", "R2L", "U2R"]
        
        for idx, expected in enumerate(expected_verdicts):
            resp = self.client.post("/api/simulate-step", json={
                "scenario": "mixed_enterprise",
                "step_index": idx
            })
            self.assertEqual(resp.status_code, 200, f"Step {idx} failed: {resp.text}")
            data = resp.json()
            
            pred = data["prediction"]
            self.assertEqual(pred["final_prediction"], expected,
                             f"Step {idx} expected verdict '{expected}', got '{pred['final_prediction']}'")
            
            # If attack, verify incident_id is assigned and stage1 prob >= 0.40
            if expected != "Normal":
                self.assertTrue(pred["is_attack"], f"Step {idx} expected attack flag True")
                self.assertIsNotNone(pred["incident_id"], f"Step {idx} attack flow must have incident_id")
                self.assertTrue(pred["incident_id"].startswith("INC-2026-"), f"Invalid incident_id format: {pred['incident_id']}")
                self.assertGreaterEqual(pred["stage1"]["attack_probability"], 0.40)
            else:
                self.assertFalse(pred["is_attack"], f"Step {idx} expected attack flag False")
                self.assertLess(pred["stage1"]["attack_probability"], 0.40)

    def test_03_all_scenarios_step_execution(self):
        """Test step execution across all 6 scenarios."""
        for scenario_key in SCENARIOS.keys():
            resp = self.client.post("/api/simulate-step", json={
                "scenario": scenario_key,
                "step_index": 0
            })
            self.assertEqual(resp.status_code, 200, f"Scenario '{scenario_key}' step failed")
            data = resp.json()
            
            self.assertIn("prediction", data)
            self.assertIn("features", data)
            self.assertIn("flow_hint", data)
            
            pred = data["prediction"]
            self.assertIn("sample_id", pred)
            self.assertIn("timestamp", pred)
            self.assertIn("stage1", pred)
            self.assertIn("stage2", pred)
            self.assertIn("final_prediction", pred)
            self.assertIn("alert_severity", pred)
            self.assertIn("latency_ms", pred)

    def test_04_rolling_telemetry_timeline(self):
        """Verify that analytics timeline stores attack probabilities and sample IDs for chart rendering."""
        # Execute 3 steps
        for i in range(3):
            self.client.post("/api/simulate-step", json={
                "scenario": "mixed_enterprise",
                "step_index": i
            })
        
        resp = self.client.get("/api/analytics")
        self.assertEqual(resp.status_code, 200)
        analytics = resp.json()
        
        self.assertIn("timeline", analytics)
        self.assertGreaterEqual(len(analytics["timeline"]), 3)
        
        last_item = analytics["timeline"][-1]
        self.assertIn("attack_prob", last_item)
        self.assertIn("sample_id", last_item)
        self.assertIn("is_attack", last_item)
        self.assertIn("family", last_item)
        self.assertIn("severity", last_item)

    def test_05_reset_returns_nominal_posture(self):
        """Verify that reset endpoint clears all state and resets security posture to NOMINAL."""
        # Cause critical incursion (DoS SYN flood)
        for i in range(2):
            self.client.post("/api/simulate-step", json={
                "scenario": "dos_syn_flood",
                "step_index": i
            })
        
        # Check posture is CRITICAL
        resp_before = self.client.get("/api/analytics")
        self.assertEqual(resp_before.json()["posture_level"], "critical")
        
        # Perform Reset
        reset_resp = self.client.post("/api/reset")
        self.assertEqual(reset_resp.status_code, 200)
        
        # Check posture is now NOMINAL
        resp_after = self.client.get("/api/analytics")
        data_after = resp_after.json()
        self.assertEqual(data_after["posture"], "NOMINAL")
        self.assertEqual(data_after["posture_level"], "low")
        self.assertEqual(data_after["critical_alerts"], 0)
        self.assertEqual(data_after["total_flows"], 0)


if __name__ == "__main__":
    unittest.main()
