"""
CSNet-IDA Phase 5 Verification Suite: Incident Center 2.0 & SOC Workstation.
Comprehensive test suite validating:
1. Incident Data Model & 40-feature snapshot integrity.
2. Incident Investigation API (GET, PATCH, POST notes, evidence, CSV export).
3. Incident Lifecycle state transitions & strict transition rules (New -> Investigating -> Confirmed -> Resolved).
4. Full evidence package with authentic Stage 1/2 probabilities, global RF importances, and threat intel.
5. Analyst Notes recording and audit history tracking.
6. Correlated related incidents detection.
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure root directory is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from src.model_loader import load_models
from src.incidents import (
    create_incident,
    get_incidents,
    get_incident_by_id,
    update_incident_status,
    add_incident_note,
    get_incident_evidence,
    get_related_incidents,
    export_incidents_csv,
    clear_incidents
)
from src.presets import PRESETS


class TestPhase5Incidents(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        load_models()

    def setUp(self):
        # Clear incident store before each test
        clear_incidents()
        self.client.post("/api/reset")

    def _create_sample_attack_incident(self, preset_key="dos"):
        """Helper to create a verified authentic incident."""
        flow_features = PRESETS[preset_key]["data"].copy()
        resp = self.client.post("/api/predict", json=flow_features)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["is_attack"])
        self.assertIsNotNone(data["incident_id"])
        return data["incident_id"], data

    def test_01_incident_creation_and_fields(self):
        """Test incident creation produces complete structured data model."""
        inc_id, pred_data = self._create_sample_attack_incident("dos")
        
        inc = get_incident_by_id(inc_id)
        self.assertIsNotNone(inc)
        self.assertEqual(inc["id"], inc_id)
        self.assertEqual(inc["attack_family"], "DoS")
        self.assertEqual(inc["severity"].lower(), "critical")
        self.assertEqual(inc["status"], "New")
        self.assertGreaterEqual(inc["attack_probability"], 0.40)
        self.assertEqual(inc["stage1_threshold"], 0.40)
        self.assertEqual(inc["protocol"].lower(), "tcp")
        self.assertEqual(inc["service"], "private")
        self.assertEqual(inc["flag"], "S0")
        
        # Verify 40-feature snapshot is complete
        self.assertEqual(len(inc["features"]), 40)
        self.assertEqual(inc["features"]["protocol_type"], "tcp")
        self.assertEqual(inc["features"]["service"], "private")
        self.assertEqual(inc["features"]["flag"], "S0")
        self.assertEqual(inc["features"]["count"], 123.0)

        # Verify initial lifecycle history and timestamps
        self.assertGreaterEqual(len(inc["lifecycle_history"]), 1)
        self.assertEqual(inc["lifecycle_history"][0]["status"], "New")
        self.assertIn("detected_at", inc["timeline_timestamps"])

    def test_02_incident_list_api_and_filtering(self):
        """Test GET /api/incidents filtering and sorting."""
        # Create DoS, Probe, R2L, U2R incidents
        self._create_sample_attack_incident("dos")
        self._create_sample_attack_incident("probe")
        self._create_sample_attack_incident("r2l")
        self._create_sample_attack_incident("u2r")

        # 1. Get all
        resp = self.client.get("/api/incidents")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 4)
        self.assertEqual(len(data["incidents"]), 4)

        # 2. Filter by family
        resp = self.client.get("/api/incidents?family=DoS")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["incidents"][0]["attack_family"], "DoS")

        # 3. Filter by severity
        resp = self.client.get("/api/incidents?severity=Critical")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total"], 1)
        for inc in data["incidents"]:
            self.assertEqual(inc["severity"].lower(), "critical")

        # 4. Search by service
        resp = self.client.get("/api/incidents?search=private")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(data["total"], 1)

        # 5. Sort by probability descending
        resp = self.client.get("/api/incidents?sort_by=probability_desc")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        probs = [inc["attack_probability"] for inc in data["incidents"]]
        self.assertEqual(probs, sorted(probs, reverse=True))

    def test_03_incident_evidence_endpoint(self):
        """Test GET /api/incidents/{incident_id}/evidence returns comprehensive evidence package."""
        inc_id, _ = self._create_sample_attack_incident("dos")
        
        resp = self.client.get(f"/api/incidents/{inc_id}/evidence")
        self.assertEqual(resp.status_code, 200)
        ev = resp.json()

        self.assertEqual(ev["incident_id"], inc_id)
        self.assertEqual(ev["attack_family"], "DoS")
        self.assertEqual(ev["severity"].lower(), "critical")
        self.assertGreaterEqual(ev["stage1_probability"], 0.40)
        self.assertEqual(ev["stage1_threshold"], 0.40)
        self.assertEqual(ev["stage1_verdict"], "Attack")
        
        # Stage 2 probabilities
        self.assertIn("stage2_probabilities", ev)
        self.assertIn("DoS", ev["stage2_probabilities"])
        self.assertIn("Probe", ev["stage2_probabilities"])
        self.assertIn("R2L", ev["stage2_probabilities"])
        self.assertIn("U2R", ev["stage2_probabilities"])

        # 40-feature snapshot
        self.assertEqual(len(ev["features_snapshot"]), 40)

        # Observed features summary
        obs = ev["observed_features_summary"]
        self.assertEqual(obs["protocol"].lower(), "tcp")
        self.assertEqual(obs["service"], "private")
        self.assertEqual(obs["flag"], "S0")
        self.assertEqual(obs["count"], 123.0)

        # Global feature importance with non-fabrication methodology
        self.assertIn("global_feature_importance", ev)
        self.assertGreater(len(ev["global_feature_importance"]), 0)
        for feat in ev["global_feature_importance"]:
            self.assertIn("feature", feat)
            self.assertIn("global_importance_pct", feat)
            self.assertIn("detection_signal", feat)

        # Contextual threat intelligence
        self.assertIn("threat_intelligence", ev)
        intel = ev["threat_intelligence"]
        self.assertIn("DoS", intel["family"])
        self.assertIn("behavior", intel)
        self.assertIn("recommended_playbook", intel)

        # Lifecycle history & timestamps
        self.assertIn("lifecycle_history", ev)
        self.assertIn("timeline_timestamps", ev)
        self.assertIn("notes", ev)
        self.assertIn("related_incidents", ev)

    def test_04_lifecycle_progression_valid(self):
        """Test valid state transitions: New -> Investigating -> Confirmed -> Resolved."""
        inc_id, _ = self._create_sample_attack_incident("dos")
        
        # 1. Transition New -> Investigating
        resp = self.client.patch(f"/api/incidents/{inc_id}/status", json={
            "status": "Investigating",
            "notes": "Analyst began packet inspection",
            "analyst": "Analyst Alice"
        })
        self.assertEqual(resp.status_code, 200)
        inc = resp.json()["incident"]
        self.assertEqual(inc["status"], "Investigating")
        self.assertIsNotNone(inc["timeline_timestamps"].get("investigating_at"))

        # 2. Transition Investigating -> Confirmed
        resp = self.client.patch(f"/api/incidents/{inc_id}/status", json={
            "status": "Confirmed",
            "notes": "Confirmed SYN flood pattern",
            "analyst": "Analyst Alice"
        })
        self.assertEqual(resp.status_code, 200)
        inc = resp.json()["incident"]
        self.assertEqual(inc["status"], "Confirmed")
        self.assertIsNotNone(inc["timeline_timestamps"].get("confirmed_at"))

        # 3. Transition Confirmed -> Resolved
        resp = self.client.patch(f"/api/incidents/{inc_id}/status", json={
            "status": "Resolved",
            "notes": "Firewall rate limiting applied",
            "analyst": "Analyst Alice"
        })
        self.assertEqual(resp.status_code, 200)
        inc = resp.json()["incident"]
        self.assertEqual(inc["status"], "Resolved")
        self.assertIsNotNone(inc["timeline_timestamps"].get("resolved_at"))

        # Verify audit history has 4 entries
        self.assertEqual(len(inc["lifecycle_history"]), 4)

    def test_05_lifecycle_progression_invalid_transitions(self):
        """Test that invalid backward or illegal jumps are rejected with 400 Bad Request."""
        inc_id, _ = self._create_sample_attack_incident("dos")
        
        # Resolve incident directly
        resp = self.client.patch(f"/api/incidents/{inc_id}/status", json={
            "status": "Resolved",
            "notes": "Resolved immediately"
        })
        self.assertEqual(resp.status_code, 200)

        # Attempt illegal backward transition: Resolved -> New
        resp = self.client.patch(f"/api/incidents/{inc_id}/status", json={
            "status": "New",
            "notes": "Attempting illegal reset"
        })
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Invalid transition", resp.json()["detail"])

        # Attempt illegal transition: Resolved -> Confirmed
        resp = self.client.patch(f"/api/incidents/{inc_id}/status", json={
            "status": "Confirmed"
        })
        self.assertEqual(resp.status_code, 400)

    def test_06_analyst_notes_api(self):
        """Test POST /api/incidents/{incident_id}/notes appends structured notes."""
        inc_id, _ = self._create_sample_attack_incident("probe")

        # Add Note 1 (Incident already has 1 automated trigger note, so total becomes 2)
        resp = self.client.post(f"/api/incidents/{inc_id}/notes", json={
            "text": "Source IP observed scanning ports 80, 443, 8080.",
            "analyst": "Analyst Bob"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["notes"]), 2)
        self.assertEqual(data["notes"][-1]["text"], "Source IP observed scanning ports 80, 443, 8080.")
        self.assertEqual(data["notes"][-1]["analyst"], "Analyst Bob")

        # Add Note 2 (Total becomes 3)
        resp = self.client.post(f"/api/incidents/{inc_id}/notes", json={
            "text": "Isolated destination host from internal VLAN.",
            "analyst": "Lead Analyst"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data["notes"]), 3)

        # Verify notes appear in evidence endpoint
        resp_ev = self.client.get(f"/api/incidents/{inc_id}/evidence")
        self.assertEqual(len(resp_ev.json()["notes"]), 3)

    def test_07_related_incidents_correlation(self):
        """Test that incidents sharing family, service, or protocol are correlated."""
        # Create two DoS incidents (private service) and one Probe (eco_i service)
        id1, _ = self._create_sample_attack_incident("dos")
        id2, _ = self._create_sample_attack_incident("dos")
        id3, _ = self._create_sample_attack_incident("probe")

        related1 = get_related_incidents(id1)
        self.assertGreaterEqual(len(related1), 1)
        
        # Verify id2 is in related incidents of id1
        rel_ids = [r["id"] for r in related1]
        self.assertIn(id2, rel_ids)
        self.assertNotIn(id1, rel_ids)  # Cannot correlate with self

    def test_08_incident_csv_export(self):
        """Test GET /api/incidents/export/csv produces valid downloadable CSV."""
        self._create_sample_attack_incident("dos")
        self._create_sample_attack_incident("probe")

        resp = self.client.get("/api/incidents/export/csv")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.headers["content-type"])
        
        csv_text = resp.text
        lines = [line.strip() for line in csv_text.splitlines() if line.strip()]
        self.assertGreaterEqual(len(lines), 3)  # Header + 2 rows

        header = lines[0]
        self.assertIn("incident_id", header)
        self.assertIn("attack_family", header)
        self.assertIn("severity", header)
        self.assertIn("stage1_probability", header)
        self.assertIn("protocol", header)
        self.assertIn("service", header)
        self.assertIn("status", header)

    def test_09_nonexistent_incident_handling(self):
        """Test 404 response for non-existent incident IDs."""
        resp = self.client.get("/api/incidents/INC-NONEXISTENT")
        self.assertEqual(resp.status_code, 404)

        resp = self.client.get("/api/incidents/INC-NONEXISTENT/evidence")
        self.assertEqual(resp.status_code, 404)

        resp = self.client.patch("/api/incidents/INC-NONEXISTENT/status", json={"status": "Investigating"})
        self.assertEqual(resp.status_code, 404)

        resp = self.client.post("/api/incidents/INC-NONEXISTENT/notes", json={"text": "Test note"})
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
