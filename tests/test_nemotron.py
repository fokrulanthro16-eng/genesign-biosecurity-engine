"""GeneSign NVIDIA Nemotron AI Threat Intelligence & Biosecurity Rationale Tests.

Verifies:
1. NVIDIA Nemotron advisor initialization and provider configuration.
2. Threat rationale endpoint POST /api/v1/analyze/ai-rationale on UNKNOWN_DRIFT.
3. Threat rationale endpoint POST /api/v1/analyze/ai-rationale on TAMPERED_PAYLOAD.
4. Threat rationale endpoint POST /api/v1/analyze/ai-rationale on ROGUE_SYNTHETIC.
5. Deterministic guard fallback resilience when external network is unavailable.
6. Operational status endpoint GET /api/v1/analyze/ai-status.
"""

import pytest
from fastapi.testclient import TestClient
from web.app import app
from engine.nemotron import NemotronBiosecurityAdvisor, nemotron_advisor


client = TestClient(app)


def test_nemotron_advisor_status_endpoint():
    """Verifies GET /api/v1/analyze/ai-status reports active model configuration."""
    resp = client.get("/api/v1/analyze/ai-status")
    assert resp.status_code == 200
    data = resp.json()
    assert "provider" in data
    assert "model_id" in data
    assert "endpoint" in data
    assert "has_api_key" in data
    assert data["has_api_key"] is True


def test_ai_rationale_unknown_drift():
    """Tests executive rationale generation for UNKNOWN_DRIFT classification."""
    req_payload = {
        "record_id": "ORDER-BENIGN-UNKNOWN-01",
        "classification": "UNKNOWN_DRIFT",
        "sequence_length": 850,
        "gc_content": 48.5,
        "threat_detected": False,
        "highest_threat_tier": "NONE",
        "threat_matches": [],
        "tampered": False,
        "status_summary": "UNWATERMARKED BENIGN: Sequence does not contain GeneSign provenance token.",
        "lab_id": "UNKNOWN",
        "order_id": "ORD-999",
    }

    resp = client.post("/api/v1/analyze/ai-rationale", json=req_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert data["classification"] == "UNKNOWN_DRIFT"
    assert "model" in data
    assert "provider" in data
    assert isinstance(data["risk_score"], int)
    assert 0 <= data["risk_score"] <= 100
    assert len(data["executive_summary"]) > 20
    assert len(data["regulatory_implications"]) > 20
    assert isinstance(data["recommended_actions"], list)
    assert len(data["recommended_actions"]) >= 1
    assert any("HHS" in data["regulatory_implications"] or "customer" in data["executive_summary"].lower() or "provenance" in data["executive_summary"].lower() for _ in [1])


def test_ai_rationale_tampered_payload():
    """Tests executive rationale and E-STOP mitigation for TAMPERED_PAYLOAD classification."""
    req_payload = {
        "record_id": "ORDER-MUTATED-CORRUPT-02",
        "classification": "TAMPERED_PAYLOAD",
        "sequence_length": 720,
        "gc_content": 51.2,
        "threat_detected": False,
        "highest_threat_tier": "NONE",
        "threat_matches": [],
        "tampered": True,
        "status_summary": "TAMPER INTERLOCK TRIPPED: CRC16 checksum desynchronized.",
        "lab_id": "TWS",
        "order_id": "ORD-001",
    }

    resp = client.post("/api/v1/analyze/ai-rationale", json=req_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert data["classification"] == "TAMPERED_PAYLOAD"
    assert data["risk_score"] >= 70  # Tampered payload is a high-severity security alert
    assert len(data["recommended_actions"]) >= 2
    # Verify operational directives advise halt/quarantine
    actions_text = " ".join(data["recommended_actions"]).lower()
    assert ("halt" in actions_text or "lock" in actions_text or "quarantine" in actions_text or "interlock" in actions_text or "e-stop" in actions_text)


def test_ai_rationale_rogue_synthetic():
    """Tests critical pathogen containment rationale for ROGUE_SYNTHETIC classification."""
    req_payload = {
        "record_id": "ORDER-RICIN-ATTACK-03",
        "classification": "ROGUE_SYNTHETIC",
        "sequence_length": 810,
        "gc_content": 44.0,
        "threat_detected": True,
        "highest_threat_tier": "SELECT AGENT TOXIN",
        "threat_matches": [
            {
                "agent_name": "Ricin Toxin (A-chain)",
                "regulatory_tier": "SELECT AGENT TOXIN",
                "target_gene": "RTA",
            }
        ],
        "tampered": False,
        "status_summary": "CRITICAL BIOSECURITY VIOLATION: Unsigned sequence matching SELECT AGENT TOXIN!",
        "lab_id": None,
        "order_id": None,
    }

    resp = client.post("/api/v1/analyze/ai-rationale", json=req_payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["success"] is True
    assert data["classification"] == "ROGUE_SYNTHETIC"
    assert data["risk_score"] >= 90  # Critical threat
    assert len(data["recommended_actions"]) >= 2


def test_deterministic_guard_fallback():
    """Verifies that the advisor seamlessly switches to the high-reliability expert engine if offline."""
    offline_advisor = NemotronBiosecurityAdvisor(api_key="")
    assert offline_advisor.api_key == ""

    result = offline_advisor.analyze_threat_rationale({
        "record_id": "OFFLINE-TEST",
        "classification": "TAMPERED_PAYLOAD",
        "sequence_length": 600,
        "threat_detected": False,
        "tampered": True,
    })

    assert result["success"] is True
    assert result["is_fallback"] is True
    assert result["classification"] == "TAMPERED_PAYLOAD"
    assert result["risk_score"] == 88
    assert "CRC16 checksum desynchronization" in result["executive_summary"]
    assert len(result["recommended_actions"]) == 4
