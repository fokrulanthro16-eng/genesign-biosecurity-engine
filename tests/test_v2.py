"""GeneSign Level 2 Enterprise & Industrial Biosecurity Test Suite.

Verifies:
1. Multi-Tenant Key Management Service (KMS) provider registration, key versioning, and Ed25519 signing.
2. Key Revocation List (CRL) enforcement and provenance verification failure on revoked keys.
3. Scalable Threat Detector canonical k-mer sliding window matching (Ebola, Smallpox, Chimeric Furin, Tier-1 toxins).
4. Asynchronous Batch FASTA / FASTQ ingestion pipeline and multi-state compliance screening.
5. System health probe (/healthz) and Level 2 REST endpoints.
"""

from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient

from engine.kms import KeyManagementService, ProviderKey, SynthesisProvider, kms_service
from engine.threat_detector import ScalableThreatDetector, threat_detector
from scanner.firewall import BiosecurityFirewall, ComplianceClassification, SequenceParser
from engine.watermark import embed_watermark, clean_sequence
from web.app import app, BATCH_JOBS


SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Multi-Tenant Key Management Service (KMS) & CRL Tests
# ---------------------------------------------------------------------------
def test_kms_default_providers():
    """Verify default synthesis provider tenants are initialized with valid Ed25519 keys."""
    assert "TWIST" in kms_service.providers
    assert "GINKGO" in kms_service.providers
    assert "IDT" in kms_service.providers

    twist = kms_service.providers["TWIST"]
    assert twist.status == "ACTIVE"
    assert twist.active_key_version == "v1"

    active_key = twist.get_active_key()
    assert active_key is not None
    assert len(active_key.fingerprint) == 16
    assert active_key.revoked is False


def test_kms_key_rotation():
    """Verify seamless key rotation increments version and produces distinct cryptographic keys."""
    initial_key = kms_service.providers["GINKGO"].get_active_key()
    initial_fp = initial_key.fingerprint

    # Rotate to v2
    new_key = kms_service.rotate_provider_key("GINKGO")
    assert new_key.version == "v2"
    assert new_key.fingerprint != initial_fp
    assert kms_service.providers["GINKGO"].active_key_version == "v2"
    assert len(kms_service.providers["GINKGO"].keys) >= 2


def test_kms_signing_and_verification():
    """Verify asymmetric provenance token generation and cryptographic integrity verification."""
    sample_seq = "ATGGCCCTGTGGATGCGCCTCCTGCCCCTGCTGGCGCTGCTGGCCCTCTGGGGACCTGACCCAGCCGCA"
    token = kms_service.sign_provenance("TWIST", sample_seq, order_id="ORD-9901")

    assert token["token_header"]["format"] == "GeneSign-Provenance-v2"
    assert token["claims"]["provider_id"] == "TWIST"
    assert token["claims"]["order_id"] == "ORD-9901"

    # Verify authentic token
    verification = kms_service.verify_provenance(token, sample_seq)
    assert verification["valid"] is True
    assert verification["hash_match"] is True
    assert verification["signature_valid"] is True
    assert verification["crl_revoked"] is False

    # Verify tamper sensitivity (1-base mutation breaks hash match)
    mutated_seq = sample_seq[:-1] + ("A" if sample_seq[-1] != "A" else "C")
    tampered_verification = kms_service.verify_provenance(token, mutated_seq)
    assert tampered_verification["valid"] is False
    assert tampered_verification["hash_match"] is False


def test_kms_crl_revocation():
    """Verify that revoking a provider key immediately blocks verification via CRL interlock."""
    test_kms = KeyManagementService(kms_dir=Path(__file__).resolve().parent.parent / "keys" / "test_scratch")
    test_kms.register_provider("TEST-LAB", "Test Biosecurity Lab", "US-NY")

    seq = "ATGGCCCTGTGGATGCGCCTCCTGCCCCTGCTGGCGCTGCTGGCCCTCTGGGGACCTGACCCAGCCGCA"
    token = test_kms.sign_provenance("TEST-LAB", seq, order_id="ORD-TEST")

    # Initial verification passes
    assert test_kms.verify_provenance(token, seq)["valid"] is True

    # Revoke key v1
    crl_entry = test_kms.revoke_key("TEST-LAB", "v1", reason="COMPROMISED_KEYSTORE_AUDIT")
    assert crl_entry["key_version"] == "v1"
    assert crl_entry["reason"] == "COMPROMISED_KEYSTORE_AUDIT"
    assert len(test_kms.get_crl()) >= 1

    # Subsequent verification must fail with CRL violation
    revoked_eval = test_kms.verify_provenance(token, seq)
    assert revoked_eval["valid"] is False
    assert revoked_eval["crl_revoked"] is True
    assert "KEY_REVOKED_CRL_VIOLATION" in revoked_eval["error"]


# ---------------------------------------------------------------------------
# 2. Scalable Threat Detector Tests
# ---------------------------------------------------------------------------
def test_threat_detector_select_agents():
    """Verify canonical k-mer sliding window identification of Filoviridae and Poxviridae."""
    detector = ScalableThreatDetector(k=16)

    # 1. Ebola VP35
    ebola_path = SAMPLES_DIR / "ebola_vp35.fasta"
    ebola_seq = list(SequenceParser.parse_stream(ebola_path.read_text(encoding="utf-8")))[0].sequence
    ebola_res = detector.scan_sequence(ebola_seq)
    assert ebola_res["threat_detected"] is True
    assert len(ebola_res["hits"]) > 0
    assert any("Ebola" in h["agent_name"] for h in ebola_res["hits"])
    assert any("TIER-1" in h["regulatory_tier"] or "SELECT AGENT" in h["regulatory_tier"] for h in ebola_res["hits"])

    # 2. Smallpox Hemagglutinin
    smallpox_path = SAMPLES_DIR / "smallpox_ha.fasta"
    smallpox_seq = list(SequenceParser.parse_stream(smallpox_path.read_text(encoding="utf-8")))[0].sequence
    smallpox_res = detector.scan_sequence(smallpox_seq)
    assert smallpox_res["threat_detected"] is True
    assert len(smallpox_res["hits"]) > 0
    assert any("Variola" in h["agent_name"] or "Smallpox" in h["agent_name"] for h in smallpox_res["hits"])

    # 3. Benign Negative Control (GFP)
    gfp_path = SAMPLES_DIR / "gfp.fasta"
    gfp_seq = list(SequenceParser.parse_stream(gfp_path.read_text(encoding="utf-8")))[0].sequence
    gfp_res = detector.scan_sequence(gfp_seq)
    assert gfp_res["threat_detected"] is False
    assert len(gfp_res["hits"]) == 0, "Benign GFP must yield 0 threat matches"


def test_threat_detector_chimeric_and_toxins():
    """Verify detection of engineered furin cleavage motifs and CDC Tier-1 toxins."""
    detector = ScalableThreatDetector(k=16)

    # Engineered Furin loop construct
    chimeric_construct = (
        "ATGGCCCTGTGG"
        "CCTCGGCGGGCACGTAGTGTAGCTAGTCAATCCATCATTGCCTACACTATGTCACTTGGTGCAGAAAATTCAGTTGCTTACTCTAATAACTCTATTGCCATACCC"
        "GCCCTCTGGGGA"
    )
    chimeric_res = detector.scan_sequence(chimeric_construct)
    assert chimeric_res["threat_detected"] is True
    assert any("Chimeric" in h["agent_name"] or "Furin" in h["agent_name"] for h in chimeric_res["hits"])

    # Botulinum neurotoxin catalytic motif
    bont_construct = (
        "ATGCCATTTGTTAATAAACAATTTAATTATAAAGATCCTGTAAATGGTGTTGATATTGCTTATATAAAAATTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCT"
    )
    bont_res = detector.scan_sequence(bont_construct)
    assert bont_res["threat_detected"] is True
    assert any("Botulinum" in h["agent_name"] for h in bont_res["hits"])


# ---------------------------------------------------------------------------
# 3. Asynchronous Batch Screening Pipeline & REST Endpoints
# ---------------------------------------------------------------------------
def test_healthz_endpoint():
    """Verify /healthz system health check."""
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["version"] == "2.2.0-ENTERPRISE"
    assert data["active_providers"] >= 3
    assert data["threat_index_count"] >= 5


def test_kms_rest_endpoints():
    """Verify Level 2 KMS REST provider registry and rotation endpoints."""
    # List providers
    prov_resp = client.get("/api/v2/kms/providers")
    assert prov_resp.status_code == 200
    prov_data = prov_resp.json()
    assert prov_data["total_providers"] >= 3

    # Rotate IDT key
    rot_resp = client.post("/api/v2/kms/providers/IDT/rotate")
    assert rot_resp.status_code == 200
    rot_data = rot_resp.json()
    assert rot_data["success"] is True
    assert rot_data["provider_id"] == "IDT"
    assert len(rot_data["fingerprint"]) == 16

    # Revoke key
    rev_resp = client.post("/api/v2/kms/providers/IDT/revoke", json={"reason": "SCHEDULED_KEY_RETIREMENT"})
    assert rev_resp.status_code == 200
    rev_data = rev_resp.json()
    assert rev_data["success"] is True
    assert rev_data["crl_entry"]["reason"] == "SCHEDULED_KEY_RETIREMENT"

    # Inspect CRL
    crl_resp = client.get("/api/v2/kms/crl")
    assert crl_resp.status_code == 200
    crl_data = crl_resp.json()
    assert crl_data["total_revocations"] >= 1


def test_batch_screening_fasta_pipeline():
    """Verify multi-record FASTA batch scanning asynchronously screens orders."""
    fasta_path = SAMPLES_DIR / "batch_synthesis_orders.fasta"
    fasta_content = fasta_path.read_text(encoding="utf-8")

    # Upload batch
    resp = client.post(
        "/api/v2/batch-scan",
        data={"fasta_text": fasta_content},
    )
    assert resp.status_code == 200
    data = resp.json()
    job_id = data["job_id"]
    assert job_id.startswith("BATCH-")

    # Poll status until completed (max 5 seconds)
    completed = False
    for _ in range(25):
        poll_resp = client.get(f"/api/v2/batch-scan/{job_id}")
        assert poll_resp.status_code == 200
        poll_data = poll_resp.json()
        if poll_data["status"] == "completed":
            completed = True
            break
        time.sleep(0.2)

    assert completed is True, "Batch scanning job must complete asynchronously"
    assert poll_data["total_records"] >= 7
    assert poll_data["progress_percent"] == 100.0

    # Verify multi-state classification representation
    summary = poll_data["summary"]
    assert summary["total"] >= 7
    assert summary["rogue_synthetic"] >= 2, "Must flag Ebola and Smallpox orders as ROGUE_SYNTHETIC"
    assert summary["threats_flagged"] >= 2
    assert summary["unknown_drift"] >= 1, "Must classify natural insulin/gfp as UNKNOWN_DRIFT"
    assert len(poll_data["manifest"]) >= 7


def test_batch_screening_fastq_pipeline():
    """Verify multi-record FASTQ stream screening handles quality-scored records."""
    fastq_path = SAMPLES_DIR / "batch_inspection.fastq"
    fastq_content = fastq_path.read_text(encoding="utf-8")

    resp = client.post(
        "/api/v2/batch-scan",
        data={"fasta_text": fastq_content},
    )
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    for _ in range(25):
        poll_resp = client.get(f"/api/v2/batch-scan/{job_id}")
        poll_data = poll_resp.json()
        if poll_data["status"] == "completed":
            break
        time.sleep(0.2)

    assert poll_data["status"] == "completed"
    assert poll_data["total_records"] == 3
    manifest = poll_data["manifest"]
    assert any(m["format"] == "FASTQ" for m in manifest)
