"""GeneSign Level 3 Autonomous Biosecurity Network & Hardware Synthesis Interlock Test Suite.

Verifies:
1. Physical Synthesizer Hardware State Interlock (OPC-UA protocol simulation, safety gate, valve sealing, INTERLOCK_HALT).
2. Fragment Assembly De-anonymization & Overhang Reconstruction (sliding-window multi-order assembly of distributed evasion attacks).
3. Cryptographic Merkle Tree Ledger, hash-chaining, inclusion proofs, and RFC-3161 audit bundles.
4. Level 3 REST API endpoints.
"""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from engine.hardware_interlock import SynthesizerHardwareInterlock, HardwareState, ValveStatus, hardware_interlock
from engine.assembly_scanner import SplitOrderGraphAssembler, FragmentOrder, assembly_scanner
from engine.ledger import CryptographicAuditLedger, MerkleTree, GENESIS_HASH, sha256_hex
from engine.watermark import embed_watermark
from engine.kms import kms_service
from web.app import app


SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Hardware State Interlock Tests
# ---------------------------------------------------------------------------
def test_hardware_initial_standby_and_telemetry():
    """Verify hardware synthesizer initializes in safe locked standby."""
    interlock = SynthesizerHardwareInterlock(device_id="TEST-SYNTH-01")
    telem = interlock.get_telemetry()
    assert telem.device_id == "TEST-SYNTH-01"
    assert telem.state == HardwareState.LOCKED
    assert telem.interlock_latched is False
    assert telem.valves["monomer_a"] == "CLOSED"


def test_hardware_authorized_dispatch_synthesis():
    """Verify that cryptographically verified sequence passes safety gate and executes synthesis."""
    interlock = SynthesizerHardwareInterlock(device_id="TEST-SYNTH-02")

    # Generate genuine watermarked sequence with Ed25519 token
    gfp_path = SAMPLES_DIR / "gfp.fasta"
    from scanner.firewall import SequenceParser
    dna = list(SequenceParser.parse_stream(gfp_path.read_text(encoding="utf-8")))[0].sequence
    wm_res = embed_watermark(dna, {"lab_id": "TWIST", "order_id": "901", "key_fp": "1234"})
    token = kms_service.sign_provenance("TWIST", wm_res.watermarked_dna, order_id="901")

    # Dispatch to hardware
    res = interlock.dispatch_synthesis(
        sequence=wm_res.watermarked_dna,
        record_id="INSULIN-LICENSED",
        provenance_token=token,
        lab_id="TWIST",
        order_id="901",
    )

    assert res["success"] is True
    assert res["interlock_tripped"] is False
    assert res["classification"] == "VERIFIED_LICENSED"
    assert res["state"] == "COMPLETED"
    assert res["coupling_efficiency_pct"] >= 99.0
    assert interlock.interlock_latched is False


def test_hardware_unauthorized_pathogen_trips_interlock_halt():
    """Verify that an unauthorized rogue sequence immediately trips physical INTERLOCK_HALT."""
    interlock = SynthesizerHardwareInterlock(device_id="TEST-SYNTH-03")

    # Ebola VP35 sequence without provenance token
    ebola_frag = "ATGACAACTAGAACAAAGGGCAGGGGCCATACTGCGGCCACGACTCAAAACGACAGAATGCCAGGCCCTGAGCTTTCGGGCTGGATCTCTGAGCAGCTAATGACCGG"

    res = interlock.dispatch_synthesis(
        sequence=ebola_frag,
        record_id="ROGUE-EBOLA-ATTEMPT",
        provenance_token=None,
    )

    assert res["success"] is False
    assert res["interlock_tripped"] is True
    assert res["classification"] == "ROGUE_SYNTHETIC"
    assert res["state"] == "INTERLOCK_HALT"
    assert interlock.interlock_latched is True
    assert interlock.valves.monomer_a == ValveStatus.SEALED
    assert interlock.valves.monomer_t == ValveStatus.SEALED

    # Subsequent dispatch attempts must be blocked while latched
    blocked = interlock.dispatch_synthesis(
        sequence="ATGGCCCTGTGG",
        record_id="ANY-SUBSEQUENT-REQ",
    )
    assert blocked["success"] is False
    assert "Administrative reset required" in blocked["error"]


def test_hardware_reset_latch():
    """Verify administrative reset clears interlock latch."""
    interlock = SynthesizerHardwareInterlock(device_id="TEST-SYNTH-04")
    interlock.trigger_interlock_halt("Simulated safety trip")
    assert interlock.interlock_latched is True

    # Reset with valid key
    reset_res = interlock.reset_hardware(authorization_key="ADMIN-SECURITY-OVERRIDE")
    assert reset_res["success"] is True
    assert reset_res["state"] == "LOCKED"
    assert interlock.interlock_latched is False


# ---------------------------------------------------------------------------
# 2. Fragment Assembly De-anonymization Tests
# ---------------------------------------------------------------------------
def test_split_order_assembly_pathogen_evasion():
    """Verify assembly of fragmented sub-lethal oligos into composite pathogen construct."""
    scanner = SplitOrderGraphAssembler(min_overlap=18)

    # Split Botulinum Neurotoxin light chain catalytic sequence into 3 orders with 20bp overlaps
    # Target: ATGCCATTTGTTAATAAACAATTTAATTATAAAGATCCTGTAAATGGTGTTGATATTGCTTATATAAAAATTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCTTTTAAAATTCATAATAAAATATGGGTAATTCCAGAAAGAGATACATTTACAAATCCTGAAGAAGGAGATTTAAATCCACCACCAGAAGCAAAACAAGTTCCAGTTTCATATTATGATTCAACATATCTAAGTACAGATAATGAAAAAGATAACTATCTTAAAGGTGTAACTAAATTATTTGAACGTATTTATTCAACTGATTTGGGAAGA
    frag1 = "ATGCCATTTGTTAATAAACAATTTAATTATAAAGATCCTGTAAATGGTGTTGATATTGCTTATATAAAAATTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCT"
    # overlap: last 20 bp of frag1 = TTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCT
    # frag2 starts with overlap:
    frag2 = "TGCAGGTCAAATGCAACCAGTAAAAGCT" + "TTTAAAATTCATAATAAAATATGGGTAATTCCAGAAAGAGATACATTTACAAATCCTGAAGAAGGAGATTTAAA"
    # overlap: last 20 bp of frag2 = CCTGAAGAAGGAGATTTAAA
    frag3 = "CCTGAAGAAGGAGATTTAAA" + "TCCACCACCAGAAGCAAAACAAGTTCCAGTTTCATATTATGATTCAACATATCTAAGTACAGATAATGAAAAAGATAACTATCTTAAAGGTGTAACTAAATTATTTGAACGTATTTATTCAACTGATTTGGGAAGA"

    scanner.add_order(order_id="ORD-FRAGMENT-01", sequence=frag1, customer_id="CUST-ALPHA")
    scanner.add_order(order_id="ORD-FRAGMENT-02", sequence=frag2, customer_id="CUST-BETA")
    scanner.add_order(order_id="ORD-FRAGMENT-03", sequence=frag3, customer_id="CUST-GAMMA")

    contigs = scanner.reconstruct_contigs()
    assert len(contigs) > 0

    top_contig = contigs[0]
    assert len(top_contig.participating_order_ids) == 3
    assert top_contig.threat_detected is True
    assert "Botulinum" in (top_contig.agent_name or "")
    assert top_contig.assembled_length_nt > 200
    assert len(top_contig.overlap_junctions) == 2


def test_split_order_assembly_benign_negative_control():
    """Verify benign fragmented sequences reconstruct without flagging threat alerts."""
    scanner = SplitOrderGraphAssembler(min_overlap=18)

    # Split Benign GFP into 2 overlapping fragments
    gfp_full = (
        "ATGAGTAAAGGAGAAGAACTTTTCACTGGAGTTGTCCCAATTCTTGTTGAATTAGATGGTGATGTTAATGGGCACAAATTTTCTGTCCGTGGAGAGGGTGAAGGTGATGCT"
        "ACAAACGGAAAACTCACCCTTAAATTTATTTGCACTACTGGAAAACTACCTGTTCCATGGCCAACACTTGTCACTACTTTCTCTTATGGTGTTCAATGCTTTTCCCGTTAT"
    )
    half = len(gfp_full) // 2
    f1 = gfp_full[: half + 20]
    f2 = gfp_full[half:]

    scanner.add_order(order_id="ORD-GFP-1", sequence=f1, customer_id="LAB-A")
    scanner.add_order(order_id="ORD-GFP-2", sequence=f2, customer_id="LAB-B")

    contigs = scanner.reconstruct_contigs()
    assert len(contigs) > 0
    assert contigs[0].threat_detected is False


# ---------------------------------------------------------------------------
# 3. Merkle Tree & Cryptographic Hash-Chained Ledger Tests
# ---------------------------------------------------------------------------
def test_merkle_tree_root_and_inclusion_proofs():
    """Verify binary Merkle tree root calculation and mathematical inclusion proofs."""
    leaf_data = [sha256_hex(f"TX-{i}") for i in range(8)]
    tree = MerkleTree(leaf_data)

    assert len(tree.root) == 64

    # Verify inclusion proof for leaf 3
    proof = tree.get_inclusion_proof(3)
    assert len(proof) == 3  # log2(8) = 3
    assert MerkleTree.verify_inclusion_proof(leaf_data[3], proof, tree.root) is True

    # Tampered leaf hash must fail verification
    fake_leaf = sha256_hex("TAMPERED_TX_PAYLOAD")
    assert MerkleTree.verify_inclusion_proof(fake_leaf, proof, tree.root) is False


def test_crypto_ledger_hash_chain_and_rfc3161_bundle(tmp_path):
    """Verify immutable cryptographic hash chain and RFC-3161 audit bundle export."""
    db_file = tmp_path / "test_crypto_ledger.db"
    ledger = CryptographicAuditLedger(db_path=db_file)

    # Record chained events
    ev1 = ledger.record_chained_event(
        event_id="EVT-001",
        event_type="WATERMARK",
        sequence_hash=sha256_hex("SEQ_1"),
        sequence_length=100,
        classification="VERIFIED_LICENSED",
    )
    assert ev1["prev_hash"] == GENESIS_HASH
    assert len(ev1["event_hash"]) == 64

    ev2 = ledger.record_chained_event(
        event_id="EVT-002",
        event_type="FIREWALL_SCAN",
        sequence_hash=sha256_hex("SEQ_2"),
        sequence_length=200,
        classification="ROGUE_SYNTHETIC",
    )
    assert ev2["prev_hash"] == ev1["event_hash"]

    # Export RFC-3161 bundle
    bundle = ledger.export_rfc3161_bundle(limit=10)
    assert bundle["specification"] == "RFC-3161-BIOSECURITY-AUDIT-V3"
    assert bundle["total_transactions"] == 2
    assert len(bundle["merkle_root"]) == 64

    # Verify bundle
    verif = CryptographicAuditLedger.verify_rfc3161_bundle(bundle)
    assert verif["valid"] is True
    assert verif["total_verified_events"] == 2

    # Verify tampering detection
    bundle["transactions"][0]["event_hash"] = sha256_hex("TAMPERED_EVENT")
    tampered_verif = CryptographicAuditLedger.verify_rfc3161_bundle(bundle)
    assert tampered_verif["valid"] is False


# ---------------------------------------------------------------------------
# 4. Level 3 REST API Endpoints Tests
# ---------------------------------------------------------------------------
def test_api_v3_hardware_status_and_estop():
    """Verify Level 3 hardware status, emergency stop, and reset endpoints."""
    # Status
    status_resp = client.get("/api/v3/hardware/status")
    assert status_resp.status_code == 200
    st_data = status_resp.json()
    assert "valves" in st_data
    assert "chamber_pressure_bar" in st_data

    # E-STOP
    estop_resp = client.post("/api/v3/hardware/estop", json={"reason": "ROUTINE_EMERGENCY_DRILL"})
    assert estop_resp.status_code == 200
    assert estop_resp.json()["state"] == "INTERLOCK_HALT"

    # Reset
    reset_resp = client.post("/api/v3/hardware/reset", json={"authorization_key": "ADMIN-SECURITY-OVERRIDE"})
    assert reset_resp.status_code == 200
    assert reset_resp.json()["state"] == "LOCKED"


def test_api_v3_split_orders_screen():
    """Verify Level 3 distributed split-order screening endpoint."""
    orders = [
        {
            "order_id": "SPLIT-01",
            "sequence": "ATGCCATTTGTTAATAAACAATTTAATTATAAAGATCCTGTAAATGGTGTTGATATTGCTTATATAAAAATTCCAAATGCAGGTCAAATGCAACCAGTAAAAGCT",
            "customer_id": "RESEARCH-LAB-1",
        },
        {
            "order_id": "SPLIT-02",
            "sequence": "TGCAGGTCAAATGCAACCAGTAAAAGCTTTTAAAATTCATAATAAAATATGGGTAATTCCAGAAAGAGATACATTTACAAATCCTGAAGAAGGAGATTTAAA",
            "customer_id": "RESEARCH-LAB-2",
        },
    ]

    resp = client.post("/api/v3/split-orders/screen", json={"orders": orders, "min_overlap": 18})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_orders_analyzed"] == 2
    assert data["assembled_contigs_count"] >= 1
    assert data["threats_detected_count"] >= 1
    assert "Botulinum" in data["contigs"][0]["agent_name"]


def test_api_v3_merkle_bundle_export_and_verify():
    """Verify Level 3 RFC-3161 Merkle bundle export and verification endpoints."""
    # Export bundle
    bundle_resp = client.get("/api/v3/ledger/merkle-bundle")
    assert bundle_resp.status_code == 200
    bundle = bundle_resp.json()
    assert "merkle_root" in bundle
    assert "transactions" in bundle

    # Verify bundle
    verify_resp = client.post("/api/v3/ledger/verify-bundle", json=bundle)
    assert verify_resp.status_code == 200
    verify_data = verify_resp.json()
    assert verify_data["valid"] is True
    assert verify_data["regulatory_status"] == "COMPLIANT_VERIFIED"
