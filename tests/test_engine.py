"""GeneSign Comprehensive Automated Test Suite.

Verifies:
1. Absolute amino acid translation preservation across standard proteins (GFP, Insulin, Spike).
2. Template-free payload extraction accuracy & single-base-flip tamper sensitivity.
3. Biological invariant preservation (GC drift < 2.5%, Shannon entropy stability, restriction site protection).
4. Biosecurity firewall multi-state classification (VERIFIED_LICENSED, UNKNOWN_DRIFT, ROGUE_SYNTHETIC, TAMPERED_PAYLOAD).
"""

from pathlib import Path
import pytest

from engine.watermark import (
    embed_watermark,
    extract_watermark,
    translate_dna,
    calculate_gc_content,
    calculate_shannon_entropy,
    scan_restriction_sites,
    clean_sequence,
)
from scanner.firewall import BiosecurityFirewall, ComplianceClassification, SequenceParser
from security.signer import LabKeyManager, ProvenanceSigner, calculate_sequence_hash
from storage.ledger import AuditLedger


SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


def load_sample_sequence(filename: str) -> str:
    path = SAMPLES_DIR / filename
    content = path.read_text(encoding="utf-8")
    records = list(SequenceParser.parse_stream(content))
    return records[0].sequence


# ---------------------------------------------------------------------------
# Test 1: Absolute Translation Preservation
# ---------------------------------------------------------------------------
def test_translation_preservation_gfp():
    """Verifies that watermarked GFP CDS translates to 100% identical amino acids."""
    dna = load_sample_sequence("gfp.fasta")
    orig_protein = translate_dna(dna)

    payload = {
        "lab_id": "TWS",
        "order_id": "901",
        "key_fp": "1122",
    }

    result = embed_watermark(dna, payload)
    assert result.success is True
    assert result.watermarked_dna != result.original_dna, "Watermark must modulate codons"

    post_protein = translate_dna(result.watermarked_dna)
    assert post_protein == orig_protein, "Translation must be 100% identical (0 missense/nonsense)"
    assert result.invariants.missense_mutations == 0
    assert result.invariants.nonsense_mutations == 0
    assert result.invariants.translation_identical is True


def test_translation_preservation_insulin():
    """Verifies translation preservation for human insulin CDS."""
    dna = load_sample_sequence("insulin.fasta")
    orig_protein = translate_dna(dna)

    payload = {
        "lab_id": "ID",
        "order_id": "01",
    }

    result = embed_watermark(dna, payload)
    assert result.success is True
    post_protein = translate_dna(result.watermarked_dna)
    assert post_protein == orig_protein


def test_translation_preservation_spike():
    """Verifies translation preservation for large Spike protein CDS."""
    dna = load_sample_sequence("spike_partial.fasta")
    orig_protein = translate_dna(dna)

    payload = {
        "lab_id": "GNK",
        "order_id": "012",
        "key_fp": "9988",
    }

    result = embed_watermark(dna, payload)
    assert result.success is True
    post_protein = translate_dna(result.watermarked_dna)
    assert post_protein == orig_protein


# ---------------------------------------------------------------------------
# Test 2: Extraction Accuracy and Bit-Flip Tamper Interlock
# ---------------------------------------------------------------------------
def test_payload_extraction_and_bit_flip_sensitivity():
    """Verifies template-free extraction and immediate tamper detection on 1-nt mutation."""
    dna = load_sample_sequence("gfp.fasta")
    payload = {
        "lab_id": "TWS",
        "order_id": "901",
        "key_fp": "1234",
    }

    wm_res = embed_watermark(dna, payload)
    assert wm_res.success is True

    # 1. Successful extraction without template
    ext = extract_watermark(wm_res.watermarked_dna)
    assert ext.extracted is True
    assert ext.tampered is False
    assert ext.valid_crc is True
    assert ext.payload["lab_id"] == "TWS"
    assert ext.payload["order_id"] == "901"

    # 2. Single Nucleotide Tamper Test: Mutate exactly 1 nucleotide at modulated codon
    mod_codon = wm_res.codon_modulations[0]
    pos_to_flip = mod_codon["codon_index"] * 3 + 2  # Wobble position

    mutated_list = list(wm_res.watermarked_dna)
    orig_base = mutated_list[pos_to_flip]
    alternate_base = "T" if orig_base != "T" else "A"
    mutated_list[pos_to_flip] = alternate_base
    tampered_dna = "".join(mutated_list)

    # 3. Verify tamper interlock triggers
    tamper_ext = extract_watermark(tampered_dna)
    assert (tamper_ext.extracted is False) or (tamper_ext.tampered is True) or (tamper_ext.valid_crc is False)


# ---------------------------------------------------------------------------
# Test 3: Biological Invariant Compliance (GC Drift, Entropy, Restriction)
# ---------------------------------------------------------------------------
def test_biological_invariants_compliance():
    """Verifies GC content drift < 2.5%, entropy preservation, and restriction site guard."""
    dna = load_sample_sequence("gfp.fasta")
    payload = {
        "lab_id": "TWS",
        "order_id": "901",
        "key_fp": "FEED",
    }

    wm_res = embed_watermark(dna, payload)
    inv = wm_res.invariants

    # GC Drift < 2.5% (Zero-drift guarantees 0.000%)
    assert inv.gc_drift <= 2.5, f"GC drift {inv.gc_drift}% exceeded 2.5% threshold"
    assert inv.gc_drift_tolerated is True

    # Entropy Stability
    assert abs(inv.entropy_drift) < 0.15, "Shannon entropy should remain stable"

    # Restriction Enzyme Guard
    assert inv.restriction_guard_passed is True
    assert len(inv.new_restriction_sites_introduced) == 0


# ---------------------------------------------------------------------------
# Test 4: Threat Classification Engine Outputs
# ---------------------------------------------------------------------------
def test_threat_classification_multi_state():
    """Tests all 4 biosecurity firewall classification states."""
    firewall = BiosecurityFirewall()

    # State A: UNKNOWN_DRIFT (Benign unwatermarked natural sequence)
    benign_dna = load_sample_sequence("insulin.fasta")
    eval_benign = firewall.scan_sequence(benign_dna, record_id="BENIGN-INS")
    assert eval_benign.classification == ComplianceClassification.UNKNOWN_DRIFT
    assert eval_benign.threat_detected is False

    # State B: ROGUE_SYNTHETIC (Unsigned Ebola VP35 sequence)
    ebola_dna = load_sample_sequence("ebola_vp35.fasta")
    eval_rogue = firewall.scan_sequence(ebola_dna, record_id="ROGUE-EBOLA")
    assert eval_rogue.classification == ComplianceClassification.ROGUE_SYNTHETIC
    assert eval_rogue.threat_detected is True
    assert eval_rogue.threat_matches[0]["agent_name"] == "Zaire Ebolavirus"

    # State C: VERIFIED_LICENSED (Watermarked GFP benign sequence)
    gfp_dna = load_sample_sequence("gfp.fasta")
    wm_res = embed_watermark(gfp_dna, {
        "lab_id": "TWS",
        "order_id": "901",
        "key_fp": "1122",
    })
    eval_licensed = firewall.scan_sequence(wm_res.watermarked_dna, record_id="LICENSED-GFP")
    assert eval_licensed.classification == ComplianceClassification.VERIFIED_LICENSED
    assert eval_licensed.threat_detected is False
    assert eval_licensed.payload_valid is True

    # State D: TAMPERED_PAYLOAD (Watermarked GFP mutated by 1 nucleotide inside payload body)
    tampered_gfp = list(wm_res.watermarked_dna)
    mod_codon = wm_res.codon_modulations[10]
    flip_idx = mod_codon["codon_index"] * 3 + 2
    tampered_gfp[flip_idx] = "T" if tampered_gfp[flip_idx] != "T" else "A"
    tampered_dna = "".join(tampered_gfp)

    eval_tampered = firewall.scan_sequence(tampered_dna, record_id="TAMPERED-GFP")
    assert eval_tampered.classification == ComplianceClassification.TAMPERED_PAYLOAD
    assert eval_tampered.tampered is True


# ---------------------------------------------------------------------------
# Test 5: Cryptographic Dual-Layer Signer Interlock
# ---------------------------------------------------------------------------
def test_cryptographic_signer_and_tamper_interlock():
    """Verifies Ed25519 asymmetric token generation and tamper detection."""
    priv_key, pub_key = LabKeyManager.generate_keypair()
    signer = ProvenanceSigner(lab_id="LAB-US-ED25519", private_key=priv_key)

    dna = load_sample_sequence("insulin.fasta")
    token = signer.create_provenance_token(dna, order_id="ORD-CRYPTO-1")

    # 1. Verify authentic token + sequence
    verify_ok = ProvenanceSigner.verify_provenance_token(token, dna, pub_key)
    assert verify_ok["valid"] is True
    assert verify_ok["hash_match"] is True
    assert verify_ok["signature_valid"] is True

    # 2. Mutate 1 nucleotide: sequence hash check fails
    first_base = dna[0]
    alternate_base = "C" if first_base != "C" else "T"
    mutated_dna = alternate_base + dna[1:]
    verify_tampered = ProvenanceSigner.verify_provenance_token(token, mutated_dna, pub_key)
    assert verify_tampered["valid"] is False
    assert verify_tampered["hash_match"] is False
