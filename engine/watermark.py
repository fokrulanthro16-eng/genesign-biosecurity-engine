"""GeneSign Core Steganography & Biological Invariants Engine.

Implements synonymous degenerate codon steganography in coding sequences (CDS),
ensuring 100% amino acid translation preservation, restriction site protection,
GC-content drift tolerance (< 2.5%, guaranteed zero-drift carrier pairs),
and template-free extraction.
"""

import math
import struct
import zlib
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any

from engine.constants import (
    CODON_TO_AA,
    AA_TO_CODONS,
    CARRIER_CODON_TO_BIT,
    CARRIER_CODON_PARTNER,
    RESTRICTION_SITES,
    MAGIC_SYNC_BITS,
    MAGIC_SYNC_BYTE,
    PROTOCOL_VERSION,
)


@dataclass
class BiologicalInvariants:
    """Quantitative biological invariant metrics."""
    original_length_nt: int
    watermarked_length_nt: int
    amino_acid_length: int
    translation_identical: bool
    missense_mutations: int
    nonsense_mutations: int
    original_gc: float
    watermarked_gc: float
    gc_drift: float
    gc_drift_tolerated: bool
    original_entropy: float
    watermarked_entropy: float
    entropy_drift: float
    original_restriction_sites: Dict[str, List[int]]
    watermarked_restriction_sites: Dict[str, List[int]]
    new_restriction_sites_introduced: List[str]
    restriction_guard_passed: bool
    all_invariants_passed: bool


@dataclass
class WatermarkResult:
    """Output of watermarking process."""
    success: bool
    original_dna: str
    watermarked_dna: str
    protein_translation: str
    payload: Dict[str, Any]
    raw_payload_bytes: bytes
    carrier_capacity_bits: int
    payload_bits_used: int
    modulated_codons_count: int
    codon_modulations: List[Dict[str, Any]]
    invariants: BiologicalInvariants
    error_message: Optional[str] = None


@dataclass
class ExtractionResult:
    """Output of template-free extraction."""
    extracted: bool
    tampered: bool
    valid_sync: bool
    valid_crc: bool
    protocol_version: Optional[int]
    mode: Optional[int]
    payload: Optional[Dict[str, Any]]
    extracted_seq_hash: Optional[str]
    error_message: Optional[str] = None


def clean_sequence(seq: str) -> str:
    """Standardizes DNA sequence to uppercase stripped string."""
    return "".join(seq.strip().upper().split())


def translate_dna(dna_seq: str) -> str:
    """Translates a coding DNA sequence (CDS) into an amino acid sequence."""
    clean_dna = clean_sequence(dna_seq)
    if len(clean_dna) % 3 != 0:
        raise ValueError(f"CDS sequence length ({len(clean_dna)}) is not a multiple of 3.")
    
    protein = []
    for i in range(0, len(clean_dna), 3):
        codon = clean_dna[i:i+3]
        aa = CODON_TO_AA.get(codon, "X")
        if aa == "X":
            raise ValueError(f"Invalid codon '{codon}' encountered at position {i}.")
        protein.append(aa)
    return "".join(protein)


def calculate_gc_content(dna_seq: str) -> float:
    """Calculates GC percentage of a DNA sequence."""
    clean_dna = clean_sequence(dna_seq)
    if not clean_dna:
        return 0.0
    gc_count = clean_dna.count("G") + clean_dna.count("C")
    return round((gc_count / len(clean_dna)) * 100.0, 3)


def calculate_shannon_entropy(dna_seq: str) -> float:
    """Calculates base Shannon sequence entropy (bits per base, max 2.0)."""
    clean_dna = clean_sequence(dna_seq)
    length = len(clean_dna)
    if length == 0:
        return 0.0
    
    entropy = 0.0
    for base in ("A", "C", "G", "T"):
        count = clean_dna.count(base)
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def scan_restriction_sites(dna_seq: str) -> Dict[str, List[int]]:
    """Scans DNA sequence for prohibited restriction enzyme recognition sites."""
    clean_dna = clean_sequence(dna_seq)
    hits: Dict[str, List[int]] = {}
    for enzyme, pattern in RESTRICTION_SITES.items():
        positions = []
        idx = clean_dna.find(pattern)
        while idx != -1:
            positions.append(idx)
            idx = clean_dna.find(pattern, idx + 1)
        if positions:
            hits[enzyme] = positions
    return hits


def calculate_carrier_capacity(dna_seq: str) -> Tuple[int, List[int]]:
    """Computes total zero-drift carrier bit capacity and codon indices."""
    clean_dna = clean_sequence(dna_seq)
    carrier_codon_indices = [
        i // 3
        for i in range(0, len(clean_dna), 3)
        if clean_dna[i : i + 3] in CARRIER_CODON_TO_BIT
    ]
    return len(carrier_codon_indices), carrier_codon_indices


def pack_payload(payload_dict: Dict[str, Any], capacity: int) -> Tuple[bytes, str]:
    """Packs payload dict into binary format and generates bit string.

    Mode 1 (Micro, capacity < 96 bits):
      [MAGIC: 1B (0xA5)] [MODE: 1B (0x01)] [LAB: 2B] [ORDER: 2B] [CRC16: 2B] = 8 bytes (64 bits)
    Mode 2 (Standard, capacity >= 96 bits):
      [MAGIC: 1B (0xA5)] [MODE: 1B (0x02)] [LAB: 3B] [ORDER: 3B] [KEY_FP: 2B] [CRC16: 2B] = 12 bytes (96 bits)
    """
    lab_id = str(payload_dict.get("lab_id", "UN"))
    order_id = str(payload_dict.get("order_id", "01"))
    key_fp = str(payload_dict.get("key_fp", "0000"))

    if capacity < 96:
        mode = 1
        lab_b = lab_id[:2].encode("utf-8").ljust(2, b" ")
        ord_b = order_id[:2].encode("utf-8").ljust(2, b" ")
        body = struct.pack("!B2s2s", mode, lab_b, ord_b)
        crc = zlib.crc32(body) & 0xFFFF
        blob = bytes([MAGIC_SYNC_BYTE]) + body + struct.pack("!H", crc)
    else:
        mode = 2
        lab_b = lab_id[:3].encode("utf-8").ljust(3, b" ")
        ord_b = order_id[:3].encode("utf-8").ljust(3, b" ")
        fp_bytes = key_fp[:4].encode("utf-8")[:2].ljust(2, b"0")
        body = struct.pack("!B3s3s2s", mode, lab_b, ord_b, fp_bytes)
        crc = zlib.crc32(body) & 0xFFFF
        blob = bytes([MAGIC_SYNC_BYTE]) + body + struct.pack("!H", crc)

    bitstream = "".join(f"{b:08b}" for b in blob)
    return blob, bitstream


def unpack_payload(bitstream: str) -> ExtractionResult:
    """Extracts and verifies payload from carrier bitstream."""
    magic_idx = bitstream.find(MAGIC_SYNC_BITS)
    if magic_idx == -1:
        return ExtractionResult(
            extracted=False,
            tampered=False,
            valid_sync=False,
            valid_crc=False,
            protocol_version=None,
            mode=None,
            payload=None,
            extracted_seq_hash=None,
            error_message="Magic sync preamble not found in carrier sequence."
        )

    stream = bitstream[magic_idx:]
    # Mode byte is at bits 8:16
    if len(stream) < 16:
        return ExtractionResult(
            extracted=False,
            tampered=True,
            valid_sync=True,
            valid_crc=False,
            protocol_version=None,
            mode=None,
            payload=None,
            extracted_seq_hash=None,
            error_message="Truncated carrier bitstream header."
        )

    mode = int(stream[8:16], 2)
    total_bits = 64 if mode == 1 else 96

    if len(stream) < total_bits:
        return ExtractionResult(
            extracted=False,
            tampered=True,
            valid_sync=True,
            valid_crc=False,
            protocol_version=PROTOCOL_VERSION,
            mode=mode,
            payload=None,
            extracted_seq_hash=None,
            error_message=f"Carrier stream too short: expected {total_bits} bits, found {len(stream)}."
        )

    raw_bytes = bytes(int(stream[i:i+8], 2) for i in range(0, total_bits, 8))
    # Check CRC16 over body (bytes 1 to -2)
    calc_crc = zlib.crc32(raw_bytes[1:-2]) & 0xFFFF
    ext_crc = struct.unpack("!H", raw_bytes[-2:])[0]

    if calc_crc != ext_crc:
        return ExtractionResult(
            extracted=False,
            tampered=True,
            valid_sync=True,
            valid_crc=False,
            protocol_version=PROTOCOL_VERSION,
            mode=mode,
            payload=None,
            extracted_seq_hash=None,
            error_message=f"CRC16 checksum mismatch (calc {hex(calc_crc)}, ext {hex(ext_crc)}): payload tampered."
        )

    if mode == 1:
        m, lab_raw, ord_raw = struct.unpack("!B2s2s", raw_bytes[1:-2])
        payload = {
            "lab_id": lab_raw.decode("utf-8", errors="ignore").strip(),
            "order_id": ord_raw.decode("utf-8", errors="ignore").strip(),
            "mode": "Micro-64bit",
        }
    else:
        m, lab_raw, ord_raw, fp_raw = struct.unpack("!B3s3s2s", raw_bytes[1:-2])
        payload = {
            "lab_id": lab_raw.decode("utf-8", errors="ignore").strip(),
            "order_id": ord_raw.decode("utf-8", errors="ignore").strip(),
            "key_fp": fp_raw.decode("utf-8", errors="ignore").strip(),
            "mode": "Standard-96bit",
        }

    return ExtractionResult(
        extracted=True,
        tampered=False,
        valid_sync=True,
        valid_crc=True,
        protocol_version=PROTOCOL_VERSION,
        mode=mode,
        payload=payload,
        extracted_seq_hash=None,
        error_message=None,
    )


def embed_watermark(
    dna_seq: str,
    payload_dict: Dict[str, Any],
    max_gc_drift: float = 2.5,
) -> WatermarkResult:
    """Embeds cryptographic watermark payload into CDS synonymous codons.

    Guarantees 100% translation preservation, zero GC drift via synonymous pairs,
    and restriction site guard.
    """
    clean_dna = clean_sequence(dna_seq)
    orig_protein = translate_dna(clean_dna)
    orig_gc = calculate_gc_content(clean_dna)
    orig_entropy = calculate_shannon_entropy(clean_dna)
    orig_sites = scan_restriction_sites(clean_dna)

    total_capacity, carrier_indices = calculate_carrier_capacity(clean_dna)
    if total_capacity < 64:
        raise ValueError(
            f"Sequence contains only {total_capacity} zero-drift carrier codons. Minimum required is 64."
        )

    raw_bytes, bitstream = pack_payload(payload_dict, total_capacity)
    payload_bits_needed = len(bitstream)

    codons = [clean_dna[i:i+3] for i in range(0, len(clean_dna), 3)]
    codon_modulations = []
    bit_idx = 0

    for c_i in carrier_indices:
        if bit_idx < payload_bits_needed:
            target_bit = bitstream[bit_idx]
            cur_codon = codons[c_i]
            cur_bit = CARRIER_CODON_TO_BIT[cur_codon]

            if cur_bit != target_bit:
                candidate_codon = CARRIER_CODON_PARTNER[cur_codon]

                # Check restriction site avoidance
                start_context = max(0, (c_i - 2) * 3)
                end_context = min(len(clean_dna), (c_i + 3) * 3)
                context_tentative = (
                    "".join(codons[start_context // 3 : c_i])
                    + candidate_codon
                    + "".join(codons[c_i + 1 : end_context // 3])
                )
                prospective_sites = scan_restriction_sites(context_tentative)
                orig_context_sites = scan_restriction_sites(clean_dna[start_context:end_context])

                new_site = any(
                    len(prospective_sites.get(enz, [])) > len(orig_context_sites.get(enz, []))
                    for enz in RESTRICTION_SITES
                )
                if not new_site:
                    codons[c_i] = candidate_codon
                    codon_modulations.append({
                        "codon_index": c_i,
                        "amino_acid": CODON_TO_AA[candidate_codon],
                        "original_codon": cur_codon,
                        "watermarked_codon": candidate_codon,
                        "bits_embedded": target_bit,
                        "wobble_mutation": f"{cur_codon} -> {candidate_codon}",
                    })
            bit_idx += 1

    watermarked_dna = "".join(codons)
    post_protein = translate_dna(watermarked_dna)
    post_gc = calculate_gc_content(watermarked_dna)
    post_entropy = calculate_shannon_entropy(watermarked_dna)
    post_sites = scan_restriction_sites(watermarked_dna)

    gc_drift = round(abs(post_gc - orig_gc), 3)
    entropy_drift = round(abs(post_entropy - orig_entropy), 4)

    new_sites = [
        enz for enz in RESTRICTION_SITES
        if len(post_sites.get(enz, [])) > len(orig_sites.get(enz, []))
    ]
    restriction_guard_passed = len(new_sites) == 0
    translation_identical = (post_protein == orig_protein)

    all_passed = (
        translation_identical
        and (gc_drift <= max_gc_drift)
        and restriction_guard_passed
    )

    invariants = BiologicalInvariants(
        original_length_nt=len(clean_dna),
        watermarked_length_nt=len(watermarked_dna),
        amino_acid_length=len(orig_protein),
        translation_identical=translation_identical,
        missense_mutations=0 if translation_identical else 1,
        nonsense_mutations=0,
        original_gc=orig_gc,
        watermarked_gc=post_gc,
        gc_drift=gc_drift,
        gc_drift_tolerated=(gc_drift <= max_gc_drift),
        original_entropy=orig_entropy,
        watermarked_entropy=post_entropy,
        entropy_drift=entropy_drift,
        original_restriction_sites=orig_sites,
        watermarked_restriction_sites=post_sites,
        new_restriction_sites_introduced=new_sites,
        restriction_guard_passed=restriction_guard_passed,
        all_invariants_passed=all_passed,
    )

    return WatermarkResult(
        success=all_passed,
        original_dna=clean_dna,
        watermarked_dna=watermarked_dna,
        protein_translation=post_protein,
        payload=payload_dict,
        raw_payload_bytes=raw_bytes,
        carrier_capacity_bits=total_capacity,
        payload_bits_used=min(bit_idx, payload_bits_needed),
        modulated_codons_count=len(codon_modulations),
        codon_modulations=codon_modulations,
        invariants=invariants,
        error_message=None if all_passed else "Biological invariants failed verification.",
    )


def extract_watermark(dna_seq: str) -> ExtractionResult:
    """Template-free payload extraction from raw DNA coding sequence."""
    clean_dna = clean_sequence(dna_seq)
    if len(clean_dna) % 3 != 0:
        return ExtractionResult(
            extracted=False,
            tampered=False,
            valid_sync=False,
            valid_crc=False,
            protocol_version=None,
            mode=None,
            payload=None,
            extracted_seq_hash=None,
            error_message="Sequence length is not a multiple of 3.",
        )

    # Collect carrier bits
    carrier_bits = [
        CARRIER_CODON_TO_BIT[clean_dna[i:i+3]]
        for i in range(0, len(clean_dna), 3)
        if clean_dna[i:i+3] in CARRIER_CODON_TO_BIT
    ]

    bitstream = "".join(carrier_bits)
    if not bitstream:
        return ExtractionResult(
            extracted=False,
            tampered=False,
            valid_sync=False,
            valid_crc=False,
            protocol_version=None,
            mode=None,
            payload=None,
            extracted_seq_hash=None,
            error_message="No synonymous carrier codons found in sequence.",
        )

    return unpack_payload(bitstream)
