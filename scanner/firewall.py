"""GeneSign Biosecurity Firewall & Origin Provenance Threat Radar.

Performs real-time FASTA/FastQ stream ingestion, select agent pathogen screening,
cryptographic watermark extraction, multi-tenant KMS verification, and multi-state compliance classification:
  - VERIFIED_LICENSED: Valid cryptographic signature & safe non-pathogenic target.
  - UNKNOWN_DRIFT: Unsigned benign sequence (natural/unwatermarked sequence).
  - ROGUE_SYNTHETIC: Unsigned or forged sequence matching regulated pathogen/toxin profiles.
  - TAMPERED_PAYLOAD: Watermark detected but cryptographic checksum or sequence hash mismatch.
"""

from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, Iterator, List, Optional, Tuple, Any

from cryptography.hazmat.primitives.asymmetric import ed25519

from engine.watermark import extract_watermark, translate_dna, clean_sequence, ExtractionResult
from engine.threat_detector import threat_detector, ScalableThreatDetector
from engine.kms import kms_service
from security.signer import ProvenanceSigner, calculate_sequence_hash


class ComplianceClassification(str, Enum):
    """Biosecurity firewall classification states."""
    VERIFIED_LICENSED = "VERIFIED_LICENSED"
    UNKNOWN_DRIFT = "UNKNOWN_DRIFT"
    ROGUE_SYNTHETIC = "ROGUE_SYNTHETIC"
    TAMPERED_PAYLOAD = "TAMPERED_PAYLOAD"


@dataclass
class SequenceRecord:
    """Parsed sequence entity from FASTA or FastQ source."""
    record_id: str
    description: str
    sequence: str
    quality_scores: Optional[str] = None
    format_type: str = "FASTA"


@dataclass
class ScanEvaluation:
    """Detailed result of firewall evaluation on a single sequence."""
    record_id: str
    classification: ComplianceClassification
    threat_detected: bool
    watermark_detected: bool
    payload_valid: bool
    tampered: bool
    lab_id: Optional[str]
    order_id: Optional[str]
    sequence_hash: str
    threat_matches: List[Dict[str, Any]]
    extraction_details: Optional[Dict[str, Any]]
    status_summary: str
    provenance_verified: bool
    chimeric_detected: bool = False
    highest_threat_tier: str = "NONE"


class SequenceParser:
    """High-throughput FASTA and FastQ stream parser."""

    @staticmethod
    def parse_stream(raw_text: str) -> Iterator[SequenceRecord]:
        """Parses multiline string containing FASTA or FastQ records."""
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if not lines:
            return

        # Detect FastQ by first char '@' and recurring 4-line blocks
        first_line = lines[0]
        if first_line.startswith("@") and len(lines) >= 4 and lines[2].startswith("+"):
            # FastQ format
            i = 0
            while i < len(lines):
                if lines[i].startswith("@") and i + 3 < len(lines) and lines[i+2].startswith("+"):
                    header = lines[i][1:]
                    parts = header.split(maxsplit=1)
                    rec_id = parts[0]
                    desc = parts[1] if len(parts) > 1 else ""
                    seq = lines[i+1].upper()
                    qual = lines[i+3]
                    yield SequenceRecord(
                        record_id=rec_id,
                        description=desc,
                        sequence=seq,
                        quality_scores=qual,
                        format_type="FASTQ",
                    )
                    i += 4
                else:
                    i += 1
            return

        # FASTA format parser
        current_id = "SEQ-1"
        current_desc = ""
        current_seq_parts: List[str] = []

        for line in lines:
            if line.startswith(">"):
                if current_seq_parts:
                    yield SequenceRecord(
                        record_id=current_id,
                        description=current_desc,
                        sequence="".join(current_seq_parts).upper(),
                        format_type="FASTA",
                    )
                    current_seq_parts = []
                header = line[1:].strip()
                parts = header.split(maxsplit=1)
                current_id = parts[0] if parts else "SEQ-UNKNOWN"
                current_desc = parts[1] if len(parts) > 1 else ""
            else:
                current_seq_parts.append(line)

        if current_seq_parts:
            yield SequenceRecord(
                record_id=current_id,
                description=current_desc,
                sequence="".join(current_seq_parts).upper(),
                format_type="FASTA",
            )


class BiosecurityFirewall:
    """Production Biosecurity Firewall & Provenance Radar."""

    def __init__(
        self,
        trusted_lab_keys: Optional[Dict[str, ed25519.Ed25519PublicKey]] = None,
        kmer_size: int = 17,
    ):
        self.detector = threat_detector
        self.kms = kms_service
        self.trusted_lab_keys = trusted_lab_keys or {}

    def register_lab_public_key(self, lab_id: str, public_key: ed25519.Ed25519PublicKey) -> None:
        """Registers a licensed synthesis laboratory public key."""
        self.trusted_lab_keys[lab_id] = public_key

    def scan_sequence(
        self,
        sequence: str,
        record_id: str = "QUERY-SEQ",
        provenance_token: Optional[Dict[str, Any]] = None,
    ) -> ScanEvaluation:
        """Evaluates a DNA sequence against biosecurity pathogen database and watermark provenance."""
        clean_dna = clean_sequence(sequence)
        seq_hash = calculate_sequence_hash(clean_dna)

        # 1. Advanced Threat & Alignment Scan (Sliding-window canonical k-mers)
        threat_scan = self.detector.scan_sequence(clean_dna)
        threat_detected = threat_scan["threat_detected"]
        chimeric_detected = threat_scan.get("chimeric_detected", False)
        highest_tier = threat_scan.get("highest_tier", "NONE")
        threat_hits = threat_scan["hits"]

        # 2. Template-free Watermark Extraction
        ext_result: ExtractionResult = extract_watermark(clean_dna)

        # 3. Provenance Token Check via KMS and/or local trusted keys
        token_verified = False
        token_crl_revoked = False
        token_error = None

        if provenance_token:
            # Check KMS multi-tenant registry first
            kms_check = self.kms.verify_provenance(provenance_token, clean_dna)
            if kms_check.get("valid"):
                token_verified = True
            elif kms_check.get("crl_revoked"):
                token_crl_revoked = True
                token_error = kms_check.get("error")
            else:
                # Fallback to local trusted keys
                lab_id_token = provenance_token.get("claims", {}).get("lab_id") or provenance_token.get("claims", {}).get("provider_id")
                pub_key = self.trusted_lab_keys.get(lab_id_token)
                if pub_key:
                    local_check = ProvenanceSigner.verify_provenance_token(provenance_token, clean_dna, pub_key)
                    token_verified = local_check.get("valid", False)
                    if not token_verified:
                        token_error = local_check.get("error")

        # Multi-state decision matrix
        classification: ComplianceClassification
        status_summary: str

        if token_crl_revoked:
            classification = ComplianceClassification.TAMPERED_PAYLOAD
            status_summary = (
                f"SECURITY VIOLATION: Provenance token uses a REVOKED cryptographic key! ({token_error})"
            )
        elif provenance_token and not token_verified:
            classification = ComplianceClassification.TAMPERED_PAYLOAD
            status_summary = (
                "TAMPER INTERLOCK TRIPPED: Cryptographic Provenance Token verification failed. "
                "Sequence SHA-256 hash or Ed25519 signature mismatch detected."
            )
        elif ext_result.tampered:
            # Watermark magic was detected, but CRC failed or stream corrupted
            classification = ComplianceClassification.TAMPERED_PAYLOAD
            status_summary = (
                f"TAMPER INTERLOCK TRIPPED: Steganographic payload CRC corrupted. "
                f"Single-nucleotide mutation or synthetic modification detected. ({ext_result.error_message})"
            )
        elif threat_detected:
            # Pathogen threat found
            if ext_result.extracted or token_verified:
                # Sequence has valid watermark
                classification = ComplianceClassification.VERIFIED_LICENSED
                agent_name = threat_hits[0]['agent_name'] if threat_hits else "Regulated Agent"
                status_summary = (
                    f"AUTHORIZED LICENSED SYNTHESIS: Sequence matches regulated pathogen signature "
                    f"({agent_name}), but contains verified provenance credentials."
                )
            else:
                classification = ComplianceClassification.ROGUE_SYNTHETIC
                agent_name = threat_hits[0]['agent_name'] if threat_hits else "Regulated Agent"
                target_gene = threat_hits[0]['target_gene'] if threat_hits else ""
                ins_type = threat_hits[0].get('insertion_type', 'MATCH')
                status_summary = (
                    f"CRITICAL BIOSECURITY VIOLATION: Unsigned synthetic sequence matching "
                    f"{highest_tier} ({agent_name} - {target_gene} [{ins_type}])!"
                )
                if chimeric_detected:
                    status_summary += " [ALERT: Chimeric construct spanning multiple agent families detected!]"
        else:
            # No pathogen threat found
            if ext_result.extracted or token_verified:
                classification = ComplianceClassification.VERIFIED_LICENSED
                status_summary = (
                    "PROVENANCE VERIFIED: Valid cryptographic DNA watermark detected from licensed synthesis provider."
                )
            else:
                classification = ComplianceClassification.UNKNOWN_DRIFT
                status_summary = (
                    "UNWATERMARKED BENIGN: Sequence does not contain GeneSign provenance token, "
                    "but passes pathogen screen as non-hazardous genetic material."
                )

        payload_dict = ext_result.payload if ext_result.extracted else None
        lab_id = payload_dict.get("lab_id") if payload_dict else None
        order_id = payload_dict.get("order_id") if payload_dict else None

        if provenance_token and not lab_id:
            lab_id = provenance_token.get("claims", {}).get("provider_id") or provenance_token.get("claims", {}).get("lab_id")
            order_id = provenance_token.get("claims", {}).get("order_id")

        return ScanEvaluation(
            record_id=record_id,
            classification=classification,
            threat_detected=threat_detected,
            watermark_detected=ext_result.extracted or ext_result.valid_sync,
            payload_valid=ext_result.extracted,
            tampered=ext_result.tampered or token_crl_revoked,
            lab_id=lab_id,
            order_id=order_id,
            sequence_hash=seq_hash,
            threat_matches=threat_hits,
            extraction_details=asdict(ext_result) if ext_result else None,
            status_summary=status_summary,
            provenance_verified=(classification == ComplianceClassification.VERIFIED_LICENSED),
            chimeric_detected=chimeric_detected,
            highest_threat_tier=highest_tier,
        )

    def scan_batch(self, raw_input: str) -> List[ScanEvaluation]:
        """Scans a batch of sequences in FASTA/FastQ format."""
        results = []
        for record in SequenceParser.parse_stream(raw_input):
            eval_res = self.scan_sequence(
                sequence=record.sequence,
                record_id=record.record_id,
            )
            results.append(eval_res)
        return results
