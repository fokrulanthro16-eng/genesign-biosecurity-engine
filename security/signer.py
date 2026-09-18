"""GeneSign Cryptographic Provenance & Key Management Module.

Provides dual-layer cryptographic signing (SHA-256 digest + Ed25519 asymmetric
signature) for licensed synthetic DNA synthesis providers, generating tamper-evident
Provenance Tokens and enforcing single-nucleotide tamper interlocks.
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class LabKeyManager:
    """Manages Ed25519 cryptographic keypairs for DNA synthesis laboratories."""

    @staticmethod
    def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generates a new Ed25519 keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def get_fingerprint(public_key: ed25519.Ed25519PublicKey) -> str:
        """Computes SHA-256 fingerprint of the Ed25519 public key in hex."""
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw_bytes).hexdigest()[:16]

    @staticmethod
    def save_keys(
        private_key: ed25519.Ed25519PrivateKey,
        private_path: Path,
        public_path: Path,
    ) -> None:
        """Saves private and public keys to PEM format."""
        private_path.parent.mkdir(parents=True, exist_ok=True)
        public_path.parent.mkdir(parents=True, exist_ok=True)

        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_path.write_bytes(priv_bytes)
        public_path.write_bytes(pub_bytes)

    @staticmethod
    def load_private_key(path: Path) -> ed25519.Ed25519PrivateKey:
        """Loads Ed25519 private key from PEM file."""
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError(f"Key at {path} is not an Ed25519 private key.")
        return key

    @staticmethod
    def load_public_key(path: Path) -> ed25519.Ed25519PublicKey:
        """Loads Ed25519 public key from PEM file."""
        data = path.read_bytes()
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, ed25519.Ed25519PublicKey):
            raise ValueError(f"Key at {path} is not an Ed25519 public key.")
        return key


def calculate_sequence_hash(dna_seq: str) -> str:
    """Calculates canonical SHA-256 digest of clean DNA sequence."""
    clean = "".join(dna_seq.strip().upper().split())
    return hashlib.sha256(clean.encode("utf-8")).hexdigest()


class ProvenanceSigner:
    """Generates and verifies cryptographic provenance tokens for watermarked DNA."""

    def __init__(
        self,
        lab_id: str,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        public_key: Optional[ed25519.Ed25519PublicKey] = None,
    ):
        self.lab_id = lab_id
        self.private_key = private_key
        if private_key is not None and public_key is None:
            self.public_key = private_key.public_key()
        else:
            self.public_key = public_key

        self.key_fingerprint = (
            LabKeyManager.get_fingerprint(self.public_key)
            if self.public_key is not None
            else "UNKNOWN"
        )

    def create_provenance_token(
        self,
        dna_seq: str,
        order_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Creates an authenticated provenance token binding DNA hash and lab credentials."""
        if self.private_key is None:
            raise ValueError("Cannot sign provenance token: private key is not configured.")

        seq_hash = calculate_sequence_hash(dna_seq)
        now_utc = datetime.now(timezone.utc).isoformat()
        token_id = f"GS-PROOF-{uuid.uuid4().hex[:12].upper()}"

        claims = {
            "token_id": token_id,
            "lab_id": self.lab_id,
            "order_id": order_id,
            "sequence_hash": seq_hash,
            "key_fingerprint": self.key_fingerprint,
            "sequence_length_nt": len("".join(dna_seq.strip().upper().split())),
            "timestamp": now_utc,
            "compliance_standard": "ISO/TC-276-BIOSECURITY-V2",
            "regulatory_status": "CERTIFIED_COMMERCIAL_SYNTHESIS",
            "custom_metadata": metadata or {},
        }

        # Canonical canonical string for asymmetric signature
        canonical_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature_bytes = self.private_key.sign(canonical_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

        return {
            "token_header": {
                "algorithm": "Ed25519",
                "digest": "SHA-256",
                "format": "GeneSign-Provenance-v1",
            },
            "claims": claims,
            "signature": signature_b64,
        }

    @staticmethod
    def verify_provenance_token(
        token: Dict[str, Any],
        dna_seq: str,
        public_key: ed25519.Ed25519PublicKey,
    ) -> Dict[str, Any]:
        """Verifies provenance token validity, sequence hash integrity, and cryptographic signature."""
        claims = token.get("claims", {})
        sig_b64 = token.get("signature", "")
        if not claims or not sig_b64:
            return {
                "valid": False,
                "error": "Malformed provenance token structure.",
                "hash_match": False,
                "signature_valid": False,
            }

        # 1. Verify sequence hash match (Tamper Interlock)
        computed_hash = calculate_sequence_hash(dna_seq)
        expected_hash = claims.get("sequence_hash", "")
        hash_match = (computed_hash == expected_hash)

        # 2. Verify asymmetric Ed25519 signature
        canonical_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            signature_bytes = base64.b64decode(sig_b64)
            public_key.verify(signature_bytes, canonical_bytes)
            signature_valid = True
        except (InvalidSignature, Exception):
            signature_valid = False

        is_valid = hash_match and signature_valid

        return {
            "valid": is_valid,
            "hash_match": hash_match,
            "signature_valid": signature_valid,
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "claims": claims,
            "error": None if is_valid else (
                "Sequence SHA-256 mismatch (tampered nucleotides)" if not hash_match else "Ed25519 signature invalid"
            ),
        }
