"""GeneSign Multi-Tenant Key Management Service (KMS) & Trust Registry.

Manages asymmetric Ed25519 cryptographic keys for multi-tenant commercial DNA synthesis
providers (e.g., Twist Bioscience, Ginkgo Bioworks, IDT, Custom Foundries).
Enforces Key Revocation Lists (CRLs), provider key versioning, and tamper-evident
multi-tenant provenance signing and verification.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


DEFAULT_KMS_DIR = Path(__file__).resolve().parent.parent / "keys"


class ProviderKey:
    """Individual cryptographic key version for a DNA synthesis provider."""

    def __init__(
        self,
        version: str,
        public_key: ed25519.Ed25519PublicKey,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        created_at: Optional[str] = None,
        revoked: bool = False,
        revocation_reason: Optional[str] = None,
        revoked_at: Optional[str] = None,
    ):
        self.version = version
        self.public_key = public_key
        self.private_key = private_key
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.revoked = revoked
        self.revocation_reason = revocation_reason
        self.revoked_at = revoked_at

    @property
    def fingerprint(self) -> str:
        """Computes SHA-256 fingerprint of the Ed25519 public key."""
        raw_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw_bytes).hexdigest()[:16]

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        """Serializes key metadata."""
        data = {
            "version": self.version,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
            "revoked": self.revoked,
            "revocation_reason": self.revocation_reason,
            "revoked_at": self.revoked_at,
            "has_private_key": self.private_key is not None,
        }
        return data


class SynthesisProvider:
    """Licensed DNA synthesis provider tenant."""

    def __init__(
        self,
        provider_id: str,
        name: str,
        jurisdiction: str = "US",
        status: str = "ACTIVE",
    ):
        self.provider_id = provider_id
        self.name = name
        self.jurisdiction = jurisdiction
        self.status = status  # ACTIVE, SUSPENDED, REVOKED
        self.keys: Dict[str, ProviderKey] = {}
        self.active_key_version: str = "v1"

    def add_key(self, key: ProviderKey, set_active: bool = True) -> None:
        """Registers a key version for the provider."""
        self.keys[key.version] = key
        if set_active:
            self.active_key_version = key.version

    def get_active_key(self) -> Optional[ProviderKey]:
        """Returns the current active key for signing/verification."""
        return self.keys.get(self.active_key_version)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes provider profile."""
        active_key = self.get_active_key()
        return {
            "provider_id": self.provider_id,
            "name": self.name,
            "jurisdiction": self.jurisdiction,
            "status": self.status,
            "active_key_version": self.active_key_version,
            "active_fingerprint": active_key.fingerprint if active_key else None,
            "total_keys": len(self.keys),
            "keys": [k.to_dict() for k in self.keys.values()],
        }


class KeyManagementService:
    """Multi-tenant Enterprise Key Management Service and Trust Registry."""

    def __init__(self, kms_dir: Optional[Path] = None):
        target_dir = kms_dir or DEFAULT_KMS_DIR
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            self.kms_dir = target_dir
        except (OSError, PermissionError):
            tmp_kms = Path("/tmp/genesign_keys")
            try:
                tmp_kms.mkdir(parents=True, exist_ok=True)
                self.kms_dir = tmp_kms
            except (OSError, PermissionError):
                self.kms_dir = target_dir
        self.providers: Dict[str, SynthesisProvider] = {}
        self.crl: List[Dict[str, Any]] = []  # Key Revocation List
        self._init_default_providers()

    def _init_default_providers(self) -> None:
        """Bootstraps default licensed commercial synthesis providers."""
        default_tenants = [
            ("TWIST", "Twist Bioscience Enterprise", "US-CA"),
            ("GINKGO", "Ginkgo Bioworks Foundry", "US-MA"),
            ("IDT", "Integrated DNA Technologies", "US-IA"),
            ("TWS", "Twist Synthesis Quick-ID", "US-CA"),
            ("LAB-CUSTOM", "Verified Biosecurity Foundry", "EU-DE"),
        ]

        for pid, name, juris in default_tenants:
            provider = SynthesisProvider(provider_id=pid, name=name, jurisdiction=juris)
            
            # Check if key file exists on disk, otherwise generate
            priv_file = self.kms_dir / f"{pid.lower()}_v1_private.pem"
            pub_file = self.kms_dir / f"{pid.lower()}_v1_public.pem"

            if priv_file.exists() and pub_file.exists():
                priv = serialization.load_pem_private_key(priv_file.read_bytes(), password=None)
                pub = serialization.load_pem_public_key(pub_file.read_bytes())
            else:
                priv = ed25519.Ed25519PrivateKey.generate()
                pub = priv.public_key()
                # Persist if filesystem is writable
                priv_bytes = priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pub_bytes = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                try:
                    priv_file.write_bytes(priv_bytes)
                    pub_file.write_bytes(pub_bytes)
                except (OSError, PermissionError):
                    pass

            pkey = ProviderKey(version="v1", public_key=pub, private_key=priv)
            provider.add_key(pkey, set_active=True)
            self.providers[pid] = provider

    def register_provider(
        self,
        provider_id: str,
        name: str,
        jurisdiction: str = "US",
    ) -> SynthesisProvider:
        """Registers a new synthesis provider tenant with an initial v1 Ed25519 keypair."""
        pid = provider_id.strip().upper()
        if pid in self.providers:
            return self.providers[pid]

        provider = SynthesisProvider(provider_id=pid, name=name, jurisdiction=jurisdiction)
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_file = self.kms_dir / f"{pid.lower()}_v1_private.pem"
        pub_file = self.kms_dir / f"{pid.lower()}_v1_public.pem"
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        try:
            priv_file.write_bytes(priv_bytes)
            pub_file.write_bytes(pub_bytes)
        except (OSError, PermissionError):
            pass

        pkey = ProviderKey(version="v1", public_key=pub, private_key=priv)
        provider.add_key(pkey, set_active=True)
        self.providers[pid] = provider
        return provider

    def rotate_provider_key(self, provider_id: str) -> ProviderKey:
        """Rotates keypair for a provider to the next version (e.g. v1 -> v2)."""
        pid = provider_id.strip().upper()
        provider = self.providers.get(pid)
        if not provider:
            raise KeyError(f"Synthesis provider '{pid}' not found in registry.")

        next_ver = f"v{len(provider.keys) + 1}"
        priv = ed25519.Ed25519PrivateKey.generate()
        pub = priv.public_key()

        priv_file = self.kms_dir / f"{pid.lower()}_{next_ver}_private.pem"
        pub_file = self.kms_dir / f"{pid.lower()}_{next_ver}_public.pem"
        try:
            priv_file.write_bytes(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
            pub_file.write_bytes(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
        except (OSError, PermissionError):
            pass

        new_pkey = ProviderKey(version=next_ver, public_key=pub, private_key=priv)
        provider.add_key(new_pkey, set_active=True)
        return new_pkey

    def revoke_key(
        self,
        provider_id: str,
        key_version: str,
        reason: str = "ROUTINE_SECURITY_RETIREMENT",
    ) -> Dict[str, Any]:
        """Revokes a key and appends it to the Key Revocation List (CRL)."""
        pid = provider_id.strip().upper()
        provider = self.providers.get(pid)
        if not provider:
            raise KeyError(f"Synthesis provider '{pid}' not found in registry.")

        key = provider.keys.get(key_version)
        if not key:
            raise KeyError(f"Key version '{key_version}' not found for provider '{pid}'.")

        key.revoked = True
        key.revocation_reason = reason
        key.revoked_at = datetime.now(timezone.utc).isoformat()

        crl_entry = {
            "provider_id": pid,
            "key_version": key_version,
            "fingerprint": key.fingerprint,
            "reason": reason,
            "revoked_at": key.revoked_at,
        }
        self.crl.append(crl_entry)
        return crl_entry

    def sign_provenance(
        self,
        provider_id: str,
        dna_seq: str,
        order_id: str,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Signs sequence with active tenant key, embedding Provider ID + Key Version."""
        pid = provider_id.strip().upper()
        provider = self.providers.get(pid)
        if not provider:
            raise KeyError(f"Synthesis provider '{pid}' not found in registry.")

        if provider.status != "ACTIVE":
            raise ValueError(f"Provider '{pid}' is currently {provider.status}.")

        active_key = provider.get_active_key()
        if not active_key or not active_key.private_key:
            raise ValueError(f"Provider '{pid}' has no active private signing key.")

        if active_key.revoked:
            raise ValueError(f"Cannot sign with revoked key '{active_key.version}' (Reason: {active_key.revocation_reason}).")

        clean_seq = "".join(dna_seq.strip().upper().split())
        seq_hash = hashlib.sha256(clean_seq.encode("utf-8")).hexdigest()
        now_utc = datetime.now(timezone.utc).isoformat()
        token_id = f"GS-PROOF-{pid}-{now_utc[:10].replace('-', '')}-{hashlib.md5(now_utc.encode()).hexdigest()[:6].upper()}"

        claims = {
            "token_id": token_id,
            "provider_id": pid,
            "provider_name": provider.name,
            "key_version": active_key.version,
            "key_fingerprint": active_key.fingerprint,
            "order_id": order_id,
            "sequence_hash": seq_hash,
            "sequence_length_nt": len(clean_seq),
            "timestamp": now_utc,
            "compliance_standard": "ISO/TC-276-BIOSECURITY-V2",
            "regulatory_status": "CERTIFIED_COMMERCIAL_SYNTHESIS",
            "custom_metadata": custom_metadata or {},
        }

        canonical_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        signature_bytes = active_key.private_key.sign(canonical_bytes)
        sig_b64 = base64.b64encode(signature_bytes).decode("ascii")

        return {
            "token_header": {
                "format": "GeneSign-Provenance-v2",
                "algorithm": "Ed25519",
                "digest": "SHA-256",
                "provider_id": pid,
                "key_version": active_key.version,
                "key_fingerprint": active_key.fingerprint,
            },
            "claims": claims,
            "signature": sig_b64,
        }

    def verify_provenance(
        self,
        token: Dict[str, Any],
        dna_seq: str,
    ) -> Dict[str, Any]:
        """Verifies multi-tenant token validity, CRL compliance, sequence digest, and signature."""
        header = token.get("token_header", {})
        claims = token.get("claims", {})
        sig_b64 = token.get("signature", "")

        pid = header.get("provider_id") or claims.get("provider_id") or claims.get("lab_id")
        key_ver = header.get("key_version") or claims.get("key_version", "v1")

        if not pid or not sig_b64:
            return {
                "valid": False,
                "error": "Malformed token: missing provider ID or cryptographic signature.",
                "hash_match": False,
                "signature_valid": False,
                "crl_revoked": False,
            }

        provider = self.providers.get(pid.upper())
        if not provider:
            return {
                "valid": False,
                "error": f"Unknown or unregistered synthesis provider '{pid}'.",
                "hash_match": False,
                "signature_valid": False,
                "crl_revoked": False,
            }

        key = provider.keys.get(key_ver)
        if not key:
            return {
                "valid": False,
                "error": f"Key version '{key_ver}' not found for provider '{pid}'.",
                "hash_match": False,
                "signature_valid": False,
                "crl_revoked": False,
            }

        # 1. Key Revocation List (CRL) Check
        if key.revoked:
            return {
                "valid": False,
                "error": f"KEY_REVOKED_CRL_VIOLATION: Key {key_ver} was revoked on {key.revoked_at} (Reason: {key.revocation_reason}).",
                "hash_match": False,
                "signature_valid": False,
                "crl_revoked": True,
            }

        # 2. Sequence SHA-256 Hash Integrity (Tamper Interlock)
        clean_seq = "".join(dna_seq.strip().upper().split())
        computed_hash = hashlib.sha256(clean_seq.encode("utf-8")).hexdigest()
        expected_hash = claims.get("sequence_hash", "")
        hash_match = (computed_hash == expected_hash)

        # 3. Asymmetric Ed25519 Signature Verification
        canonical_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        try:
            sig_bytes = base64.b64decode(sig_b64)
            key.public_key.verify(sig_bytes, canonical_bytes)
            sig_valid = True
        except (InvalidSignature, Exception):
            sig_valid = False

        is_valid = hash_match and sig_valid

        return {
            "valid": is_valid,
            "provider_id": pid,
            "provider_name": provider.name,
            "key_version": key_ver,
            "key_fingerprint": key.fingerprint,
            "hash_match": hash_match,
            "signature_valid": sig_valid,
            "crl_revoked": False,
            "computed_hash": computed_hash,
            "expected_hash": expected_hash,
            "claims": claims,
            "error": None if is_valid else (
                "Sequence SHA-256 mismatch (tampered nucleotides)" if not hash_match else "Ed25519 signature invalid"
            ),
        }

    def get_public_registry(self) -> List[Dict[str, Any]]:
        """Returns the serialized public trust registry."""
        return [p.to_dict() for p in self.providers.values()]

    def get_crl(self) -> List[Dict[str, Any]]:
        """Returns the active Key Revocation List."""
        return list(self.crl)


# Global singleton instance
kms_service = KeyManagementService()
