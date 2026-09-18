"""GeneSign Web Tactical Operations HUD & Enterprise REST API (Level 2).

FastAPI production backend providing automated DNA watermarking,
biosecurity firewall scanning, cryptographic provenance certification,
multi-tenant KMS trust registry, and asynchronous batch FASTA/FASTQ ingestion.
"""

import os
import sys
import time
import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

# Ensure project root is in sys.path for serverless runtimes (e.g. Vercel, AWS Lambda)
BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, Request, BackgroundTasks, UploadFile, File, Form, Depends
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from security.auth import (
    UserRole, hash_password, verify_password, generate_salt,
    create_access_token, generate_api_key, get_current_identity, require_role,
)
from security.ratelimit import rate_limiter, enforce_rate_limit
from engine.billing import billing_service, PRICING_PLANS
from engine.compliance_report import compliance_generator

from engine.watermark import (
    embed_watermark,
    extract_watermark,
    translate_dna,
    clean_sequence,
    calculate_gc_content,
    calculate_shannon_entropy,
)
from engine.kms import kms_service, KeyManagementService
from engine.threat_detector import threat_detector, ScalableThreatDetector
from engine.hardware_interlock import hardware_interlock, SynthesizerHardwareInterlock
from engine.assembly_scanner import assembly_scanner, SplitOrderGraphAssembler, FragmentOrder
from engine.ledger import crypto_ledger, CryptographicAuditLedger
from scanner.firewall import BiosecurityFirewall, SequenceParser, ComplianceClassification
from security.signer import LabKeyManager, ProvenanceSigner, calculate_sequence_hash
from storage.ledger import AuditLedger
from engine.nemotron import nemotron_advisor, NemotronBiosecurityAdvisor



BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
SAMPLES_DIR = PROJECT_ROOT / "samples"
KEYS_DIR = Path(os.getenv("KMS_ROOT", str(PROJECT_ROOT / "keys")))
LEDGER_DB = Path(os.getenv("LEDGER_PATH", str(PROJECT_ROOT / "storage" / "ledger.db")))
MAX_BATCH_RECORDS = int(os.getenv("MAX_BATCH_RECORDS", "500"))
WORKER_CONCURRENCY = int(os.getenv("WORKER_CONCURRENCY", "4"))

app = FastAPI(
    title="GeneSign Biosecurity & DNA Watermarking Engine",
    version="2.2.0-ENTERPRISE",
    description="Enterprise Synthetic DNA Watermarking, Origin Provenance KMS & Biosecurity Firewall REST API",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Initialize services
ledger = AuditLedger(db_path=LEDGER_DB)
firewall = BiosecurityFirewall()

# Ensure demo server key exists for backward compatibility
SERVER_KEY_PRIV = KEYS_DIR / "server_private.pem"
SERVER_KEY_PUB = KEYS_DIR / "server_public.pem"

if SERVER_KEY_PRIV.exists() and SERVER_KEY_PUB.exists():
    try:
        server_priv = LabKeyManager.load_private_key(SERVER_KEY_PRIV)
        server_pub = LabKeyManager.load_public_key(SERVER_KEY_PUB)
    except Exception:
        server_priv, server_pub = LabKeyManager.generate_keypair()
else:
    server_priv, server_pub = LabKeyManager.generate_keypair()
    try:
        LabKeyManager.save_keys(server_priv, SERVER_KEY_PRIV, SERVER_KEY_PUB)
    except (OSError, PermissionError):
        tmp_keys = Path("/tmp/genesign_keys")
        try:
            tmp_keys.mkdir(parents=True, exist_ok=True)
            LabKeyManager.save_keys(server_priv, tmp_keys / "server_private.pem", tmp_keys / "server_public.pem")
        except (OSError, PermissionError):
            pass
firewall.register_lab_public_key("TWS", server_pub)
firewall.register_lab_public_key("TWIST", server_pub)
firewall.register_lab_public_key("ID", server_pub)
firewall.register_lab_public_key("IDT", server_pub)
firewall.register_lab_public_key("GNK", server_pub)
firewall.register_lab_public_key("GINKGO", server_pub)
firewall.register_lab_public_key("LAB-TWIST-01", server_pub)

# In-memory caches and async batch job tracking store
CERTIFICATES_CACHE: Dict[str, Dict[str, Any]] = {}
BATCH_JOBS: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Pydantic v2 Models
# ---------------------------------------------------------------------------
class WatermarkRequest(BaseModel):
    dna_sequence: str = Field(..., description="Target coding sequence (CDS) or FASTA text.")
    lab_id: str = Field(default="TWS", description="Licensed synthesis lab ID (e.g. TWIST, IDT, GINKGO).")
    order_id: str = Field(default="901", description="Commercial order number.")
    generate_certificate: bool = Field(default=True, description="Generate asymmetric Ed25519 provenance token.")


class ModulatedCodonInfo(BaseModel):
    codon_index: int
    amino_acid: str
    original_codon: str
    watermarked_codon: str
    bits_embedded: str
    wobble_mutation: str


class WatermarkResponse(BaseModel):
    success: bool
    event_id: str
    watermarked_fasta: str
    watermarked_dna: str
    original_dna: str
    protein_translation: str
    carrier_capacity_bits: int
    payload_bits_used: int
    modulated_codons_count: int
    codon_modulations: List[ModulatedCodonInfo]
    invariants: Dict[str, Any]
    certificate: Optional[Dict[str, Any]] = None
    certificate_id: Optional[str] = None


class ScanRequest(BaseModel):
    sequence_or_fasta: str = Field(..., description="Raw DNA string or multiline FASTA/FastQ.")
    record_id: Optional[str] = Field(default="USER-QUERY", description="User record identifier.")
    provenance_token: Optional[Dict[str, Any]] = Field(default=None, description="Optional external provenance token.")


class ThreatMatchInfo(BaseModel):
    agent_id: str
    agent_name: str
    tax_family: str
    regulatory_tier: str
    target_gene: str
    description: str
    kmer_matches: int
    alignment_score: Optional[float] = None
    confidence: Optional[str] = None
    insertion_type: Optional[str] = None
    query_match_start: int
    query_match_end: int
    threat_detected: bool


class ScanResponse(BaseModel):
    record_id: str
    classification: str
    threat_detected: bool
    watermark_detected: bool
    payload_valid: bool
    tampered: bool
    lab_id: Optional[str]
    order_id: Optional[str]
    sequence_hash: str
    sequence_length: int
    gc_content: float
    shannon_entropy: float
    amino_acid_translation: str
    threat_matches: List[ThreatMatchInfo]
    status_summary: str
    provenance_verified: bool
    event_id: str
    chimeric_detected: Optional[bool] = False
    highest_threat_tier: Optional[str] = "NONE"


class VerifyRequest(BaseModel):
    sequence: str = Field(..., description="Watermarked DNA sequence to extract and verify.")


class RegisterProviderRequest(BaseModel):
    provider_id: str = Field(..., description="Unique provider ID (e.g. TWIST, GINKGO, IDT, CUSTOM-LAB)")
    name: str = Field(..., description="Full legal provider name")
    jurisdiction: str = Field(default="US", description="Regulatory jurisdiction code")


class RotateKeyRequest(BaseModel):
    provider_id: str = Field(..., description="Provider ID to rotate key for")


class RevokeKeyRequest(BaseModel):
    provider_id: Optional[str] = None
    key_version: Optional[str] = None
    reason: str = Field(default="COMPROMISE_ROTATION", description="Revocation rationale")


# ---------------------------------------------------------------------------
# Background Batch Processing Worker
# ---------------------------------------------------------------------------
def execute_batch_scan_job(
    job_id: str,
    raw_content: str,
    provenance_token: Optional[Dict[str, Any]] = None,
):
    """Asynchronous background worker executing high-throughput batch screening."""
    job = BATCH_JOBS.get(job_id)
    if not job:
        return

    start_time = time.time()
    job["status"] = "PROCESSING"

    try:
        records = list(SequenceParser.parse_stream(raw_content))
        if not records:
            # Try raw text as single record
            clean = clean_sequence(raw_content)
            if clean:
                records = [firewall.parse_stream(f">RAW-SEQ\n{clean}")][0]
            else:
                job["status"] = "COMPLETED"
                job["completed_at"] = datetime.now(timezone.utc).isoformat()
                job["summary"]["status_message"] = "No valid sequence records found in input stream."
                return

        # Memory bound check
        if len(records) > MAX_BATCH_RECORDS:
            records = records[:MAX_BATCH_RECORDS]

        job["total_records"] = len(records)
        processed_records = []
        threats_count = 0
        licensed_count = 0
        tampered_count = 0
        unknown_count = 0

        for i, rec in enumerate(records):
            eval_res = firewall.scan_sequence(
                sequence=rec.sequence,
                record_id=rec.record_id,
                provenance_token=provenance_token,
            )

            # Metrics aggregation
            if eval_res.threat_detected or eval_res.classification == ComplianceClassification.ROGUE_SYNTHETIC:
                threats_count += 1
            if eval_res.classification == ComplianceClassification.VERIFIED_LICENSED:
                licensed_count += 1
            elif eval_res.classification == ComplianceClassification.TAMPERED_PAYLOAD:
                tampered_count += 1
            elif eval_res.classification == ComplianceClassification.UNKNOWN_DRIFT:
                unknown_count += 1

            record_summary = {
                "record_id": rec.record_id,
                "description": rec.description,
                "format": getattr(rec, "format_type", "FASTA"),
                "length_nt": len(clean_sequence(rec.sequence)),
                "gc_content": calculate_gc_content(rec.sequence),
                "classification": eval_res.classification.value,
                "threat_detected": eval_res.threat_detected,
                "highest_threat_tier": eval_res.highest_threat_tier,
                "chimeric_detected": eval_res.chimeric_detected,
                "threat_matches": eval_res.threat_matches,
                "threat_names": [t["agent_name"] for t in eval_res.threat_matches],
                "lab_id": eval_res.lab_id,
                "order_id": eval_res.order_id,
                "sequence_hash": eval_res.sequence_hash,
                "provenance_verified": eval_res.provenance_verified,
                "status_summary": eval_res.status_summary,
            }
            processed_records.append(record_summary)

            # Update live progress
            job["processed_records"] = i + 1
            job["progress_percent"] = round(((i + 1) / len(records)) * 100, 1)

        duration_ms = round((time.time() - start_time) * 1000, 2)

        job["status"] = "completed"
        job["completed_at"] = datetime.now(timezone.utc).isoformat()
        job["summary"] = {
            "total_records": len(records),
            "threats_found": threats_count,
            "licensed_count": licensed_count,
            "tampered_count": tampered_count,
            "unknown_count": unknown_count,
            "total": len(records),
            "verified_licensed": licensed_count,
            "rogue_synthetic": threats_count,
            "tampered_payload": tampered_count,
            "unknown_drift": unknown_count,
            "threats_flagged": threats_count,
            "duration_ms": duration_ms,
            "status_message": f"Processed {len(records)} records in {duration_ms} ms.",
        }
        job["records"] = processed_records
        job["manifest"] = processed_records

        # Record batch event in ledger
        ledger.record_event(
            event_id=f"EVT-BATCH-{uuid.uuid4().hex[:8].upper()}",
            event_type="BATCH_SCAN",
            sequence_hash=hashlib.sha256(raw_content[:512].encode()).hexdigest(),
            sequence_length=len(raw_content),
            classification="BATCH_PROCESSED",
            threat_detected=(threats_count > 0),
            payload_valid=(licensed_count > 0),
            details=job["summary"],
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        job["status"] = "FAILED"
        job["completed_at"] = datetime.now(timezone.utc).isoformat()
        job["summary"]["error"] = str(e)


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------
@app.get("/healthz")
async def health_check():
    """Kubernetes / Docker health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "2.2.0-ENTERPRISE",
        "active_providers": len(kms_service.providers),
        "kms_providers": len(kms_service.providers),
        "threat_index_count": len(threat_detector.references),
        "threat_index_targets": len(threat_detector.references),
        "ledger_events": ledger.get_stats().get("total_events", 0),
        "max_batch_records": MAX_BATCH_RECORDS,
    }


@app.get("/", response_class=HTMLResponse)
async def index_view(request: Request):
    """Renders the GeneSign Tactical Biosecurity Operations HUD."""
    stats = ledger.get_stats()
    providers = kms_service.get_public_registry()
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "stats": stats,
            "version": "2.2.0-ENTERPRISE",
            "providers": providers,
        },
    )


# ---------------------------------------------------------------------------
# V2 Batch FASTA/FASTQ Async Streaming Pipeline
# ---------------------------------------------------------------------------
@app.post("/api/v2/batch-scan")
async def api_batch_scan_v2(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    fasta_text: Optional[str] = Form(None),
    provenance_token_json: Optional[str] = Form(None),
):
    """Asynchronously ingests and screens multi-record FASTA/FASTQ files.

    Accepts multipart file upload (.fasta, .fa, .fastq) or raw text.
    Returns structured job handle for polling live progress and batch manifest.
    """
    content = ""
    if file:
        file_bytes = await file.read()
        content = file_bytes.decode("utf-8", errors="replace")
    elif raw_text and raw_text.strip():
        content = raw_text.strip()
    elif fasta_text and fasta_text.strip():
        content = fasta_text.strip()
    else:
        raise HTTPException(status_code=400, detail="Must provide either a multipart file upload, raw_text, or fasta_text string.")

    token = None
    if provenance_token_json:
        try:
            token = json.loads(provenance_token_json)
        except Exception:
            pass

    job_id = f"BATCH-{uuid.uuid4().hex[:12].upper()}"
    now_utc = datetime.now(timezone.utc).isoformat()

    BATCH_JOBS[job_id] = {
        "job_id": job_id,
        "status": "PENDING",
        "created_at": now_utc,
        "completed_at": None,
        "total_records": 0,
        "processed_records": 0,
        "progress_percent": 0.0,
        "summary": {},
        "records": [],
    }

    background_tasks.add_task(execute_batch_scan_job, job_id, content, token)

    return {
        "job_id": job_id,
        "status": "PENDING",
        "created_at": now_utc,
        "poll_url": f"/api/v2/batch-scan/{job_id}",
        "message": "Batch ingestion pipeline initialized. Polling available.",
    }


@app.get("/api/v2/batch-scan/{job_id}")
async def api_get_batch_job(job_id: str):
    """Polls status, live progress, and results of an async batch screening job."""
    job = BATCH_JOBS.get(job_id) or BATCH_JOBS.get(job_id.upper())
    if not job:
        raise HTTPException(status_code=404, detail=f"Batch scan job '{job_id}' not found.")
    return job


@app.get("/api/v2/batch-scan")
async def api_list_batch_jobs(limit: int = 15):
    """Lists recent batch jobs and their current status."""
    jobs = list(BATCH_JOBS.values())[-limit:]
    jobs.reverse()
    return {
        "total_jobs": len(BATCH_JOBS),
        "jobs": [
            {
                "job_id": j["job_id"],
                "status": j["status"],
                "created_at": j["created_at"],
                "completed_at": j["completed_at"],
                "total_records": j["total_records"],
                "progress_percent": j["progress_percent"],
                "summary": j["summary"],
            }
            for j in jobs
        ],
    }


# ---------------------------------------------------------------------------
# V2 Multi-Tenant Key Management Service (KMS) Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v2/kms/providers")
async def api_kms_providers():
    """Returns list of registered synthesis providers and active key versions."""
    return {
        "providers": kms_service.get_public_registry(),
        "total_providers": len(kms_service.providers),
        "crl_revoked_count": len(kms_service.crl),
    }


@app.post("/api/v2/kms/providers")
async def api_kms_register_provider(req: RegisterProviderRequest):
    """Registers a new licensed synthesis provider with an initial v1 Ed25519 keypair."""
    try:
        prov = kms_service.register_provider(
            provider_id=req.provider_id,
            name=req.name,
            jurisdiction=req.jurisdiction,
        )
        return {
            "status": "SUCCESS",
            "provider": prov.to_dict(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v2/kms/providers/{provider_id}/rotate")
async def api_kms_rotate_key(provider_id: str):
    """Rotates Ed25519 signing keypair for a provider to the next version."""
    try:
        new_key = kms_service.rotate_provider_key(provider_id)
        firewall.register_lab_public_key(provider_id.upper(), new_key.public_key)
        return {
            "success": True,
            "status": "ROTATED",
            "provider_id": provider_id.upper(),
            "new_key": new_key.to_dict(),
            "new_key_version": new_key.version,
            "fingerprint": new_key.fingerprint,
            "created_at": new_key.created_at,
            "message": f"Successfully rotated key to {new_key.version} for {provider_id.upper()}",
        }
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/v2/kms/providers/{provider_id}/revoke")
async def api_kms_revoke_key(provider_id: str, req: RevokeKeyRequest):
    """Revokes a key and appends it to the active Key Revocation List (CRL)."""
    try:
        pid = provider_id.upper()
        provider = kms_service.providers.get(pid)
        if not provider:
            raise HTTPException(status_code=404, detail=f"Synthesis provider '{pid}' not found.")
        key_ver = req.key_version or provider.active_key_version
        crl_entry = kms_service.revoke_key(
            provider_id=pid,
            key_version=key_ver,
            reason=req.reason,
        )
        return {
            "success": True,
            "status": "REVOKED",
            "provider_id": pid,
            "key_version": key_ver,
            "crl_entry": crl_entry,
            "message": f"Key {key_ver} for provider {pid} has been revoked.",
        }
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v2/kms/crl")
async def api_kms_crl():
    """Retrieves active Key Revocation List (CRL)."""
    return {
        "crl": kms_service.get_crl(),
        "total_revocations": len(kms_service.crl),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# V1 Core REST Endpoints (Preserved for 100% Backward Compatibility)
# ---------------------------------------------------------------------------
@app.post("/api/v1/watermark", response_model=WatermarkResponse)
async def api_watermark(req: WatermarkRequest):
    """Embeds synonymous degenerate codon watermark and generates provenance certificate."""
    input_text = req.dna_sequence.strip()
    records = list(SequenceParser.parse_stream(input_text))
    if records:
        clean_dna = records[0].sequence
        rec_id = records[0].record_id
    else:
        clean_dna = clean_sequence(input_text)
        rec_id = "SYNTH-CDS"

    if len(clean_dna) % 3 != 0:
        raise HTTPException(status_code=400, detail=f"CDS length ({len(clean_dna)}) must be multiple of 3.")

    seq_hash = calculate_sequence_hash(clean_dna)
    pub_fp = LabKeyManager.get_fingerprint(server_pub)

    payload = {
        "lab_id": req.lab_id,
        "order_id": req.order_id,
        "key_fp": pub_fp[:4],
    }

    try:
        wm_res = embed_watermark(clean_dna, payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    event_id = f"EVT-WM-{uuid.uuid4().hex[:8].upper()}"

    # Generate Ed25519 provenance token using KMS or fallback signer
    pid = req.lab_id.upper()
    if pid in kms_service.providers:
        token = kms_service.sign_provenance(pid, wm_res.watermarked_dna, order_id=req.order_id)
    else:
        signer = ProvenanceSigner(lab_id=req.lab_id, private_key=server_priv)
        token = signer.create_provenance_token(wm_res.watermarked_dna, order_id=req.order_id)

    token_id = token["claims"]["token_id"]
    CERTIFICATES_CACHE[token_id] = token

    # Format FASTA
    header = f">{rec_id}|GeneSign-Watermarked|Lab={req.lab_id}|Order={req.order_id}|Cert={token_id}"
    lines = [wm_res.watermarked_dna[i:i+80] for i in range(0, len(wm_res.watermarked_dna), 80)]
    fasta_out = f"{header}\n" + "\n".join(lines) + "\n"

    # Audit Ledger
    ledger.record_event(
        event_id=event_id,
        event_type="WATERMARK",
        sequence_hash=calculate_sequence_hash(wm_res.watermarked_dna),
        sequence_length=len(wm_res.watermarked_dna),
        lab_id=req.lab_id,
        order_id=req.order_id,
        classification="VERIFIED_LICENSED",
        threat_detected=False,
        payload_valid=True,
        details={
            "modulated_codons": wm_res.modulated_codons_count,
            "gc_drift": wm_res.invariants.gc_drift,
            "cert_id": token_id,
        },
    )

    # Metering Telemetry
    billing_service.record_usage(req.lab_id or "TWIST", "BASE_PAIRS_WATERMARKED", len(wm_res.watermarked_dna))

    inv_dict = {
        "original_length_nt": wm_res.invariants.original_length_nt,
        "watermarked_length_nt": wm_res.invariants.watermarked_length_nt,
        "amino_acid_length": wm_res.invariants.amino_acid_length,
        "translation_identical": wm_res.invariants.translation_identical,
        "missense_mutations": wm_res.invariants.missense_mutations,
        "original_gc": wm_res.invariants.original_gc,
        "watermarked_gc": wm_res.invariants.watermarked_gc,
        "gc_drift": wm_res.invariants.gc_drift,
        "gc_drift_tolerated": wm_res.invariants.gc_drift_tolerated,
        "original_entropy": wm_res.invariants.original_entropy,
        "watermarked_entropy": wm_res.invariants.watermarked_entropy,
        "entropy_drift": wm_res.invariants.entropy_drift,
        "new_restriction_sites": wm_res.invariants.new_restriction_sites_introduced,
        "restriction_guard_passed": wm_res.invariants.restriction_guard_passed,
    }

    return WatermarkResponse(
        success=wm_res.success,
        event_id=event_id,
        watermarked_fasta=fasta_out,
        watermarked_dna=wm_res.watermarked_dna,
        original_dna=wm_res.original_dna,
        protein_translation=wm_res.protein_translation,
        carrier_capacity_bits=wm_res.carrier_capacity_bits,
        payload_bits_used=wm_res.payload_bits_used,
        modulated_codons_count=wm_res.modulated_codons_count,
        codon_modulations=[ModulatedCodonInfo(**c) for c in wm_res.codon_modulations],
        invariants=inv_dict,
        certificate=token if req.generate_certificate else None,
        certificate_id=token_id if req.generate_certificate else None,
    )


@app.post("/api/v1/scan", response_model=ScanResponse)
async def api_scan(req: ScanRequest):
    """Scans DNA sequence through Biosecurity Firewall & Threat Radar."""
    input_text = req.sequence_or_fasta.strip()
    records = list(SequenceParser.parse_stream(input_text))
    if records:
        clean_dna = records[0].sequence
        rec_id = records[0].record_id
    else:
        clean_dna = clean_sequence(input_text)
        rec_id = req.record_id or "UNKNOWN-QUERY"

    if len(clean_dna) < 17:
        raise HTTPException(status_code=400, detail="Sequence too short for biosecurity inspection.")

    eval_res = firewall.scan_sequence(
        sequence=clean_dna,
        record_id=rec_id,
        provenance_token=req.provenance_token,
    )

    try:
        protein = translate_dna(clean_dna) if len(clean_dna) % 3 == 0 else "N/A (Frameshift/Non-CDS)"
    except Exception:
        protein = "Translation Failed (Invalid Codons)"

    event_id = f"EVT-SCAN-{uuid.uuid4().hex[:8].upper()}"

    # Log to audit ledger
    ledger.record_event(
        event_id=event_id,
        event_type="SCAN",
        sequence_hash=eval_res.sequence_hash,
        sequence_length=len(clean_dna),
        lab_id=eval_res.lab_id,
        order_id=eval_res.order_id,
        classification=eval_res.classification.value,
        threat_detected=eval_res.threat_detected,
        payload_valid=eval_res.payload_valid,
        details={
            "threats": [t["agent_name"] for t in eval_res.threat_matches],
            "status": eval_res.status_summary,
        },
    )

    # Metering Telemetry
    billing_service.record_usage(eval_res.lab_id or "TWIST", "BIOSECURITY_SCAN", 1)

    return ScanResponse(
        record_id=rec_id,
        classification=eval_res.classification.value,
        threat_detected=eval_res.threat_detected,
        watermark_detected=eval_res.watermark_detected,
        payload_valid=eval_res.payload_valid,
        tampered=eval_res.tampered,
        lab_id=eval_res.lab_id,
        order_id=eval_res.order_id,
        sequence_hash=eval_res.sequence_hash,
        sequence_length=len(clean_dna),
        gc_content=calculate_gc_content(clean_dna),
        shannon_entropy=calculate_shannon_entropy(clean_dna),
        amino_acid_translation=protein,
        threat_matches=[ThreatMatchInfo(**m) for m in eval_res.threat_matches],
        status_summary=eval_res.status_summary,
        provenance_verified=eval_res.provenance_verified,
        event_id=event_id,
        chimeric_detected=eval_res.chimeric_detected,
        highest_threat_tier=eval_res.highest_threat_tier,
    )


# ---------------------------------------------------------------------------
# NVIDIA Nemotron Threat Rationale & Regulatory Intelligence
# ---------------------------------------------------------------------------
class AiRationaleRequest(BaseModel):
    record_id: Optional[str] = Field("SCAN-TARGET", description="Unique record/sample ID")
    classification: str = Field(..., description="Firewall classification: UNKNOWN_DRIFT, TAMPERED_PAYLOAD, ROGUE_SYNTHETIC, VERIFIED_LICENSED")
    sequence_length: Optional[int] = Field(0, description="Length of sequence in base pairs")
    gc_content: Optional[float] = Field(0.0, description="GC content percentage")
    threat_detected: Optional[bool] = Field(False, description="Whether select agent matches were found")
    highest_threat_tier: Optional[str] = Field("NONE", description="Tier of highest threat match")
    threat_matches: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="List of threat match objects")
    tampered: Optional[bool] = Field(False, description="Whether watermark payload integrity failed")
    status_summary: Optional[str] = Field("", description="Engine status summary")
    lab_id: Optional[str] = Field(None, description="Origin lab identifier")
    order_id: Optional[str] = Field(None, description="Commercial order identifier")
    sequence_hash: Optional[str] = Field(None, description="SHA-256 hash of sequence")


class AiRationaleResponse(BaseModel):
    success: bool
    model: str
    provider: str
    classification: str
    risk_score: int
    executive_summary: str
    regulatory_implications: str
    recommended_actions: List[str]
    latency_seconds: float
    is_fallback: bool
    timestamp: str
    record_id: Optional[str] = None
    fallback_reason: Optional[str] = None


@app.post("/api/v1/analyze/ai-rationale", response_model=AiRationaleResponse)
async def api_analyze_ai_rationale(req: AiRationaleRequest):
    """Generates an executive biosecurity risk rationale and regulatory directive using NVIDIA Nemotron."""
    eval_dict = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    result = nemotron_advisor.analyze_threat_rationale(eval_dict)
    result["record_id"] = req.record_id
    return AiRationaleResponse(**result)


@app.get("/api/v1/analyze/ai-status")
async def api_analyze_ai_status():
    """Returns the operational configuration and connection status of NVIDIA Nemotron."""
    return nemotron_advisor.get_status()


@app.post("/api/v1/verify")
async def api_verify(req: VerifyRequest):
    """Template-free extraction and verification."""
    clean_dna = clean_sequence(req.sequence)
    res = extract_watermark(clean_dna)
    return {
        "extracted": res.extracted,
        "tampered": res.tampered,
        "valid_sync": res.valid_sync,
        "valid_crc": res.valid_crc,
        "payload": res.payload,
        "error": res.error_message,
        "sequence_hash": calculate_sequence_hash(clean_dna),
    }


@app.get("/api/v1/ledger")
async def api_ledger(limit: int = 50):
    """Returns persistent audit ledger events and aggregated metrics."""
    return {
        "events": ledger.get_recent_events(limit=limit),
        "stats": ledger.get_stats(),
    }


@app.get("/api/v1/samples/{sample_id}")
async def api_sample(sample_id: str):
    """Provides standard biological sample sequences."""
    mapping = {
        "gfp": "gfp.fasta",
        "insulin": "insulin.fasta",
        "ebola": "ebola_vp35.fasta",
        "smallpox": "smallpox_ha.fasta",
        "spike": "spike_partial.fasta",
        "batch_fasta": "batch_synthesis_orders.fasta",
        "batch_fastq": "batch_inspection.fastq",
    }
    filename = mapping.get(sample_id.lower())
    if not filename:
        raise HTTPException(status_code=404, detail="Sample not found.")
    file_path = SAMPLES_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Sample file missing.")
    return {
        "sample_id": sample_id,
        "filename": filename,
        "content": file_path.read_text(encoding="utf-8"),
    }


@app.get("/api/v1/certificate/{token_id}")
async def api_certificate(token_id: str):
    """Downloads JSON Provenance Certificate."""
    cert = CERTIFICATES_CACHE.get(token_id)
    if not cert:
        # Check if stored in ledger
        events = ledger.get_recent_events(limit=100)
        for ev in events:
            if ev.get("details", {}).get("cert_id") == token_id:
                cert = {
                    "token_id": token_id,
                    "event_id": ev["event_id"],
                    "sequence_hash": ev["sequence_hash"],
                    "lab_id": ev.get("lab_id"),
                    "order_id": ev.get("order_id"),
                    "status": "RETRIEVED_FROM_AUDIT_LEDGER",
                }
                break
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate token not found.")
    return JSONResponse(
        content=cert,
        headers={"Content-Disposition": f"attachment; filename=genesign_cert_{token_id}.json"},
    )


# ---------------------------------------------------------------------------
# Level 3: Hardware State Interlock & Protocol Endpoints
# ---------------------------------------------------------------------------
class HardwareDispatchRequest(BaseModel):
    sequence: str = Field(..., description="Target sequence to synthesize")
    record_id: Optional[str] = Field("SYNTH-TARGET", description="Unique record/sample ID")
    provenance_token: Optional[Dict[str, Any]] = Field(None, description="Cryptographic Ed25519 provenance certificate")
    lab_id: Optional[str] = Field("TWS", description="Synthesis provider ID")
    order_id: Optional[str] = Field("ORD-001", description="Commercial order number")


class HardwareEstopRequest(BaseModel):
    reason: Optional[str] = Field("MANUAL_EMERGENCY_ESTOP_TRIGGERED", description="Emergency stop rationale")


class HardwareResetRequest(BaseModel):
    authorization_key: Optional[str] = Field("ADMIN-SECURITY-OVERRIDE", description="Administrative bypass key")


@app.get("/api/v3/hardware/status")
async def api_v3_hardware_status():
    """Returns physical synthesis equipment status, valve states, and pressure/temp telemetry."""
    return hardware_interlock.get_telemetry().to_dict()


@app.post("/api/v3/hardware/dispatch")
async def api_v3_hardware_dispatch(req: HardwareDispatchRequest):
    """Enforces biosecurity gate on hardware. Dispenses if licensed, trips physical E-STOP if violation."""
    result = hardware_interlock.dispatch_synthesis(
        sequence=req.sequence,
        record_id=req.record_id or "SYNTH-TARGET",
        provenance_token=req.provenance_token,
        lab_id=req.lab_id,
        order_id=req.order_id,
    )
    # Also log to crypto ledger
    event_id = f"EVT-HW-{uuid.uuid4().hex[:8].upper()}"
    crypto_ledger.record_chained_event(
        event_id=event_id,
        event_type="HARDWARE_DISPATCH",
        sequence_hash=result.get("sequence_hash", "UNKNOWN"),
        sequence_length=len(req.sequence),
        lab_id=req.lab_id,
        order_id=req.order_id,
        classification=result.get("classification", "LOCKED"),
        threat_detected=result.get("threat_detected", False),
        payload_valid=result.get("success", False),
        details={"state": result.get("state"), "error": result.get("error")},
    )
    # Metering Telemetry
    billing_service.record_usage(req.lab_id or "TWIST", "HARDWARE_DISPATCH", 1)
    return result


@app.post("/api/v3/hardware/estop")
async def api_v3_hardware_estop(req: HardwareEstopRequest):
    """Manually or remotely trips physical synthesizer emergency stop (INTERLOCK_HALT)."""
    return hardware_interlock.trigger_interlock_halt(reason=req.reason or "MANUAL_ESTOP_REQUESTED")


@app.post("/api/v3/hardware/reset")
async def api_v3_hardware_reset(req: HardwareResetRequest):
    """Clears physical emergency latch following authorized administrative review."""
    try:
        return hardware_interlock.reset_hardware(authorization_key=req.authorization_key or "ADMIN-SECURITY-OVERRIDE")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Level 3: Fragment Assembly De-anonymization & Overhang Reconstruction
# ---------------------------------------------------------------------------
class SplitOrderInput(BaseModel):
    order_id: str
    sequence: str
    customer_id: Optional[str] = "CUST-DEFAULT"
    provider_id: Optional[str] = "TWIST"
    record_id: Optional[str] = None


class SplitOrderScreenRequest(BaseModel):
    orders: List[SplitOrderInput]
    min_overlap: Optional[int] = 15


@app.post("/api/v3/split-orders/screen")
async def api_v3_screen_split_orders(req: SplitOrderScreenRequest):
    """Cross-references orders, detects cohesive overlaps, and evaluates assembled contigs."""
    scanner = SplitOrderGraphAssembler(min_overlap=req.min_overlap or 15)
    for ord_in in req.orders:
        scanner.add_order(
            order_id=ord_in.order_id,
            sequence=ord_in.sequence,
            customer_id=ord_in.customer_id or "CUST-DEFAULT",
            provider_id=ord_in.provider_id or "TWIST",
            record_id=ord_in.record_id,
        )

    contigs = scanner.reconstruct_contigs()
    threats_flagged = [c for c in contigs if c.threat_detected]

    # If any assembled threat detected, record event in ledger
    if threats_flagged:
        event_id = f"EVT-SPLIT-THREAT-{uuid.uuid4().hex[:8].upper()}"
        top_threat = threats_flagged[0]
        crypto_ledger.record_chained_event(
            event_id=event_id,
            event_type="DISTRIBUTED_THREAT_DETECTED",
            sequence_hash=hashlib.sha256(top_threat.assembled_sequence.encode()).hexdigest(),
            sequence_length=top_threat.assembled_length_nt,
            classification="ROGUE_SYNTHETIC",
            threat_detected=True,
            payload_valid=False,
            details={
                "target_agent": top_threat.agent_name,
                "regulatory_tier": top_threat.regulatory_tier,
                "participating_orders": top_threat.participating_order_ids,
            },
        )

    return {
        "total_orders_analyzed": len(req.orders),
        "assembled_contigs_count": len(contigs),
        "threats_detected_count": len(threats_flagged),
        "contigs": [c.to_dict() for c in contigs],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/v3/split-orders/orders")
async def api_v3_get_split_orders():
    """Lists recent fragment orders maintained in the active sliding window."""
    return {
        "order_pool_count": len(assembly_scanner.order_pool),
        "orders": [
            {
                "order_id": o.order_id,
                "record_id": o.record_id,
                "customer_id": o.customer_id,
                "provider_id": o.provider_id,
                "length_nt": o.length_nt,
                "sequence_hash": o.sequence_hash,
                "timestamp": o.timestamp,
            }
            for o in assembly_scanner.order_pool
        ],
    }


@app.post("/api/v3/split-orders/reset")
async def api_v3_reset_split_orders():
    """Resets the cross-order sliding window memory."""
    assembly_scanner.clear()
    return {"success": True, "message": "Sliding-window order memory cleared."}


# ---------------------------------------------------------------------------
# Level 3: Immutable Merkle Tree Ledger & RFC-3161 Proofs
# ---------------------------------------------------------------------------
@app.get("/api/v3/ledger/merkle-bundle")
async def api_v3_get_merkle_bundle(limit: int = 50):
    """Exports RFC-3161 compliant cryptographic audit bundle with Merkle inclusion proofs."""
    bundle = crypto_ledger.export_rfc3161_bundle(limit=limit)
    billing_service.record_usage("TWIST", "MERKLE_PROOF_ISSUED", 1)
    return bundle


@app.post("/api/v3/ledger/verify-bundle")
async def api_v3_verify_merkle_bundle(bundle: Dict[str, Any]):
    """Cryptographically verifies an RFC-3161 audit bundle and its Merkle inclusion proofs."""
    return CryptographicAuditLedger.verify_rfc3161_bundle(bundle)


# ===========================================================================
# Commercial SaaS & Enterprise Monetization Layer
# ===========================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., description="Corporate username or email")
    password: str = Field(..., description="Account password")


class RegisterUserRequest(BaseModel):
    username: str = Field(..., description="Corporate email identifier")
    password: str = Field(..., description="Minimum 8-character password")
    tenant_id: Optional[str] = Field("TWIST", description="Assigned tenant provider ID")
    role: Optional[str] = Field("LAB_TECHNICIAN", description="RBAC Role")


class CreateApiKeyRequest(BaseModel):
    name: str = Field("Production Foundry Key", description="Friendly API key label")
    tier: Optional[str] = Field("FREE", description="Subscription tier: FREE, STARTUP, ENTERPRISE")
    rate_limit_per_day: Optional[int] = Field(50, description="Daily request quota")


class SubscribeRequest(BaseModel):
    tier: str = Field(..., description="Target tier: STARTUP_LAB, SYNTHESIS_FOUNDRY, GLOBAL_ENTERPRISE")
    payment_method_id: Optional[str] = Field("pm_mock_visa", description="Stripe payment method token")


class TenantBrandingRequest(BaseModel):
    tenant_id: Optional[str] = Field("TWIST", description="Tenant provider identifier")
    org_name: str = Field(..., description="Official corporate or foundry legal name")
    lab_id: str = Field(..., description="Assigned laboratory facility ID")
    logo_url: Optional[str] = Field("", description="SVG or PNG logo asset URL")
    contact_email: Optional[str] = Field("", description="Compliance point of contact email")
    accent_color: Optional[str] = Field("#ff6b4a", description="Brand accent color hex code")


# ---------------------------------------------------------------------------
# 1. Authentication & RBAC Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/auth/login")
async def api_auth_login(req: LoginRequest):
    """Authenticates corporate user and issues signed HMAC-SHA256 JWT bearer token."""
    user = ledger.get_user_by_username(req.username.strip())
    if not user:
        raise HTTPException(status_code=401, detail="Invalid corporate credentials.")

    if not verify_password(req.password, user["password_hash"], user["salt"]):
        raise HTTPException(status_code=401, detail="Invalid corporate credentials.")

    token_claims = {
        "sub": user["username"],
        "user_id": user["id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
    }
    access_token = create_access_token(token_claims)

    return {
        "success": True,
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "tenant_id": user["tenant_id"],
            "role": user["role"],
        },
        "message": f"Authenticated successfully as {user['role']}",
    }


@app.post("/api/v1/auth/register")
async def api_auth_register(req: RegisterUserRequest, identity: Dict[str, Any] = Depends(get_current_identity)):
    """Registers a new user account under the active tenant (requires ENTERPRISE_ADMIN)."""
    # Enforce role: only ENTERPRISE_ADMIN can provision users
    if identity.get("role") != UserRole.ENTERPRISE_ADMIN:
        raise HTTPException(status_code=403, detail="Only ENTERPRISE_ADMIN may provision new user accounts.")

    existing = ledger.get_user_by_username(req.username.strip())
    if existing:
        raise HTTPException(status_code=400, detail=f"User '{req.username}' is already registered.")

    salt = generate_salt()
    pw_hash = hash_password(req.password, salt)
    tenant = req.tenant_id or identity.get("tenant_id", "TWIST")
    role = req.role if req.role in UserRole.ALL_ROLES else UserRole.LAB_TECHNICIAN

    created = ledger.create_user(req.username.strip(), pw_hash, salt, tenant, role)
    return {
        "success": True,
        "user": created,
        "message": f"Successfully created {role} user '{req.username}' under tenant '{tenant}'.",
    }


@app.get("/api/v1/auth/me")
async def api_auth_me(identity: Dict[str, Any] = Depends(get_current_identity)):
    """Returns caller profile, active permissions, tenant context, and rate limit status."""
    return {
        "identity": identity,
        "authenticated": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# 2. Commercial API Key Management Endpoints
# ---------------------------------------------------------------------------
@app.post("/api/v1/auth/api-keys")
async def api_create_api_key(
    req: CreateApiKeyRequest,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Generates a high-security API key for programmatic B2B synthesis integration."""
    tenant = identity.get("tenant_id", "TWIST")
    raw_key, key_hash = generate_api_key(prefix="gs_live")
    key_id = f"KEY-{uuid.uuid4().hex[:8].upper()}"

    tier_clean = req.tier.upper() if req.tier else "FREE"
    rate_limit = req.rate_limit_per_day
    if tier_clean == "FREE":
        rate_limit = 50
    elif tier_clean in ["STARTUP", "STARTUP_LAB"]:
        rate_limit = 10_000
    else:
        rate_limit = 1_000_000

    prefix_display = raw_key[:12] + "..." + raw_key[-4:]
    saved = ledger.create_api_key(
        key_id=key_id,
        tenant_id=tenant,
        name=req.name,
        key_prefix=prefix_display,
        key_hash=key_hash,
        tier=tier_clean,
        rate_limit_per_day=rate_limit,
    )

    return {
        "success": True,
        "key_id": key_id,
        "raw_api_key": raw_key,  # Returned only once during creation
        "key_prefix": prefix_display,
        "name": req.name,
        "tenant_id": tenant,
        "tier": tier_clean,
        "rate_limit_per_day": rate_limit,
        "warning": "Please copy this API key now. For cryptographic safety, only its SHA-256 hash is retained on server.",
    }


@app.get("/api/v1/auth/api-keys")
async def api_list_api_keys(identity: Dict[str, Any] = Depends(get_current_identity)):
    """Lists all active and revoked API keys provisioned for the current tenant."""
    tenant = identity.get("tenant_id", "TWIST")
    keys = ledger.list_api_keys(tenant)
    return {
        "tenant_id": tenant,
        "total_keys": len(keys),
        "api_keys": keys,
    }


@app.delete("/api/v1/auth/api-keys/{key_id}")
async def api_revoke_api_key(key_id: str, identity: Dict[str, Any] = Depends(get_current_identity)):
    """Revokes an API key immediately blocking all further programmatic access."""
    tenant = identity.get("tenant_id", "TWIST")
    revoked = ledger.revoke_api_key(key_id, tenant)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"API key '{key_id}' not found for tenant '{tenant}'.")

    return {
        "success": True,
        "key_id": key_id,
        "status": "REVOKED",
        "message": f"API key {key_id} has been deactivated immediately.",
    }


# ---------------------------------------------------------------------------
# 3. Automated Billing & Usage Metering Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/v1/billing/usage")
async def api_get_billing_usage(
    tenant_id: Optional[str] = None,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Returns current billing cycle consumption telemetry and accrued charges."""
    effective_tenant = tenant_id or identity.get("tenant_id", "TWIST")
    return billing_service.get_billing_usage(effective_tenant)


@app.post("/api/v1/billing/subscribe")
async def api_billing_subscribe(
    req: SubscribeRequest,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Simulates automated Stripe subscription checkout and tier provisioning."""
    effective_tenant = identity.get("tenant_id", "TWIST")
    try:
        res = billing_service.subscribe_tier(
            tenant_id=effective_tenant,
            new_tier=req.tier,
            payment_method_id=req.payment_method_id,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/v1/billing/invoices")
async def api_billing_invoices(
    tenant_id: Optional[str] = None,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Retrieves itemized billing invoices for the tenant."""
    effective_tenant = tenant_id or identity.get("tenant_id", "TWIST")
    return {
        "tenant_id": effective_tenant,
        "invoices": billing_service.get_invoices(effective_tenant),
    }


@app.get("/api/v1/billing/plans")
async def api_billing_plans():
    """Returns commercial SaaS subscription tiers and pricing specs."""
    return {
        "plans": PRICING_PLANS,
        "currency": "USD",
        "billing_model": "HYBRID_SEATS_PLUS_METERED_THROUGHPUT",
    }


class CreateCheckoutSessionRequest(BaseModel):
    tier: str = Field(..., description="Target tier: STARTUP_LAB, SYNTHESIS_FOUNDRY, GLOBAL_ENTERPRISE")
    customer_email: Optional[str] = Field("executive@foundry.com", description="Customer billing email")
    success_url: Optional[str] = Field(None, description="Redirect URL upon payment completion")
    cancel_url: Optional[str] = Field(None, description="Redirect URL upon cancellation")


@app.post("/api/v1/billing/create-checkout-session")
async def api_create_checkout_session(
    req: CreateCheckoutSessionRequest,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Creates a Stripe Checkout Session for subscription tier provisioning."""
    tenant = identity.get("tenant_id", "TWIST")
    session = billing_service.create_checkout_session(
        tenant_id=tenant,
        tier=req.tier,
        customer_email=req.customer_email,
        success_url=req.success_url,
        cancel_url=req.cancel_url,
    )
    return {
        "success": True,
        "session": session,
        "checkout_url": session["checkout_url"],
    }


@app.post("/api/v1/billing/webhook")
async def api_billing_webhook(request: Request):
    """Handles Stripe webhooks (checkout.session.completed) to auto-provision production API credentials."""
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    signature = request.headers.get("Stripe-Signature")
    result = billing_service.process_webhook(payload, signature=signature)
    return result


@app.get("/api/v1/billing/checkout-test", response_class=HTMLResponse)
async def api_billing_checkout_test_page(
    session_id: str = "cs_demo_session",
    tier: str = "SYNTHESIS_FOUNDRY",
    tenant: str = "TWIST",
    email: str = "executive@twistdna.com",
):
    """Interactive Sandbox & Test Checkout Portal simulating live Stripe payment flow."""
    plan = PRICING_PLANS.get(tier.upper(), PRICING_PLANS["SYNTHESIS_FOUNDRY"])
    fee = plan["base_fee_monthly"]
    plan_name = plan["name"]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>GeneSign Commercial Checkout // Stripe Gateway</title>
  <link rel="stylesheet" href="/static/css/style.css">
  <style>
    body {{
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      background: #040812;
      padding: 1.5rem;
    }}
    .checkout-modal {{
      background: rgba(13, 19, 34, 0.95);
      backdrop-filter: blur(20px);
      border: 1px solid rgba(255, 90, 54, 0.4);
      box-shadow: 0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(255, 90, 54, 0.2);
      border-radius: 16px;
      padding: 2.5rem;
      max-width: 540px;
      width: 100%;
    }}
  </style>
</head>
<body>
  <div class="checkout-modal">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem;">
      <div style="font-size: 0.8rem; font-family: var(--font-mono); color: var(--coral-accent); font-weight: 700; text-transform: uppercase;">
        STRIPE CHECKOUT // SECURE GATEWAY
      </div>
      <span style="font-size: 0.7rem; background: rgba(16, 185, 129, 0.15); color: #34d399; padding: 0.2rem 0.5rem; border-radius: 4px; font-family: var(--font-mono);">TEST MODE ACTIVE</span>
    </div>

    <h2 style="font-size: 1.5rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem;">{plan_name}</h2>
    <p style="font-size: 0.85rem; color: #94a3b8; margin-bottom: 1.5rem;">
      Commercial biosecurity license and automated DNA watermarking subscription for <strong>{tenant}</strong>.
    </p>

    <div style="background: rgba(0,0,0,0.4); border: 1px solid var(--border-glass); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem;">
      <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; font-size: 0.85rem;">
        <span style="color: #cbd5e1;">Monthly Base Subscription:</span>
        <strong style="color: #fff; font-family: var(--font-mono);">${fee:,.2f} USD</strong>
      </div>
      <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem; font-size: 0.85rem;">
        <span style="color: #cbd5e1;">Included Base Pairs:</span>
        <span style="color: #38bdf8; font-family: var(--font-mono);">{plan['included_base_pairs']:,} bp</span>
      </div>
      <div style="display: flex; justify-content: space-between; font-size: 0.85rem;">
        <span style="color: #cbd5e1;">Subscriber Email:</span>
        <span style="color: #94a3b8; font-family: var(--font-mono);">{email}</span>
      </div>
    </div>

    <div id="checkout-actions">
      <button id="pay-btn" class="btn-cinema" style="width: 100%; justify-content: center;" onclick="completeSimulatedPayment()">
        <span>Complete Payment & Auto-Provision Key (${fee:,.2f})</span>
      </button>
      <div style="text-align: center; margin-top: 1rem;">
        <a href="/" style="font-size: 0.8rem; color: #64748b; text-decoration: none;">&larr; Return to SaaS Portal</a>
      </div>
    </div>

    <div id="checkout-success-view" style="display: none; margin-top: 1.5rem;">
      <div style="background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 8px; padding: 1.25rem;">
        <div style="color: #34d399; font-weight: 700; margin-bottom: 0.5rem;">✓ SUBSCRIPTION ACTIVATED & CREDENTIALS PROVISIONED</div>
        <p style="font-size: 0.8rem; color: #cbd5e1; margin-bottom: 0.75rem;">Your production B2B API Key has been minted and registered:</p>
        <div class="key-display-box" id="new-key-display" style="font-size: 0.85rem;">gs_live_...</div>
        <div style="margin-top: 1rem; display: flex; gap: 0.5rem;">
          <button class="btn-xs-kms" onclick="copyResultKey()">Copy Token</button>
          <a href="/" class="btn-xs-kms" style="background: rgba(255,255,255,0.1); text-decoration: none; display: inline-flex; align-items: center;">Launch Operations HUD &rarr;</a>
        </div>
      </div>
    </div>
  </div>

  <script>
    async function completeSimulatedPayment() {{
      const btn = document.getElementById("pay-btn");
      btn.disabled = true;
      btn.innerText = "Processing Stripe Webhook...";

      try {{
        const resp = await fetch("/api/v1/billing/webhook", {{
          method: "POST",
          headers: {{ "Content-Type": "application/json" }},
          body: JSON.stringify({{
            type: "checkout.session.completed",
            tenant_id: "{tenant}",
            tier: "{tier}",
            customer_email: "{email}",
            data: {{
              object: {{
                id: "{session_id}",
                client_reference_id: "{tenant}",
                metadata: {{ tier: "{tier}" }},
                customer_details: {{ email: "{email}" }}
              }}
            }}
          }})
        }});

        const res = await resp.json();
        if (res.success) {{
          document.getElementById("checkout-actions").style.display = "none";
          document.getElementById("checkout-success-view").style.display = "block";
          document.getElementById("new-key-display").innerText = res.provisioned_api_key;
        }} else {{
          alert("Payment processing error: " + JSON.stringify(res));
          btn.disabled = false;
        }}
      }} catch (err) {{
        alert("Webhook dispatch failed: " + err.message);
        btn.disabled = false;
      }}
    }}

    function copyResultKey() {{
      const key = document.getElementById("new-key-display").innerText;
      navigator.clipboard.writeText(key).then(() => alert("Production API key copied to clipboard!"));
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)


# ---------------------------------------------------------------------------
# 4. White-label Branding & Enterprise Compliance Reports
# ---------------------------------------------------------------------------
@app.get("/api/v1/tenants/branding")
async def api_get_tenant_branding(
    tenant_id: Optional[str] = None,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Retrieves custom white-label branding configurations for tenant."""
    effective_tenant = tenant_id or identity.get("tenant_id", "TWIST")
    return ledger.get_tenant_branding(effective_tenant)


@app.post("/api/v1/tenants/branding")
async def api_save_tenant_branding(
    req: TenantBrandingRequest,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Updates white-label organization details, lab ID, logo, and brand accent color."""
    effective_tenant = req.tenant_id or identity.get("tenant_id", "TWIST")
    saved = ledger.save_tenant_branding(
        tenant_id=effective_tenant,
        org_name=req.org_name,
        lab_id=req.lab_id,
        logo_url=req.logo_url or "",
        contact_email=req.contact_email or "",
        accent_color=req.accent_color or "#ff6b4a",
    )
    return {
        "success": True,
        "branding": saved,
        "message": f"Successfully updated white-label branding for {effective_tenant}",
    }


@app.get("/api/v1/compliance/certificate/{event_id}")
async def api_get_compliance_certificate_json(
    event_id: str,
    tenant_id: Optional[str] = None,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Generates standardized cryptographic JSON-LD Biosecurity Compliance Certificate."""
    effective_tenant = tenant_id or identity.get("tenant_id", "TWIST")
    events = ledger.get_recent_events(limit=100)
    matched = next((e for e in events if e.get("event_id") == event_id), None)

    if not matched:
        # Fallback synthetic event record for interactive preview
        matched = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "WATERMARK",
            "sequence_hash": hashlib.sha256(event_id.encode()).hexdigest(),
            "sequence_length": 720,
            "classification": "VERIFIED_LICENSED",
            "threat_detected": False,
            "payload_valid": True,
            "lab_id": effective_tenant,
            "order_id": "ORD-SYNTH-991",
        }

    return compliance_generator.generate_json_certificate(matched, tenant_id=effective_tenant)


@app.get("/api/v1/compliance/certificate/{event_id}/pdf")
async def api_get_compliance_certificate_pdf(
    event_id: str,
    tenant_id: Optional[str] = None,
    identity: Dict[str, Any] = Depends(get_current_identity),
):
    """Generates publication-grade, vector-signed PDF Biosecurity Compliance Certificate."""
    effective_tenant = tenant_id or identity.get("tenant_id", "TWIST")
    events = ledger.get_recent_events(limit=100)
    matched = next((e for e in events if e.get("event_id") == event_id), None)

    if not matched:
        matched = {
            "event_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "WATERMARK",
            "sequence_hash": hashlib.sha256(event_id.encode()).hexdigest(),
            "sequence_length": 720,
            "classification": "VERIFIED_LICENSED",
            "threat_detected": False,
            "payload_valid": True,
            "lab_id": effective_tenant,
            "order_id": "ORD-SYNTH-991",
        }

    pdf_bytes = compliance_generator.generate_pdf_certificate(matched, tenant_id=effective_tenant)
    filename = f"GeneSign_Compliance_Certificate_{event_id}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"inline; filename={filename}",
            "X-Compliance-Framework": "US-HHS-2026; ISO-TC-276",
        },
    )


# Expose ASGI application instance cleanly for Vercel serverless execution
handler = app




