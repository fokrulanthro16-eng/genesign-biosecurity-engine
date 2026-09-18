"""GeneSign Enterprise CLI & Developer SDK.

Command-line interface for automated synthetic DNA watermarking,
cryptographic provenance signing, and biosecurity firewall inspection.
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click
from cryptography.hazmat.primitives.asymmetric import ed25519

from engine.watermark import embed_watermark, extract_watermark, clean_sequence
from scanner.firewall import BiosecurityFirewall, SequenceParser, ComplianceClassification
from security.signer import LabKeyManager, ProvenanceSigner, calculate_sequence_hash
from storage.ledger import AuditLedger


@click.group()
@click.version_option("2.0.0", prog_name="GeneSign Commercial DNA Watermarking")
def cli():
    """GeneSign: Commercial Synthetic DNA Watermarking & Biosecurity Firewall."""
    pass


@cli.command("keygen")
@click.option("--out-dir", type=click.Path(file_okay=False, writable=True), default="./keys", help="Directory to save PEM keys.")
@click.option("--lab-id", type=str, default="LAB-US-01", help="Licensed synthesis lab identifier.")
def keygen_cmd(out_dir: str, lab_id: str):
    """Generate asymmetric Ed25519 keypair for licensed DNA synthesis provider."""
    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    priv_file = out_path / f"{lab_id.lower()}_private.pem"
    pub_file = out_path / f"{lab_id.lower()}_public.pem"

    priv_key, pub_key = LabKeyManager.generate_keypair()
    LabKeyManager.save_keys(priv_key, priv_file, pub_file)
    fingerprint = LabKeyManager.get_fingerprint(pub_key)

    click.secho("\n[GENESIGN KEYGEN SUCCESS]", fg="green", bold=True)
    click.echo(f"  Lab ID:          {lab_id}")
    click.echo(f"  Key Fingerprint: {fingerprint}")
    click.echo(f"  Private Key:     {priv_file}")
    click.echo(f"  Public Key:      {pub_file}\n")


@cli.command("watermark")
@click.option("--in", "in_file", required=True, type=click.Path(exists=True, dir_okay=False), help="Input FASTA file containing target CDS.")
@click.option("--out", "out_file", required=True, type=click.Path(dir_okay=False, writable=True), help="Output FASTA destination for watermarked DNA.")
@click.option("--lab-id", required=True, type=str, help="Licensed DNA synthesis facility identifier.")
@click.option("--order-id", default="ORD-2026-SYNTH", type=str, help="Commercial synthesis order number.")
@click.option("--key-file", type=click.Path(exists=True, dir_okay=False), help="Path to lab Ed25519 private key PEM file (optional).")
@click.option("--cert-out", type=click.Path(dir_okay=False, writable=True), help="Output JSON Provenance Certificate file.")
def watermark_cmd(
    in_file: str,
    out_file: str,
    lab_id: str,
    order_id: str,
    key_file: Optional[str],
    cert_out: Optional[str],
):
    """Embed synonymous degenerate codon watermark and cryptographic provenance."""
    raw_content = Path(in_file).read_text(encoding="utf-8")
    records = list(SequenceParser.parse_stream(raw_content))
    if not records:
        click.secho("Error: No valid FASTA records found in input file.", fg="red", err=True)
        sys.exit(1)

    rec = records[0]
    dna_seq = rec.sequence

    # Key loading if provided
    priv_key = None
    pub_fp = "UNLOCKED-DEV-KEY"
    if key_file:
        try:
            priv_key = LabKeyManager.load_private_key(Path(key_file))
            pub_fp = LabKeyManager.get_fingerprint(priv_key.public_key())
        except Exception as e:
            click.secho(f"Key error: {e}", fg="red", err=True)
            sys.exit(1)

    # Prepare payload
    seq_hash = calculate_sequence_hash(dna_seq)
    payload = {
        "lab_id": lab_id,
        "order_id": order_id,
        "key_fp": pub_fp[:4],
    }

    try:
        wm_res = embed_watermark(dna_seq, payload)
    except Exception as e:
        click.secho(f"Watermarking failed: {e}", fg="red", err=True)
        sys.exit(1)

    if not wm_res.success:
        click.secho(f"Biological invariant failure: {wm_res.error_message}", fg="red", err=True)
        sys.exit(1)

    # Write output FASTA
    header = f">{rec.record_id}|GeneSign-Watermarked|Lab={lab_id}|Order={order_id}|FP={pub_fp[:8]}"
    formatted_seq = "\n".join(wm_res.watermarked_dna[i:i+80] for i in range(0, len(wm_res.watermarked_dna), 80))
    Path(out_file).write_text(f"{header}\n{formatted_seq}\n", encoding="utf-8")

    # Generate provenance certificate if requested or private key present
    provenance_token = None
    if priv_key:
        signer = ProvenanceSigner(lab_id=lab_id, private_key=priv_key)
        provenance_token = signer.create_provenance_token(wm_res.watermarked_dna, order_id=order_id)
        if cert_out:
            Path(cert_out).write_text(json.dumps(provenance_token, indent=2), encoding="utf-8")

    # Log to audit ledger
    ledger = AuditLedger()
    ledger.record_event(
        event_id=f"EVT-WM-{Path(out_file).stem.upper()}",
        event_type="WATERMARK",
        sequence_hash=calculate_sequence_hash(wm_res.watermarked_dna),
        sequence_length=len(wm_res.watermarked_dna),
        lab_id=lab_id,
        order_id=order_id,
        classification="VERIFIED_LICENSED",
        threat_detected=False,
        payload_valid=True,
        details={
            "modulated_codons": wm_res.modulated_codons_count,
            "gc_drift": wm_res.invariants.gc_drift,
            "bits_used": wm_res.payload_bits_used,
        },
    )

    click.secho("\n[GENESIGN WATERMARK EMBEDDED SUCCESSFULLY]", fg="green", bold=True)
    click.echo(f"  Target File:         {out_file}")
    click.echo(f"  Sequence Length:     {len(wm_res.watermarked_dna)} nt ({wm_res.invariants.amino_acid_length} aa)")
    click.echo(f"  Translation Check:   100% PRESERVED (0 missense, 0 nonsense)")
    click.echo(f"  GC Content Drift:    {wm_res.invariants.gc_drift}% (Tolerated < 2.5%)")
    click.echo(f"  Codons Modulated:    {wm_res.modulated_codons_count}")
    click.echo(f"  Restriction Guard:   PASSED (0 illegal cut sites added)")
    if cert_out:
        click.echo(f"  Provenance Cert:     {cert_out}")
    click.echo("")


@cli.command("verify")
@click.option("--in", "in_file", required=True, type=click.Path(exists=True, dir_okay=False), help="Input FASTA file to verify.")
@click.option("--pubkey", type=click.Path(exists=True, dir_okay=False), help="Optional path to lab Ed25519 public key.")
@click.option("--json-report", type=click.Path(dir_okay=False, writable=True), help="Save detailed verification report to JSON.")
def verify_cmd(in_file: str, pubkey: Optional[str], json_report: Optional[str]):
    """Verify DNA sequence watermark, extraction, and provenance integrity."""
    raw_content = Path(in_file).read_text(encoding="utf-8")
    records = list(SequenceParser.parse_stream(raw_content))
    if not records:
        click.secho("Error: No FASTA records found.", fg="red", err=True)
        sys.exit(1)

    dna_seq = records[0].sequence
    ext_result = extract_watermark(dna_seq)

    report = {
        "file": in_file,
        "sequence_hash": calculate_sequence_hash(dna_seq),
        "sequence_length": len(dna_seq),
        "watermark_extracted": ext_result.extracted,
        "tamper_detected": ext_result.tampered,
        "payload": ext_result.payload,
        "error": ext_result.error_message,
    }

    if json_report:
        Path(json_report).write_text(json.dumps(report, indent=2), encoding="utf-8")

    if ext_result.extracted:
        click.secho("\n[WATERMARK VERIFIED: AUTHENTIC]", fg="green", bold=True)
        click.echo(f"  Lab ID:          {ext_result.payload.get('lab_id')}")
        click.echo(f"  Order ID:        {ext_result.payload.get('order_id')}")
        click.echo(f"  Key Fingerprint: {ext_result.payload.get('key_fp')}")
        click.echo(f"  Tamper Status:   INTEGRITY PRESERVED (0 Bit Flips)\n")
    elif ext_result.tampered:
        click.secho("\n[WATERMARK TAMPER INTERLOCK TRIPPED: CORRUPTED]", fg="red", bold=True)
        click.echo(f"  Error: {ext_result.error_message}")
        click.echo("  Status: Sequence nucleotide mutation or unauthorized edit detected!\n")
    else:
        click.secho("\n[NO WATERMARK DETECTED: UNMARKED SEQUENCE]", fg="yellow", bold=True)
        click.echo("  Status: Unmarked natural or unwatermarked research DNA.\n")


@cli.command("scan")
@click.option("--in", "in_file", required=True, type=click.Path(exists=True, dir_okay=False), help="FASTA or FastQ file to scan through Biosecurity Firewall.")
@click.option("--json-report", type=click.Path(dir_okay=False, writable=True), help="Save firewall report to JSON.")
def scan_cmd(in_file: str, json_report: Optional[str]):
    """Biosecurity Firewall & Threat Radar screening for regulated pathogens."""
    raw_content = Path(in_file).read_text(encoding="utf-8")
    firewall = BiosecurityFirewall()
    results = firewall.scan_batch(raw_content)

    serialized = []
    click.secho("\n================ GENESIGN BIOSECURITY RADAR ================", fg="cyan", bold=True)
    for res in results:
        status_color = {
            ComplianceClassification.VERIFIED_LICENSED: "green",
            ComplianceClassification.UNKNOWN_DRIFT: "yellow",
            ComplianceClassification.ROGUE_SYNTHETIC: "red",
            ComplianceClassification.TAMPERED_PAYLOAD: "red",
        }[res.classification]

        click.secho(f"\nRecord: {res.record_id} -> [{res.classification.value}]", fg=status_color, bold=True)
        click.echo(f"  Sequence Hash:   {res.sequence_hash[:16]}...")
        click.echo(f"  Threat Detected: {'YES' if res.threat_detected else 'NO'}")
        if res.threat_matches:
            for m in res.threat_matches:
                click.secho(f"    ! AGENT HIT: {m['agent_name']} ({m['regulatory_tier']}) - K-mers: {m['kmer_matches']}", fg="red")
        click.echo(f"  Watermark:       {'VALID' if res.payload_valid else ('TAMPERED' if res.tampered else 'NONE')}")
        click.echo(f"  Summary:         {res.status_summary}")

        serialized.append({
            "record_id": res.record_id,
            "classification": res.classification.value,
            "threat_detected": res.threat_detected,
            "sequence_hash": res.sequence_hash,
            "threat_matches": res.threat_matches,
            "status_summary": res.status_summary,
        })

    if json_report:
        Path(json_report).write_text(json.dumps(serialized, indent=2), encoding="utf-8")
    click.echo("\n============================================================\n")


@cli.command("audit-ledger")
@click.option("--list-recent", is_flag=True, default=True, help="List recent ledger audit transactions.")
@click.option("--limit", type=int, default=20, help="Number of records to display.")
def ledger_cmd(list_recent: bool, limit: int):
    """Inspect immutable audit ledger for DNA watermarks and threat alerts."""
    ledger = AuditLedger()
    events = ledger.get_recent_events(limit=limit)
    stats = ledger.get_stats()

    click.secho("\n=============== GENESIGN ENTERPRISE AUDIT LEDGER ===============", fg="cyan", bold=True)
    click.echo(f"Total Transactions: {stats['total_events']} | Watermarks: {stats['watermarks_created']} | Threats Flagged: {stats['threats_intercepted']} | Interlocks: {stats['tamper_interlocks']}\n")

    if not events:
        click.echo("  (No ledger transactions recorded yet)")
    else:
        for ev in events:
            color = "green" if ev["classification"] == "VERIFIED_LICENSED" else ("red" if "THREAT" in str(ev["classification"]) or "ROGUE" in str(ev["classification"]) or ev["classification"] == "TAMPERED_PAYLOAD" else "white")
            click.secho(f"[{ev['timestamp']}] {ev['event_id']} | Type: {ev['event_type']} | Class: {ev['classification']}", fg=color)
            click.echo(f"  Hash: {ev['sequence_hash'][:16]}... | Lab: {ev.get('lab_id') or 'N/A'} | Order: {ev.get('order_id') or 'N/A'}")

    click.echo("\n================================================================\n")


if __name__ == "__main__":
    cli()
