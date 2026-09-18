"""GeneSign NVIDIA Nemotron Biosecurity Threat Intelligence Engine.

Integrates configured NVIDIA Nemotron foundation models (e.g., nvidia/nemotron-3-ultra-550b-a55b
or nvidia/nemotron-4-340b-instruct) to generate executive risk assessments, regulatory
implications (US HHS 2026, ISO/TC 276, Select Agent Regulations), and operational mitigation
action plans when DNA sequence scans trigger UNKNOWN_DRIFT, TAMPERED_PAYLOAD, or ROGUE_SYNTHETIC.
"""

import os
import json
import time
import re
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


def _load_env_file(dotenv_path: Optional[Path] = None):
    """Zero-dependency .env loader for GeneSign."""
    if dotenv_path is None:
        dotenv_path = Path(__file__).resolve().parent.parent / ".env"
    if not dotenv_path.exists():
        # Fall back to parent or nemotron-adapter directory
        alt_path = Path(__file__).resolve().parent.parent.parent / "nemotron-adapter" / ".env"
        if alt_path.exists():
            dotenv_path = alt_path
        else:
            return

    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    if key and key not in os.environ:
                        os.environ[key] = val
    except Exception:
        pass


# Initialize environment on module load
_load_env_file()


class NemotronBiosecurityAdvisor:
    """Enterprise AI Biosecurity Advisor powered by NVIDIA Nemotron."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model_id: Optional[str] = None,
        provider: Optional[str] = None,
    ):
        # Refresh env if needed
        _load_env_file()

        self.provider = (provider or os.getenv("ACTIVE_PROVIDER", "openrouter")).lower()

        if self.provider == "nvidia":
            self.api_key = api_key if api_key is not None else os.getenv("NVIDIA_API_KEY", "")
            self.base_url = (base_url or os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")).rstrip("/")
            self.model_id = model_id or os.getenv("NVIDIA_MODEL", "nvidia/nemotron-4-340b-instruct")
        else:
            self.provider = "openrouter"
            self.api_key = api_key if api_key is not None else os.getenv("OPENROUTER_API_KEY", "")
            self.base_url = (base_url or os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")).rstrip("/")
            self.model_id = model_id or os.getenv("OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")

        self.endpoint = f"{self.base_url}/chat/completions"
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get_status(self) -> Dict[str, Any]:
        """Returns active adapter configuration and operational status."""
        return {
            "provider": self.provider,
            "model_id": self.model_id,
            "base_url": self.base_url,
            "has_api_key": bool(self.api_key),
            "endpoint": self.endpoint,
        }

    def analyze_threat_rationale(self, eval_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generates executive biosecurity risk rationale and regulatory directives using NVIDIA Nemotron.

        If network is unavailable or times out, seamlessly falls back to the deterministic
        GeneSign domain-expert biosecurity reasoning engine.
        """
        classification = eval_data.get("classification", "UNKNOWN_DRIFT").upper()
        record_id = eval_data.get("record_id", "SCAN-RECORD")
        seq_hash = eval_data.get("sequence_hash", "")
        cache_key = f"{classification}:{seq_hash}:{record_id}"

        if cache_key in self._cache:
            cached = dict(self._cache[cache_key])
            cached["cached"] = True
            return cached
        record_id = eval_data.get("record_id", "SCAN-RECORD")
        seq_len = eval_data.get("sequence_length", 0)
        gc = eval_data.get("gc_content", 0.0)
        threat_detected = eval_data.get("threat_detected", False)
        threat_tier = eval_data.get("highest_threat_tier", "NONE")
        threat_matches = eval_data.get("threat_matches", [])
        status_summary = eval_data.get("status_summary", "")
        lab_id = eval_data.get("lab_id")
        order_id = eval_data.get("order_id")

        start_time = time.time()

        # If no API key configured, use deterministic expert engine
        if not self.api_key:
            return self._generate_expert_fallback(eval_data, latency=0.01, is_fallback=True)

        system_prompt = (
            "You are NVIDIA Nemotron Biosecurity Intelligence, an elite autonomous biosecurity AI advisor "
            "embedded inside the GeneSign DNA Watermarking & Biosecurity Firewall Engine.\n"
            "Your role is to analyze synthetic DNA screening verdicts and produce concise, authoritative, "
            "executive risk assessments and regulatory directives for DNA synthesis foundry operators (e.g. Twist, IDT).\n"
            "Reference key statutory frameworks: US HHS Guidance for Providers of Synthetic Double-Stranded DNA (2026/2024), "
            "ISO/TC 276 Biotechnology Standards, Export Administration Regulations (EAR 15 CFR 774), and 42 CFR 73 Select Agents.\n\n"
            "You MUST respond ONLY with a valid JSON object formatted exactly as follows:\n"
            "{\n"
            '  "executive_summary": "2-3 sentence executive synopsis of the biological and operational risk.",\n'
            '  "regulatory_implications": "Key regulatory frameworks triggered and compliance obligations.",\n'
            '  "recommended_actions": [\n'
            '    "Action 1",\n'
            '    "Action 2",\n'
            '    "Action 3"\n'
            "  ],\n"
            '  "risk_score": <integer from 0 to 100>\n'
            "}\n"
            "Do NOT include conversational filler, markdown fences, or text outside the JSON object."
        )

        threat_summary_text = "None detected."
        if threat_matches:
            threat_summary_text = "; ".join(
                f"{m.get('agent_name', 'Unknown')} ({m.get('regulatory_tier', 'Select Agent')}, Gene: {m.get('target_gene', 'N/A')})"
                for m in threat_matches
            )

        user_prompt = (
            f"Generate an executive biosecurity risk rationale for the following DNA synthesis screening verdict:\n\n"
            f"- Record Identifier: {record_id}\n"
            f"- Firewall Classification: {classification}\n"
            f"- Sequence Length: {seq_len} bp\n"
            f"- GC Content: {gc}%\n"
            f"- Threat Detected: {threat_detected}\n"
            f"- Highest Threat Tier: {threat_tier}\n"
            f"- Identified Select Agent Matches: {threat_summary_text}\n"
            f"- Origin Lab ID: {lab_id or 'Unlicensed / Missing'}\n"
            f"- Commercial Order ID: {order_id or 'Missing'}\n"
            f"- Engine Status: {status_summary}\n\n"
            f"Contextual Guidance:\n"
            f"- UNKNOWN_DRIFT: Sequence lacks GeneSign cryptographic watermark. While non-hazardous, US HHS 2026 mandates customer due-diligence and benign confirmation.\n"
            f"- TAMPERED_PAYLOAD: Sequence contains carrier watermark preamble but CRC16 / Ed25519 signature desynchronized due to nucleotide mutation or intentional supply-chain tampering. Hardware dispatch must hold.\n"
            f"- ROGUE_SYNTHETIC: Unlicensed sequence matched dangerous pathogen or toxin (e.g., Ricin, Botulinum, Ebola). Triggers immediate E-STOP hardware lock and mandatory federal reporting.\n"
            f"- VERIFIED_LICENSED: Valid cryptographic signature and intact translation invariants. Clear for physical synthesis.\n\n"
            f"Return only the requested JSON object."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "GeneSign-Nemotron-Engine/2.2",
        }

        if "openrouter.ai" in self.base_url:
            headers["HTTP-Referer"] = "https://genesign.twistdna.com"
            headers["X-Title"] = "GeneSign Biosecurity Firewall"

        payload = {
            "model": self.model_id,
            "messages": messages,
            "temperature": 0.2,
            "max_tokens": 800,
        }

        try:
            req = urllib.request.Request(
                self.endpoint,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            # Timeout bounded at 8 seconds to prevent pipeline stalls and ensure rapid response
            with urllib.request.urlopen(req, timeout=8) as resp:
                latency = round(time.time() - start_time, 2)
                resp_bytes = resp.read()
                data = json.loads(resp_bytes.decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    raw_content = choices[0].get("message", {}).get("content", "").strip()
                    parsed = self._extract_json_payload(raw_content)
                    if parsed:
                        score = int(parsed.get("risk_score", self._default_risk_score(classification)))
                        if classification == "TAMPERED_PAYLOAD" and score < 70:
                            score = 86
                        elif classification == "ROGUE_SYNTHETIC" and score < 85:
                            score = 98
                        res = {
                            "success": True,
                            "model": self.model_id,
                            "provider": self.provider,
                            "classification": classification,
                            "risk_score": score,
                            "executive_summary": parsed.get("executive_summary", ""),
                            "regulatory_implications": parsed.get("regulatory_implications", ""),
                            "recommended_actions": parsed.get("recommended_actions", []),
                            "latency_seconds": latency,
                            "is_fallback": False,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                        self._cache[cache_key] = res
                        return res
        except Exception as e:
            # On transient network issues, seamlessly fallback to domain expert engine
            latency = round(time.time() - start_time, 2)
            res = self._generate_expert_fallback(eval_data, latency=latency, is_fallback=True, error_note=str(e))
            self._cache[cache_key] = res
            return res

        res = self._generate_expert_fallback(eval_data, latency=round(time.time() - start_time, 2), is_fallback=True)
        self._cache[cache_key] = res
        return res

    def _extract_json_payload(self, text: str) -> Optional[Dict[str, Any]]:
        """Cleans and extracts JSON object from raw LLM output text."""
        if not text:
            return None

        # Clean markdown code fences if present
        text = text.strip()
        if "```json" in text:
            match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
        elif "```" in text:
            match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        # Find first { and last }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_substr = text[start : end + 1]
            try:
                return json.loads(json_substr)
            except Exception:
                pass

        try:
            return json.loads(text)
        except Exception:
            return None

    def _default_risk_score(self, classification: str) -> int:
        mapping = {
            "VERIFIED_LICENSED": 5,
            "UNKNOWN_DRIFT": 42,
            "TAMPERED_PAYLOAD": 86,
            "ROGUE_SYNTHETIC": 99,
        }
        return mapping.get(classification, 50)

    def _generate_expert_fallback(
        self,
        eval_data: Dict[str, Any],
        latency: float = 0.02,
        is_fallback: bool = True,
        error_note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Domain-expert deterministic biosecurity reasoning generator for high-reliability fallback."""
        classification = eval_data.get("classification", "UNKNOWN_DRIFT").upper()
        record_id = eval_data.get("record_id", "SCAN-RECORD")
        seq_len = eval_data.get("sequence_length", 0)
        threat_matches = eval_data.get("threat_matches", [])

        if classification == "TAMPERED_PAYLOAD":
            risk_score = 88
            executive_summary = (
                f"High-severity cryptographic integrity failure detected on order '{record_id}'. "
                "The sequence possesses a valid GeneSign watermark preamble, but single-nucleotide "
                "degenerate codon mutations have caused CRC16 checksum desynchronization and Ed25519 signature "
                "rejection. This indicates active payload tampering, unauthorized post-licensing edits, or physical sequence corruption."
            )
            regulatory_implications = (
                "Under US HHS 2026 Guidance Section 4.1 (Chain-of-Custody & Sequence Integrity) and ISO/TC 276-4, "
                "DNA synthesis providers are strictly prohibited from dispensing orders with invalidated provenance tokens. "
                "The digital order must be quarantined pending cryptographic re-issuance."
            )
            recommended_actions = [
                "Engage hardware synthesis interlock latch (LOCK_VALVES) to halt physical dispensing immediately.",
                "Quarantine order record and notify the submitting lab compliance officer.",
                "Execute bit-flip difference analysis to isolate the exact mutated wobble codon coordinates.",
                "Require the customer to re-sign and submit the pristine provenance certificate before unlocking synthesis.",
            ]

        elif classification == "UNKNOWN_DRIFT":
            risk_score = 42
            executive_summary = (
                f"Sequence '{record_id}' ({seq_len} nt) is clean of Tier-1 select agent k-mers, but lacks an "
                "authorized GeneSign cryptographic watermark. While currently evaluated as biologically benign, "
                "unwatermarked double-stranded synthetic constructs represent unverified origin provenance."
            )
            regulatory_implications = (
                "US HHS 2026 Provider Guidance Section 2 mandates comprehensive customer identity verification "
                "and end-use validation for all unwatermarked custom gene synthesis orders exceeding 200 base pairs, "
                "even in the absence of explicit select agent matches."
            )
            recommended_actions = [
                "Verify customer identity and accredited institutional affiliation (Know-Your-Customer / KYC).",
                "Log sequence SHA-256 into the append-only Merkle ledger for cross-provider assembly monitoring.",
                "Encourage customer to inject a GeneSign zero-drift synonymous watermark before physical production.",
                "Proceed with synthesis only after institutional validation and benign dual-use clearance.",
            ]

        elif classification == "ROGUE_SYNTHETIC":
            risk_score = 99
            threat_names = ", ".join(m.get("agent_name", "Select Agent") for m in threat_matches) or "Restricted Pathogen"
            executive_summary = (
                f"CRITICAL BIOSECURITY INCIDENT: Order '{record_id}' contains unlicensed synthetic DNA "
                f"matching controlled Tier-1 biological threat agents ({threat_names}). The construct lacks valid "
                "government authorization or cryptographic license provenance."
            )
            regulatory_implications = (
                "Violates 42 CFR Part 73 (Federal Select Agent Program) and Export Administration Regulations (EAR ECCN 1C351). "
                "Federal law mandates immediate emergency refusal to synthesize and statutory notification to the "
                "FBI Weapons of Mass Destruction (WMD) Directorate and CDC Select Agent Program within 24 hours."
            )
            recommended_actions = [
                "Trigger immediate Physical Synthesizer E-STOP and lock all phosphoramidite dispensing manifolds.",
                "Isolate all order metadata, customer IP address, and financial routing information.",
                "Transmit encrypted biosecurity incident manifest to the FBI WMD Coordinator and CDC FSAP.",
                "Blacklist customer account and public key across the global synthesis provider federated CRL.",
            ]

        else:  # VERIFIED_LICENSED
            risk_score = 5
            executive_summary = (
                f"Sequence '{record_id}' has been successfully validated with active GeneSign cryptographic provenance. "
                "All biological invariants are 100.0% preserved, third-base wobble watermarks match the registered Ed25519 signature, "
                "and zero restricted pathogen motifs were detected."
            )
            regulatory_implications = (
                "Complies with US HHS 2026 Guidance for Providers of Synthetic Double-Stranded DNA and ISO/TC 276. "
                "Cryptographic receipt fulfills federal audit trail requirements."
            )
            recommended_actions = [
                "Authorize physical synthesis valve release via OPC-UA / REST hardware controller.",
                "Mint immutable Merkle tree inclusion proof and append transaction to SQLite WAL ledger.",
                "Issue white-label signed vector PDF compliance certificate for order shipment.",
            ]

        return {
            "success": True,
            "model": self.model_id,
            "provider": self.provider,
            "classification": classification,
            "risk_score": risk_score,
            "executive_summary": executive_summary,
            "regulatory_implications": regulatory_implications,
            "recommended_actions": recommended_actions,
            "latency_seconds": latency,
            "is_fallback": is_fallback,
            "fallback_reason": error_note,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global singleton instance
nemotron_advisor = NemotronBiosecurityAdvisor()
