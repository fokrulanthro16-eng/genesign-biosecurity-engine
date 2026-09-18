"""GeneSign Automated Billing & Usage Metering Engine.

Tracks real-time commercial telemetry for DNA synthesis providers:
- Base pairs watermarked ($0.0005 / bp)
- Biosecurity scans executed ($0.002 / scan)
- RFC-3161 Merkle audit proofs issued ($0.05 / proof)
- Hardware synthesis interlock dispatches ($0.10 / dispatch)
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import uuid
import hashlib

from storage.ledger import AuditLedger, DEFAULT_DB_PATH


# Commercial Pricing Matrix
PRICING_PLANS = {
    "FREE": {
        "name": "Community / Academic Free Tier",
        "base_fee_monthly": 0.0,
        "included_base_pairs": 5_000,
        "overage_per_bp": 0.0010,
        "per_scan_rate": 0.005,
        "per_merkle_proof": 0.10,
        "per_hardware_dispatch": 0.25,
        "features": ["50 requests / day", "Standard FASTA Watermarking", "Community Support"],
    },
    "STARTUP_LAB": {
        "name": "Startup Lab Plan",
        "base_fee_monthly": 499.0,
        "included_base_pairs": 100_000,
        "overage_per_bp": 0.0005,
        "per_scan_rate": 0.002,
        "per_merkle_proof": 0.05,
        "per_hardware_dispatch": 0.10,
        "features": ["10,000 requests / day", "Batch FASTQ Stream Screening", "Standard US HHS Certificate", "Email SLA (48h)"],
    },
    "SYNTHESIS_FOUNDRY": {
        "name": "Synthesis Foundry Plan",
        "base_fee_monthly": 2499.0,
        "included_base_pairs": 2_500_000,
        "overage_per_bp": 0.0003,
        "per_scan_rate": 0.001,
        "per_merkle_proof": 0.02,
        "per_hardware_dispatch": 0.05,
        "features": ["Unlimited API Keys", "OPC-UA Hardware Safety Interlock", "White-Label Vector PDF Certificates", "99.9% Uptime SLA"],
    },
    "GLOBAL_ENTERPRISE": {
        "name": "Global Biosecurity Network",
        "base_fee_monthly": 9999.0,
        "included_base_pairs": 20_000_000,
        "overage_per_bp": 0.0001,
        "per_scan_rate": 0.0005,
        "per_merkle_proof": 0.01,
        "per_hardware_dispatch": 0.02,
        "features": ["Dedicated HSM Signer Integration", "Cross-Foundry Graph Assembler", "Custom ISO/TC 276 Audit Framework", "24/7 Dedicated Biosecurity Officer"],
    },
}


class BillingService:
    """Manages telemetry consumption, billing cycles, and Stripe invoice simulation."""

    def __init__(self, db: Optional[AuditLedger] = None):
        self.db = db or AuditLedger(DEFAULT_DB_PATH)

    def record_usage(self, tenant_id: str, event_type: str, units: int = 1) -> None:
        """Records a consumption event (e.g. BP_WATERMARKED, SCAN_RUN, MERKLE_PROOF)."""
        tenant = tenant_id or "TWIST"
        self.db.record_usage(tenant, event_type, units)

    def get_billing_usage(self, tenant_id: str) -> Dict[str, Any]:
        """Calculates current period telemetry and accrued charges."""
        tenant = tenant_id or "TWIST"
        sub = self.db.get_tenant_subscription(tenant)
        tier_key = sub.get("tier", "STARTUP_LAB").upper()
        if tier_key not in PRICING_PLANS:
            tier_key = "STARTUP_LAB"

        plan = PRICING_PLANS[tier_key]
        usage = self.db.get_usage_summary(tenant)

        # Extracted metered units
        bp_watermarked = usage.get("BASE_PAIRS_WATERMARKED", 0)
        scans_run = usage.get("BIOSECURITY_SCAN", 0)
        merkle_proofs = usage.get("MERKLE_PROOF_ISSUED", 0)
        hardware_runs = usage.get("HARDWARE_DISPATCH", 0)

        # Compute charges
        base_fee = plan["base_fee_monthly"]
        included_bp = plan["included_base_pairs"]
        billable_bp = max(0, bp_watermarked - included_bp)
        bp_cost = billable_bp * plan["overage_per_bp"]
        scan_cost = scans_run * plan["per_scan_rate"]
        merkle_cost = merkle_proofs * plan["per_merkle_proof"]
        hw_cost = hardware_runs * plan["per_hardware_dispatch"]

        total_accrued = base_fee + bp_cost + scan_cost + merkle_cost + hw_cost

        now = datetime.now(timezone.utc)
        billing_period_start = now.replace(day=1, hour=0, minute=0, second=0).isoformat()
        next_month = (now.replace(day=28) + timedelta(days=4)).replace(day=1)
        billing_period_end = next_month.isoformat()

        return {
            "tenant_id": tenant,
            "subscription_tier": tier_key,
            "plan_name": plan["name"],
            "currency": "USD",
            "billing_period": {
                "start": billing_period_start,
                "end": billing_period_end,
            },
            "base_monthly_fee": round(base_fee, 2),
            "telemetry": {
                "base_pairs_watermarked": bp_watermarked,
                "included_base_pairs": included_bp,
                "billable_base_pairs": billable_bp,
                "biosecurity_scans_run": scans_run,
                "merkle_proofs_issued": merkle_proofs,
                "hardware_dispatches": hardware_runs,
            },
            "itemized_charges": {
                "subscription_base": round(base_fee, 2),
                "base_pair_throughput": round(bp_cost, 4),
                "scan_screenings": round(scan_cost, 4),
                "merkle_compliance_proofs": round(merkle_cost, 4),
                "hardware_interlocks": round(hw_cost, 4),
            },
            "total_accrued_amount": round(total_accrued, 2),
            "payment_status": "CURRENT_PERIOD_UNBILLED",
        }

    def subscribe_tier(self, tenant_id: str, new_tier: str, payment_method_id: Optional[str] = None) -> Dict[str, Any]:
        """Simulates Stripe checkout and plan modification."""
        tenant = tenant_id or "TWIST"
        tier_key = new_tier.upper()
        if tier_key not in PRICING_PLANS:
            raise ValueError(f"Unknown pricing tier: {new_tier}. Available: {list(PRICING_PLANS.keys())}")

        self.db.update_tenant_subscription(tenant, tier_key)
        plan = PRICING_PLANS[tier_key]

        return {
            "success": True,
            "tenant_id": tenant,
            "tier": tier_key,
            "plan_name": plan["name"],
            "monthly_fee": plan["base_fee_monthly"],
            "stripe_subscription_id": f"sub_live_mock_{uuid.uuid4().hex[:12]}",
            "stripe_customer_id": f"cus_mock_{tenant.lower()}_{uuid.uuid4().hex[:8]}",
            "effective_date": datetime.now(timezone.utc).isoformat(),
            "message": f"Successfully activated subscription to {plan['name']}",
        }

    def get_invoices(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Retrieves itemized invoices (past and current)."""
        current_usage = self.get_billing_usage(tenant_id)
        current_amount = current_usage["total_accrued_amount"]

        # Synthetic historical invoices for realistic enterprise experience
        past_invoice_1 = {
            "invoice_id": "INV-2026-08-TWIST",
            "date": "2026-08-31T23:59:59Z",
            "amount_due": 2584.20,
            "currency": "USD",
            "status": "PAID",
            "tier": current_usage["subscription_tier"],
            "throughput_bp": 2_780_500,
            "stripe_charge_id": "ch_mock_3N01aZb",
            "receipt_url": f"/api/v1/billing/invoices/INV-2026-08-TWIST/pdf",
        }
        past_invoice_2 = {
            "invoice_id": "INV-2026-07-TWIST",
            "date": "2026-07-31T23:59:59Z",
            "amount_due": 2499.00,
            "currency": "USD",
            "status": "PAID",
            "tier": current_usage["subscription_tier"],
            "throughput_bp": 2_110_000,
            "stripe_charge_id": "ch_mock_2M99cXe",
            "receipt_url": f"/api/v1/billing/invoices/INV-2026-07-TWIST/pdf",
        }

        current_invoice = {
            "invoice_id": f"INV-{datetime.now(timezone.utc).strftime('%Y-%m')}-{tenant_id or 'TWIST'}",
            "date": datetime.now(timezone.utc).isoformat(),
            "amount_due": current_amount,
            "currency": "USD",
            "status": "OPEN",
            "tier": current_usage["subscription_tier"],
            "throughput_bp": current_usage["telemetry"]["base_pairs_watermarked"],
            "stripe_charge_id": None,
            "receipt_url": None,
        }

        return [current_invoice, past_invoice_1, past_invoice_2]

    def create_checkout_session(
        self,
        tenant_id: str,
        tier: str,
        customer_email: Optional[str] = None,
        success_url: Optional[str] = None,
        cancel_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Creates a Stripe Checkout Session for subscription tier provisioning."""
        tier_key = tier.upper()
        if tier_key not in PRICING_PLANS:
            tier_key = "SYNTHESIS_FOUNDRY"

        plan = PRICING_PLANS[tier_key]
        session_id = f"cs_live_{uuid.uuid4().hex[:20]}"
        customer_id = f"cus_{uuid.uuid4().hex[:14]}"

        # Test/Production checkout URL
        checkout_url = f"/api/v1/billing/checkout-test?session_id={session_id}&tier={tier_key}&tenant={tenant_id}&email={customer_email or 'executive@twistdna.com'}"

        session_record = {
            "session_id": session_id,
            "customer_id": customer_id,
            "tenant_id": tenant_id,
            "customer_email": customer_email or f"billing@{tenant_id.lower()}.com",
            "tier": tier_key,
            "amount_due": plan["base_fee_monthly"],
            "currency": "usd",
            "plan_name": plan["name"],
            "checkout_url": checkout_url,
            "success_url": success_url or "/?checkout=success",
            "cancel_url": cancel_url or "/?checkout=cancelled",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        return session_record

    def process_webhook(self, payload: Dict[str, Any], signature: Optional[str] = None) -> Dict[str, Any]:
        """Processes Stripe checkout.session.completed webhooks and auto-provisions API credentials."""
        from security.auth import generate_api_key

        event_type = payload.get("type", "checkout.session.completed")
        data_obj = payload.get("data", {}).get("object", {})

        tenant_id = (
            data_obj.get("client_reference_id")
            or data_obj.get("metadata", {}).get("tenant_id")
            or payload.get("tenant_id")
            or "TWIST"
        )
        tier = (
            data_obj.get("metadata", {}).get("tier")
            or payload.get("tier")
            or "SYNTHESIS_FOUNDRY"
        ).upper()

        if tier not in PRICING_PLANS:
            tier = "SYNTHESIS_FOUNDRY"

        customer_email = (
            data_obj.get("customer_details", {}).get("email")
            or payload.get("customer_email")
            or f"billing@{tenant_id.lower()}.com"
        )

        # 1. Update Tenant Subscription
        self.db.update_tenant_subscription(tenant_id, tier)

        # 2. Automatically Provision Production API Key
        raw_key, key_hash = generate_api_key(prefix="gs_live")
        key_id = f"KEY-PROD-{uuid.uuid4().hex[:8].upper()}"

        rate_limit = 10_000 if tier in ["STARTUP", "STARTUP_LAB"] else 1_000_000
        prefix_display = raw_key[:12] + "..." + raw_key[-4:]

        self.db.create_api_key(
            key_id=key_id,
            tenant_id=tenant_id,
            name=f"{PRICING_PLANS[tier]['name']} Key",
            key_prefix=prefix_display,
            key_hash=key_hash,
            tier=tier,
            rate_limit_per_day=rate_limit,
        )

        # 3. Record Audit Trail Event
        evt_id = f"EVT-BILL-{uuid.uuid4().hex[:8].upper()}"
        self.db.record_event(
            event_id=evt_id,
            event_type="SUBSCRIPTION_PROVISIONED",
            sequence_hash=hashlib.sha256(key_id.encode()).hexdigest(),
            sequence_length=0,
            lab_id=tenant_id,
            order_id="STRIPE-LIVE-CHECKOUT",
            classification="VERIFIED_LICENSED",
            threat_detected=False,
            payload_valid=True,
            details={
                "tier": tier,
                "customer_email": customer_email,
                "key_id": key_id,
                "monthly_fee": PRICING_PLANS[tier]["base_fee_monthly"],
            },
        )

        return {
            "success": True,
            "status": "PROVISIONED",
            "event": event_type,
            "tenant_id": tenant_id,
            "tier": tier,
            "plan_name": PRICING_PLANS[tier]["name"],
            "customer_email": customer_email,
            "provisioned_api_key": raw_key,
            "key_id": key_id,
            "key_prefix": prefix_display,
            "rate_limit_per_day": rate_limit,
            "message": f"Successfully activated {PRICING_PLANS[tier]['name']}. Production API credentials provisioned.",
        }


# Global singleton billing instance
billing_service = BillingService()

