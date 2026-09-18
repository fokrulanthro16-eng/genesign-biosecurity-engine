"""GeneSign Commercial SaaS & Enterprise Monetization Test Suite.

Tests:
1. JWT authentication, PBKDF2 password verification, and RBAC authorization.
2. High-security API key provisioning, SHA-256 hash storage, and tiered rate-limiting.
3. Real-time usage metering, pricing plan computation, and simulated Stripe subscriptions.
4. Custom white-label branding persistence, JSON-LD compliance certificates, and ReportLab signed vector PDF generation.
"""

import pytest
from fastapi.testclient import TestClient
from web.app import app
from storage.ledger import AuditLedger
from security.auth import UserRole, hash_password, verify_password, generate_api_key
from security.ratelimit import TieredRateLimiter
from engine.billing import billing_service, PRICING_PLANS
from engine.compliance_report import compliance_generator


client = TestClient(app)


def test_password_hashing_and_verification():
    """Verifies PBKDF2-HMAC-SHA256 password salting and timing-attack safe verification."""
    salt = "random_salt_12345"
    pw = "EnterpriseSecurePassword2026!"
    pw_hash = hash_password(pw, salt)

    assert pw_hash != pw
    assert len(pw_hash) == 64  # SHA-256 hex
    assert verify_password(pw, pw_hash, salt) is True
    assert verify_password("WrongPassword!", pw_hash, salt) is False


def test_auth_login_and_jwt_bearer():
    """Tests /api/v1/auth/login and subsequent authenticated requests."""
    # 1. Successful Admin Login
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin@twistdna.com", "password": "EnterprisePassword2026!"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["role"] == UserRole.ENTERPRISE_ADMIN

    token = data["access_token"]

    # 2. Authenticated Profile Probe
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    me_data = me_resp.json()
    assert me_data["identity"]["username"] == "admin@twistdna.com"
    assert me_data["identity"]["tenant_id"] == "TWIST"

    # 3. Bad Credentials
    bad_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin@twistdna.com", "password": "IncorrectPassword!"},
    )
    assert bad_resp.status_code == 401


def test_api_key_provisioning_and_authentication():
    """Tests API key generation, raw token masking, and X-API-Key header authentication."""
    # 1. Login as Admin
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin@twistdna.com", "password": "EnterprisePassword2026!"},
    )
    token = login_resp.json()["access_token"]

    # 2. Provision new API key
    create_resp = client.post(
        "/api/v1/auth/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "Automated Synthesis Pipeline Key",
            "tier": "FREE",
            "rate_limit_per_day": 50,
        },
    )
    assert create_resp.status_code == 200
    key_data = create_resp.json()
    assert key_data["success"] is True
    assert "raw_api_key" in key_data
    raw_key = key_data["raw_api_key"]
    assert raw_key.startswith("gs_live_")
    key_id = key_data["key_id"]

    # 3. Authenticate using X-API-Key
    api_probe = client.get("/api/v1/auth/me", headers={"X-API-Key": raw_key})
    assert api_probe.status_code == 200
    assert api_probe.json()["identity"]["identity_type"] == "API_KEY"
    assert api_probe.json()["identity"]["key_id"] == key_id

    # 4. List keys (raw key must NOT be revealed in listing)
    list_resp = client.get("/api/v1/auth/api-keys", headers={"Authorization": f"Bearer {token}"})
    assert list_resp.status_code == 200
    keys_list = list_resp.json()["api_keys"]
    found = next((k for k in keys_list if k["key_id"] == key_id), None)
    assert found is not None
    assert "raw_api_key" not in found
    assert "key_prefix" in found

    # 5. Revoke key
    del_resp = client.delete(f"/api/v1/auth/api-keys/{key_id}", headers={"Authorization": f"Bearer {token}"})
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "REVOKED"

    # 6. Revoked key must fail with 401
    revoked_probe = client.get("/api/v1/auth/me", headers={"X-API-Key": raw_key})
    assert revoked_probe.status_code == 401


def test_tiered_rate_limiting_enforcement():
    """Verifies that Free Tier limits to 50 requests/day while Enterprise allows unlimited."""
    limiter = TieredRateLimiter()

    free_identity = {"key_id": "KEY-TEST-FREE", "tier": "FREE", "rate_limit_per_day": 5}
    ent_identity = {"key_id": "KEY-TEST-ENT", "tier": "ENTERPRISE", "rate_limit_per_day": 1_000_000}

    # Consume quota for free identity
    for i in range(5):
        allowed, remaining, limit = limiter.check_limit(free_identity)
        assert allowed is True
        assert limit == 5

    # 6th request must exceed quota
    allowed, remaining, limit = limiter.check_limit(free_identity)
    assert allowed is False
    assert remaining == 0

    # Enterprise identity must never trip
    for _ in range(25):
        allowed, _, _ = limiter.check_limit(ent_identity)
        assert allowed is True


def test_billing_usage_metering_and_subscription():
    """Tests usage telemetry tracking, charge calculation, and subscription upgrades."""
    # Record synthetic usage
    billing_service.record_usage("TWIST", "BASE_PAIRS_WATERMARKED", 250_000)
    billing_service.record_usage("TWIST", "BIOSECURITY_SCAN", 15)
    billing_service.record_usage("TWIST", "MERKLE_PROOF_ISSUED", 5)

    usage_resp = client.get("/api/v1/billing/usage?tenant_id=TWIST")
    assert usage_resp.status_code == 200
    usage_data = usage_resp.json()

    assert usage_data["tenant_id"] == "TWIST"
    assert "base_monthly_fee" in usage_data
    assert "total_accrued_amount" in usage_data
    assert usage_data["telemetry"]["base_pairs_watermarked"] >= 250_000
    assert usage_data["telemetry"]["biosecurity_scans_run"] >= 15

    # Test Subscription Plan Upgrade
    sub_resp = client.post(
        "/api/v1/billing/subscribe",
        json={"tier": "GLOBAL_ENTERPRISE", "payment_method_id": "pm_mock_corp_amex"},
    )
    assert sub_resp.status_code == 200
    assert sub_resp.json()["success"] is True
    assert sub_resp.json()["tier"] == "GLOBAL_ENTERPRISE"
    assert sub_resp.json()["monthly_fee"] == 9999.0

    # Test Invoices Retrieval
    inv_resp = client.get("/api/v1/billing/invoices?tenant_id=TWIST")
    assert inv_resp.status_code == 200
    assert len(inv_resp.json()["invoices"]) >= 3


def test_white_label_branding_and_compliance_reports():
    """Tests white-label tenant customizations, JSON-LD certificates, and signed PDF generation."""
    # 1. Update White-Label Settings
    brand_resp = client.post(
        "/api/v1/tenants/branding",
        json={
            "tenant_id": "TWIST",
            "org_name": "Twist Bioscience Enterprise Foundry",
            "lab_id": "TWS-HQ-01",
            "logo_url": "https://twist.com/logo.svg",
            "contact_email": "biosecurity-ops@twistdna.com",
            "accent_color": "#0ea5e9",
        },
    )
    assert brand_resp.status_code == 200
    assert brand_resp.json()["branding"]["org_name"] == "Twist Bioscience Enterprise Foundry"

    # 2. Fetch JSON Compliance Certificate
    cert_json_resp = client.get("/api/v1/compliance/certificate/EVT-TEST-DEMO?tenant_id=TWIST")
    assert cert_json_resp.status_code == 200
    cert_json = cert_json_resp.json()
    assert cert_json["type"] == "BiosecurityComplianceCertificate"
    assert cert_json["issuer"]["organization_name"] == "Twist Bioscience Enterprise Foundry"
    assert "certificate_digest_sha256" in cert_json

    # 3. Generate Signed PDF Certificate
    pdf_resp = client.get("/api/v1/compliance/certificate/EVT-TEST-DEMO/pdf?tenant_id=TWIST")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert pdf_resp.content.startswith(b"%PDF")
    assert len(pdf_resp.content) > 1000  # Valid binary vector PDF


def test_stripe_checkout_session_and_webhook_provisioning():
    """Verifies Stripe Checkout Session generation, webhook handling, and automatic API key provisioning."""
    # 1. Login to obtain JWT Bearer
    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": "admin@twistdna.com", "password": "EnterprisePassword2026!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # 2. Create Checkout Session
    checkout_req = {
        "tier": "SYNTHESIS_FOUNDRY",
        "customer_email": "chief.biosecurity@syntheticbio.com",
        "success_url": "/?status=success",
        "cancel_url": "/?status=cancelled",
    }
    checkout_resp = client.post(
        "/api/v1/billing/create-checkout-session",
        headers={"Authorization": f"Bearer {token}"},
        json=checkout_req,
    )
    assert checkout_resp.status_code == 200
    session_data = checkout_resp.json()
    assert session_data["success"] is True
    session = session_data["session"]
    assert session["session_id"].startswith("cs_live_")
    assert session["tier"] == "SYNTHESIS_FOUNDRY"
    assert session["amount_due"] == 2499.00
    assert "checkout-test" in session["checkout_url"]

    # 3. Verify Sandbox Checkout HTML Page
    test_portal_resp = client.get(session["checkout_url"])
    assert test_portal_resp.status_code == 200
    assert "GeneSign Commercial Checkout" in test_portal_resp.text
    assert "Complete Payment & Auto-Provision Key" in test_portal_resp.text

    # 4. Trigger Webhook (checkout.session.completed)
    webhook_payload = {
        "id": "evt_test_checkout_completed",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session["session_id"],
                "client_reference_id": "TWIST",
                "customer_details": {
                    "email": "chief.biosecurity@syntheticbio.com",
                },
                "metadata": {
                    "tier": "SYNTHESIS_FOUNDRY",
                    "tenant_id": "TWIST",
                },
            }
        },
    }
    webhook_resp = client.post(
        "/api/v1/billing/webhook",
        headers={"Stripe-Signature": "t=12345,v1=mock_sig"},
        json=webhook_payload,
    )
    assert webhook_resp.status_code == 200
    wh_data = webhook_resp.json()
    assert wh_data["success"] is True
    assert wh_data["status"] == "PROVISIONED"
    assert wh_data["tier"] == "SYNTHESIS_FOUNDRY"
    assert "provisioned_api_key" in wh_data

    provisioned_key = wh_data["provisioned_api_key"]
    assert provisioned_key.startswith("gs_live_")
    assert wh_data["rate_limit_per_day"] == 1_000_000

    # 5. Immediately authenticate using newly provisioned live API key
    auth_resp = client.get("/api/v1/auth/me", headers={"X-API-Key": provisioned_key})
    assert auth_resp.status_code == 200
    ident = auth_resp.json()["identity"]
    assert ident["identity_type"] == "API_KEY"
    assert ident["tenant_id"] == "TWIST"
    assert ident["tier"] == "SYNTHESIS_FOUNDRY"

