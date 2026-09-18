"""GeneSign Persistent Cryptographic Audit Ledger.

Records all watermarking, verification, and biosecurity firewall events
in an append-only SQLite database with WAL mode enabled.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any


DEFAULT_DB_PATH = Path(__file__).resolve().parent / "ledger.db"


class AuditLedger:
    """Enterprise SQLite ledger for biosecurity and watermarking compliance."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    lab_id TEXT,
                    order_id TEXT,
                    sequence_hash TEXT NOT NULL,
                    sequence_length INTEGER,
                    classification TEXT,
                    threat_detected BOOLEAN,
                    payload_valid BOOLEAN,
                    details_json TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_seq_hash ON audit_events(sequence_hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp);")

            # Commercial SaaS Schemas
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT UNIQUE NOT NULL,
                    tenant_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT UNIQUE NOT NULL,
                    tier TEXT NOT NULL DEFAULT 'FREE',
                    rate_limit_per_day INTEGER NOT NULL DEFAULT 50,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    last_used_at TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_key_hash ON api_keys(key_hash);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    units INTEGER NOT NULL,
                    timestamp TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_tenant ON usage_records(tenant_id);")

            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_branding (
                    tenant_id TEXT PRIMARY KEY,
                    org_name TEXT NOT NULL,
                    lab_id TEXT NOT NULL,
                    logo_url TEXT,
                    contact_email TEXT,
                    accent_color TEXT DEFAULT '#ff6b4a',
                    updated_at TEXT NOT NULL
                );
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenant_subscriptions (
                    tenant_id TEXT PRIMARY KEY,
                    tier TEXT NOT NULL DEFAULT 'STARTUP',
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    billing_cycle TEXT NOT NULL DEFAULT 'MONTHLY',
                    current_period_start TEXT NOT NULL,
                    current_period_end TEXT NOT NULL
                );
            """)
            conn.commit()

        # Seed defaults
        self._seed_commercial_defaults()

    def record_event(
        self,
        event_id: str,
        event_type: str,
        sequence_hash: str,
        sequence_length: int,
        lab_id: Optional[str] = None,
        order_id: Optional[str] = None,
        classification: Optional[str] = None,
        threat_detected: bool = False,
        payload_valid: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Records a new compliance event into the audit ledger."""
        timestamp = datetime.now(timezone.utc).isoformat()
        details_str = json.dumps(details or {}, default=str)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, event_type, lab_id, order_id,
                    sequence_hash, sequence_length, classification,
                    threat_detected, payload_valid, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    timestamp,
                    event_type,
                    lab_id,
                    order_id,
                    sequence_hash,
                    sequence_length,
                    classification,
                    1 if threat_detected else 0,
                    1 if payload_valid else 0,
                    details_str,
                ),
            )
            conn.commit()

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "sequence_hash": sequence_hash,
            "classification": classification,
        }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent audit events sorted by timestamp descending."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, event_id, timestamp, event_type, lab_id, order_id,
                       sequence_hash, sequence_length, classification,
                       threat_detected, payload_valid, details_json
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                item["threat_detected"] = bool(item["threat_detected"])
                item["payload_valid"] = bool(item["payload_valid"])
                try:
                    item["details"] = json.loads(item["details_json"])
                except Exception:
                    item["details"] = {}
                results.append(item)
            return results

    def get_stats(self) -> Dict[str, Any]:
        """Retrieves aggregated statistics for the biosecurity radar."""
        with self._get_connection() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM audit_events;").fetchone()[0]
            watermarks_created = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event_type = 'WATERMARK';"
            ).fetchone()[0]
            threats_intercepted = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE threat_detected = 1;"
            ).fetchone()[0]
            tamper_interlocks = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE classification = 'TAMPERED_PAYLOAD';"
            ).fetchone()[0]

            return {
                "total_events": total_events,
                "watermarks_created": watermarks_created,
                "threats_intercepted": threats_intercepted,
                "tamper_interlocks": tamper_interlocks,
            }

    # -----------------------------------------------------------------------
    # Commercial SaaS Database Operations
    # -----------------------------------------------------------------------
    def _seed_commercial_defaults(self) -> None:
        """Seeds initial commercial tenants, default accounts, and API keys."""
        import hashlib
        now = datetime.now(timezone.utc).isoformat()

        def hash_pw(pw: str, salt: str) -> str:
            return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100_000).hex()

        def hash_key(k: str) -> str:
            return hashlib.sha256(k.encode()).hexdigest()

        with self._get_connection() as conn:
            # Check if users already exist
            user_count = conn.execute("SELECT COUNT(*) FROM users;").fetchone()[0]
            if user_count == 0:
                defaults = [
                    ("admin@twistdna.com", "EnterprisePassword2026!", "salt_admin_twist", "TWIST", "ENTERPRISE_ADMIN"),
                    ("tech@twistdna.com", "LabTechnician2026!", "salt_tech_twist", "TWIST", "LAB_TECHNICIAN"),
                    ("auditor@biosecurity.gov", "ComplianceAuditor2026!", "salt_audit_gov", "TWIST", "COMPLIANCE_AUDITOR"),
                ]
                for uname, pw, salt, tenant, role in defaults:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, salt, tenant_id, role, created_at) VALUES (?, ?, ?, ?, ?, ?);",
                        (uname, hash_pw(pw, salt), salt, tenant, role, now)
                    )

            # Check if API keys exist
            key_count = conn.execute("SELECT COUNT(*) FROM api_keys;").fetchone()[0]
            if key_count == 0:
                demo_keys = [
                    ("KEY-TWIST-PROD-01", "TWIST", "Twist Foundry Production Key", "gs_live_twist_enterprise_key_99", "ENTERPRISE", 1_000_000),
                    ("KEY-DEV-SANDBOX-02", "TWIST", "Developer Sandbox Key (Free Tier)", "gs_test_freemium_sample_key_01", "FREE", 50),
                ]
                for kid, tenant, name, raw_k, tier, limit in demo_keys:
                    prefix = raw_k[:12] + "..."
                    conn.execute(
                        """
                        INSERT INTO api_keys (
                            key_id, tenant_id, name, key_prefix, key_hash, tier,
                            rate_limit_per_day, created_at, is_active
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1);
                        """,
                        (kid, tenant, name, prefix, hash_key(raw_k), tier, limit, now)
                    )

            # Check if Tenant branding exists
            brand_count = conn.execute("SELECT COUNT(*) FROM tenant_branding;").fetchone()[0]
            if brand_count == 0:
                brands = [
                    ("TWIST", "Twist Bioscience Corporation", "TWS-SFO-01", "https://twistbioscience.com/logo.svg", "compliance@twistbioscience.com", "#ff6b4a"),
                    ("GINKGO", "Ginkgo Bioworks Automated Foundry", "GNK-BOS-02", "https://ginkgobioworks.com/logo.svg", "security@ginkgobioworks.com", "#10b981"),
                    ("IDT", "Integrated DNA Technologies", "IDT-COR-03", "https://idtdna.com/logo.svg", "biosecurity@idtdna.com", "#38bdf8"),
                ]
                for tid, oname, lid, logo, email, accent in brands:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO tenant_branding (
                            tenant_id, org_name, lab_id, logo_url, contact_email, accent_color, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                        """,
                        (tid, oname, lid, logo, email, accent, now)
                    )

            # Check if Subscriptions exist
            sub_count = conn.execute("SELECT COUNT(*) FROM tenant_subscriptions;").fetchone()[0]
            if sub_count == 0:
                subs = [
                    ("TWIST", "SYNTHESIS_FOUNDRY", "ACTIVE"),
                    ("GINKGO", "GLOBAL_ENTERPRISE", "ACTIVE"),
                    ("IDT", "STARTUP_LAB", "ACTIVE"),
                ]
                for tid, tier, st in subs:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO tenant_subscriptions (
                            tenant_id, tier, status, billing_cycle, current_period_start, current_period_end
                        ) VALUES (?, ?, ?, 'MONTHLY', ?, ?);
                        """,
                        (tid, tier, st, now, now)
                    )
            conn.commit()

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by their username."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?;", (username,)).fetchone()
            return dict(row) if row else None

    def create_user(self, username: str, password_hash: str, salt: str, tenant_id: str, role: str) -> Dict[str, Any]:
        """Registers a new user under a tenant."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, salt, tenant_id, role, created_at) VALUES (?, ?, ?, ?, ?, ?);",
                (username, password_hash, salt, tenant_id, role, now)
            )
            conn.commit()
            return {"id": cursor.lastrowid, "username": username, "tenant_id": tenant_id, "role": role, "created_at": now}

    def create_api_key(self, key_id: str, tenant_id: str, name: str, key_prefix: str, key_hash: str, tier: str = "FREE", rate_limit_per_day: int = 50) -> Dict[str, Any]:
        """Stores a new hashed API key."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO api_keys (
                    key_id, tenant_id, name, key_prefix, key_hash, tier,
                    rate_limit_per_day, created_at, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1);
                """,
                (key_id, tenant_id, name, key_prefix, key_hash, tier, rate_limit_per_day, now)
            )
            conn.commit()
            return {
                "key_id": key_id,
                "tenant_id": tenant_id,
                "name": name,
                "key_prefix": key_prefix,
                "tier": tier,
                "rate_limit_per_day": rate_limit_per_day,
                "created_at": now,
                "is_active": True
            }

    def get_api_key_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Looks up an API key by its SHA-256 digest."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1;", (key_hash,)).fetchone()
            return dict(row) if row else None

    def list_api_keys(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Lists active and inactive API keys for a tenant."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT key_id, tenant_id, name, key_prefix, tier, rate_limit_per_day, created_at, is_active, last_used_at FROM api_keys WHERE tenant_id = ? ORDER BY id DESC;",
                (tenant_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    def revoke_api_key(self, key_id: str, tenant_id: str) -> bool:
        """Deactivates an API key."""
        with self._get_connection() as conn:
            cursor = conn.execute("UPDATE api_keys SET is_active = 0 WHERE key_id = ? AND tenant_id = ?;", (key_id, tenant_id))
            conn.commit()
            return cursor.rowcount > 0

    def record_usage(self, tenant_id: str, event_type: str, units: int = 1) -> None:
        """Logs a metered consumption event for billing."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO usage_records (tenant_id, event_type, units, timestamp) VALUES (?, ?, ?, ?);",
                (tenant_id, event_type, units, now)
            )
            conn.commit()

    def get_usage_summary(self, tenant_id: str) -> Dict[str, int]:
        """Calculates total metered units by event type for the current period."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT event_type, SUM(units) as total_units FROM usage_records WHERE tenant_id = ? GROUP BY event_type;",
                (tenant_id,)
            ).fetchall()
            return {r["event_type"]: r["total_units"] for r in rows}

    def get_tenant_branding(self, tenant_id: str) -> Dict[str, Any]:
        """Retrieves custom white-label branding for a tenant."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM tenant_branding WHERE tenant_id = ?;", (tenant_id,)).fetchone()
            if row:
                return dict(row)
            return {
                "tenant_id": tenant_id,
                "org_name": f"{tenant_id} Bioscience Lab",
                "lab_id": f"LAB-{tenant_id}-01",
                "logo_url": "",
                "contact_email": f"compliance@{tenant_id.lower()}.com",
                "accent_color": "#ff6b4a",
                "updated_at": datetime.now(timezone.utc).isoformat()
            }

    def save_tenant_branding(self, tenant_id: str, org_name: str, lab_id: str, logo_url: str, contact_email: str, accent_color: str) -> Dict[str, Any]:
        """Updates custom white-label branding for a tenant."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO tenant_branding (
                    tenant_id, org_name, lab_id, logo_url, contact_email, accent_color, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    org_name=excluded.org_name,
                    lab_id=excluded.lab_id,
                    logo_url=excluded.logo_url,
                    contact_email=excluded.contact_email,
                    accent_color=excluded.accent_color,
                    updated_at=excluded.updated_at;
                """,
                (tenant_id, org_name, lab_id, logo_url, contact_email, accent_color, now)
            )
            conn.commit()
            return {
                "tenant_id": tenant_id,
                "org_name": org_name,
                "lab_id": lab_id,
                "logo_url": logo_url,
                "contact_email": contact_email,
                "accent_color": accent_color,
                "updated_at": now
            }

    def get_tenant_subscription(self, tenant_id: str) -> Dict[str, Any]:
        """Retrieves active subscription plan details."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM tenant_subscriptions WHERE tenant_id = ?;", (tenant_id,)).fetchone()
            if row:
                return dict(row)
            return {
                "tenant_id": tenant_id,
                "tier": "STARTUP_LAB",
                "status": "ACTIVE",
                "billing_cycle": "MONTHLY"
            }

    def update_tenant_subscription(self, tenant_id: str, tier: str) -> Dict[str, Any]:
        """Upgrades or modifies subscription tier."""
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO tenant_subscriptions (
                    tenant_id, tier, status, billing_cycle, current_period_start, current_period_end
                ) VALUES (?, ?, 'ACTIVE', 'MONTHLY', ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    tier=excluded.tier,
                    status='ACTIVE',
                    current_period_start=excluded.current_period_start;
                """,
                (tenant_id, tier, now, now)
            )
            conn.commit()
            return {"tenant_id": tenant_id, "tier": tier, "status": "ACTIVE", "updated_at": now}
