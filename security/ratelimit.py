"""GeneSign Tiered Rate-Limiting Engine.

Enforces commercial request rate limits across subscription tiers:
- Free Tier: 50 requests / day
- Startup Tier: 10,000 requests / day
- Enterprise Tier: Unlimited (10,000,000 requests / day)
"""

from datetime import datetime, timezone
import threading
from typing import Dict, Tuple, Any
from fastapi import HTTPException, Request, status


class TieredRateLimiter:
    """Sliding-window daily request rate limiter with thread safety."""

    def __init__(self):
        self._lock = threading.Lock()
        # Key: (subject_id, date_str) -> count
        self._counts: Dict[Tuple[str, str], int] = {}

    def _get_today_str(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def check_limit(self, identity: Dict[str, Any], client_ip: str = "127.0.0.1") -> Tuple[bool, int, int]:
        """Evaluates rate limit for identity.

        Returns: (is_allowed, remaining_quota, total_limit)
        """
        tier = identity.get("tier", "FREE").upper()
        limit = identity.get("rate_limit_per_day")

        if limit is None:
            if tier == "FREE":
                limit = 50
            elif tier == "STARTUP" or tier == "STARTUP_LAB":
                limit = 10_000
            else:
                limit = 10_000_000

        # Identifier for tracking: key_id, user_id, or IP
        subject_id = identity.get("key_id") or str(identity.get("user_id")) or client_ip
        today = self._get_today_str()

        with self._lock:
            key = (subject_id, today)
            current_usage = self._counts.get(key, 0)
            if current_usage >= limit:
                return False, 0, limit

            self._counts[key] = current_usage + 1
            remaining = max(0, limit - (current_usage + 1))
            return True, remaining, limit

    def reset_usage(self, subject_id: str):
        """Administrative reset of rate limit usage."""
        today = self._get_today_str()
        with self._lock:
            self._counts.pop((subject_id, today), None)


# Global singleton rate limiter
rate_limiter = TieredRateLimiter()


def enforce_rate_limit(request: Request, identity: Dict[str, Any]):
    """FastAPI enforcement utility raising 429 if quota exceeded."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    allowed, remaining, limit = rate_limiter.check_limit(identity, client_ip)

    request.state.rate_limit_remaining = remaining
    request.state.rate_limit_limit = limit

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for tier '{identity.get('tier', 'FREE')}'. Limit is {limit} requests/day. Upgrade to Enterprise for unlimited throughput.",
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "Retry-After": "86400",
            },
        )
