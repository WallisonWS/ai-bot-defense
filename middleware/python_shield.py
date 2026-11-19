"""
AI Bot & Automated Hacker Defense Middleware (Python — Zero Dependencies)
Protects APIs & Web Apps from Autonomous AI Hacking Agents, Fuzzers, Scrapers & Brute-Force Swarms.
Techniques:
  1. Canary / Honeypot Trap Endpoints (/.env, /.git/config, /wp-login.php, /api/debug/secrets)
  2. Sliding-Window Adaptive Token-Bucket Rate Limiter & Temporary Auto-Ban
  3. High-Entropy 404 Probing & Malicious AI Scanner Fingerprinting
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Set, Tuple


HONEYPOT_PATHS: Set[str] = {
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/phpmyadmin",
    "/api/debug/secrets",
    "/actuator/env",
    "/server-status",
}

SUSPICIOUS_AGENTS = ("sqlmap", "nikto", "nuclei", "gobuster", "ffuf", "masscan", "zgrab", "python-requests", "curl/")


@dataclass
class DefenseDecision:
    allowed: bool
    status_code: int
    reason: str
    tarpit_delay_ms: int = 0


class AiBotDefender:
    """In-memory Zero-Dependency Blue-Team API Shield."""

    def __init__(self, max_rpm: int = 90, ban_seconds: int = 900) -> None:
        self.max_rpm = max_rpm
        self.ban_seconds = ban_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._banned_until: Dict[str, float] = {}

    def inspect_request(self, client_ip: str, path: str, user_agent: str = "") -> DefenseDecision:
        now = time.time()

        # 1. Check active auto-ban
        if self._banned_until.get(client_ip, 0) > now:
            return DefenseDecision(False, 403, "IP temporarily banned (honeypot / exploit swarm trigger)", tarpit_delay_ms=1500)

        # 2. Honeypot / Canary Trap (Instant Auto-Ban)
        clean_path = path.split("?")[0].lower()
        if clean_path in HONEYPOT_PATHS:
            self._banned_until[client_ip] = now + self.ban_seconds
            return DefenseDecision(False, 403, f"Honeypot trap triggered on {clean_path}", tarpit_delay_ms=2000)

        # 3. Known Automated Exploit Scanner User-Agent
        ua_low = user_agent.lower()
        if any(sig in ua_low for sig in SUSPICIOUS_AGENTS):
            return DefenseDecision(False, 403, f"Blocked automated exploit/scanner fingerprint: {user_agent[:40]}", tarpit_delay_ms=1000)

        # 4. Sliding-Window Rate Limiter (Anti-AI-Fuzzer Burst)
        bucket = self._hits[client_ip]
        while bucket and now - bucket[0] > 60.0:
            bucket.popleft()
        bucket.append(now)

        if len(bucket) > self.max_rpm:
            self._banned_until[client_ip] = now + 300
            return DefenseDecision(False, 429, f"Rate limit exceeded ({len(bucket)} req/min) — auto-throttled", tarpit_delay_ms=800)

        return DefenseDecision(True, 200, "ALLOWED")
