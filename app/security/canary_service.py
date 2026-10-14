"""
Dynamic Canary Token Defense Engine (Inspired by Protect AI Rebuff).
Generates request-scoped secret canary tokens embedded into prompts to detect
indirect prompt injection, model instruction leakage, and data exfiltration.
"""

import uuid
import secrets
from typing import Dict, List, Optional
import time

class CanaryManager:
    def __init__(self, canary_ttl_seconds: int = 600):
        self.ttl = canary_ttl_seconds
        # Active canaries: canary_token -> (request_id, created_at)
        self.active_canaries: Dict[str, tuple[str, float]] = {}

    def generate_canary(self, request_id: str) -> str:
        """Generate a cryptographically random canary token."""
        token = f"rb_canary_{secrets.token_hex(8)}"
        self.active_canaries[token] = (request_id, time.time())
        self._cleanup()
        return token

    def check_leak(self, text: str) -> Optional[str]:
        """Check if any active canary token appears in the text."""
        self._cleanup()
        for token in list(self.active_canaries.keys()):
            if token in text:
                return token
        return None

    def _cleanup(self):
        now = time.time()
        expired = [t for t, (_, created) in self.active_canaries.items() if now - created > self.ttl]
        for t in expired:
            self.active_canaries.pop(t, None)

canary_manager = CanaryManager()
