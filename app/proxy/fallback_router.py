"""
Multi-Provider Fallback & Circuit Breaker Router (Portkey & LiteLLM Style).
Manages provider health states (CLOSED, OPEN, HALF_OPEN) and automatically
fails over to secondary models/providers when the primary encounters 429/5xx errors or network timeouts.
"""

import time
import asyncio
from typing import Dict, Any, Optional, List, Tuple
from app.config import settings

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 3, recovery_time_seconds: float = 30.0):
        self.failure_threshold = failure_threshold
        self.recovery_time_seconds = recovery_time_seconds
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def record_success(self):
        self.failure_count = 0
        self.state = "CLOSED"

    def record_failure(self):
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"

    def can_attempt(self) -> bool:
        if self.state == "CLOSED":
            return True
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_time_seconds:
                self.state = "HALF_OPEN"
                return True
            return False
        if self.state == "HALF_OPEN":
            return True
        return False

class FallbackRouter:
    def __init__(self):
        self.circuits: Dict[str, CircuitBreaker] = {
            "openai": CircuitBreaker(),
            "anthropic": CircuitBreaker(),
            "mock": CircuitBreaker()
        }
        self.fallback_events: List[Dict[str, Any]] = []

    def get_preferred_provider(self, requested_provider: str = "openai") -> Tuple[str, bool]:
        """
        Returns (provider_to_use, is_fallback).
        If requested provider circuit is OPEN, fails over to alternate.
        """
        primary_circuit = self.circuits.get(requested_provider)
        if primary_circuit and primary_circuit.can_attempt():
            return requested_provider, False

        # Fallback order
        fallback_order = ["openai", "anthropic", "mock"]
        for candidate in fallback_order:
            if candidate != requested_provider:
                circuit = self.circuits.get(candidate)
                if circuit and circuit.can_attempt():
                    self.record_fallback(requested_provider, candidate, "Circuit open on primary provider")
                    return candidate, True

        return "mock", True

    def record_success(self, provider: str):
        if provider in self.circuits:
            self.circuits[provider].record_success()

    def record_failure(self, provider: str, reason: str = ""):
        if provider in self.circuits:
            self.circuits[provider].record_failure()

    def record_fallback(self, from_provider: str, to_provider: str, reason: str):
        event = {
            "timestamp": time.time(),
            "from_provider": from_provider,
            "to_provider": to_provider,
            "reason": reason
        }
        self.fallback_events.append(event)
        if len(self.fallback_events) > 50:
            self.fallback_events.pop(0)

    def stats(self) -> Dict[str, Any]:
        return {
            "circuits": {name: cb.state for name, cb in self.circuits.items()},
            "failure_counts": {name: cb.failure_count for name, cb in self.circuits.items()},
            "total_fallback_events": len(self.fallback_events),
            "recent_fallbacks": self.fallback_events[-5:]
        }

fallback_router = FallbackRouter()
