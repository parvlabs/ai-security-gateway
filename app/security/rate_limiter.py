import time
import asyncio
from typing import Dict, Tuple, Optional
from fastapi import HTTPException

class TokenBucket:
    def __init__(self, capacity: float, refill_rate: float):
        """
        capacity: max tokens bucket can hold
        refill_rate: tokens per second added to the bucket
        """
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_update = time.time()
        self.lock = asyncio.Lock()

    async def consume(self, amount: float = 1.0) -> bool:
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            # Refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= amount:
                self.tokens -= amount
                return True
            return False

class RateLimiter:
    def __init__(self):
        # Maps app_id -> (request_bucket, token_bucket)
        self.app_buckets: Dict[str, Tuple[TokenBucket, TokenBucket]] = {}
        # Burst abuse tracker: count rapid failures
        self.abuse_counter: Dict[str, int] = {}

    def get_or_create_buckets(self, app_id: str, rpm: int, tpm: int) -> Tuple[TokenBucket, TokenBucket]:
        if app_id not in self.app_buckets:
            # Capacity equal to rpm/tpm with 20% burst tolerance
            req_bucket = TokenBucket(capacity=rpm * 1.2, refill_rate=rpm / 60.0)
            token_bucket = TokenBucket(capacity=tpm * 1.2, refill_rate=tpm / 60.0)
            self.app_buckets[app_id] = (req_bucket, token_bucket)
        return self.app_buckets[app_id]

    async def check_limits(self, app_id: str, estimated_tokens: int = 50, rpm_limit: int = 60, tpm_limit: int = 100000):
        req_bucket, tok_bucket = self.get_or_create_buckets(app_id, rpm_limit, tpm_limit)
        
        # Check request count
        req_allowed = await req_bucket.consume(1.0)
        if not req_allowed:
            self.abuse_counter[app_id] = self.abuse_counter.get(app_id, 0) + 1
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "type": "requests_per_minute_exceeded",
                    "message": f"App '{app_id}' exceeded limit of {rpm_limit} RPM."
                }
            )

        # Check token count
        tok_allowed = await tok_bucket.consume(float(estimated_tokens))
        if not tok_allowed:
            self.abuse_counter[app_id] = self.abuse_counter.get(app_id, 0) + 1
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "type": "tokens_per_minute_exceeded",
                    "message": f"App '{app_id}' exceeded limit of {tpm_limit} TPM."
                }
            )

rate_limiter = RateLimiter()
