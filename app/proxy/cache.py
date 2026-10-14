"""
Production Caching Layer (Inspired by Portkey AI Gateway & LiteLLM).
Provides sub-millisecond responses for repeated queries, cuts token expenses,
and cushions against upstream provider outages.
"""

import time
import hashlib
import json
from typing import Optional, Dict, Any, Tuple

class ResponseCache:
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 1000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self.hits = 0
        self.misses = 0
        self.tokens_saved = 0

    def _make_key(self, model: str, prompt_text: str, tools: Optional[list] = None) -> str:
        data = f"{model}:{prompt_text}:{json.dumps(tools or [], sort_keys=True)}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def get(self, model: str, prompt_text: str, tools: Optional[list] = None) -> Optional[Dict[str, Any]]:
        key = self._make_key(model, prompt_text, tools)
        if key in self._cache:
            entry_time, data = self._cache[key]
            if time.time() - entry_time < self.ttl_seconds:
                self.hits += 1
                usage = data.get("usage", {})
                self.tokens_saved += usage.get("total_tokens", 40)
                # Return deep copy with cached flag
                cached_copy = json.loads(json.dumps(data))
                cached_copy["_gateway_cache_hit"] = True
                return cached_copy
            else:
                # Expired
                del self._cache[key]
        self.misses += 1
        return None

    def set(self, model: str, prompt_text: str, response_data: Dict[str, Any], tools: Optional[list] = None):
        if len(self._cache) >= self.max_size:
            # Simple eviction of oldest item
            oldest_key = min(self._cache.keys(), key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]
        key = self._make_key(model, prompt_text, tools)
        self._cache[key] = (time.time(), response_data)

    def stats(self) -> Dict[str, Any]:
        total = self.hits + self.misses
        hit_ratio = (self.hits / total * 100.0) if total > 0 else 0.0
        # Estimated cost savings at standard $5 per 1M tokens
        estimated_usd_saved = (self.tokens_saved / 1_000_000.0) * 5.0
        return {
            "cache_entries": len(self._cache),
            "cache_hits": self.hits,
            "cache_misses": self.misses,
            "hit_ratio_pct": round(hit_ratio, 2),
            "tokens_saved": self.tokens_saved,
            "estimated_usd_saved": round(estimated_usd_saved, 4)
        }

gateway_cache = ResponseCache()
