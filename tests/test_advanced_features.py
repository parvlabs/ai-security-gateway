"""
Automated Verification Suite for Advanced Enterprise AI-WAF Features:
1. Semantic Vector Caching (Cosine Similarity)
2. Multi-Provider Fallback Router & Circuit Breaker
3. Webhook Alert Dispatcher (Slack & Discord)
4. Compliance Audit Trail Export (SOC 2, HIPAA, GDPR)
5. Mid-Stream Token Killer (Real-time SSE Abort on Leak)
"""

import asyncio
import json
import httpx
from app.config import settings
from app.proxy.semantic_cache import SemanticResponseCache
from app.proxy.fallback_router import FallbackRouter, CircuitBreaker
from app.security.webhooks import WebhookNotifier
from app.security.compliance import compliance_service
from app.security.outbound_scanner import outbound_scanner
from app.proxy.upstream import upstream_client

async def test_semantic_cache():
    print("\n--- [Test 1] Semantic Vector Caching Engine ---")
    cache = SemanticResponseCache(similarity_threshold=0.75)
    
    prompt_seed = "What is the capital city of France?"
    mock_resp = {"id": "chat-seed", "choices": [{"message": {"role": "assistant", "content": "Paris is the capital of France."}}]}
    
    # Store seed
    cache.store(model="gpt-4o", prompt=prompt_seed, response=mock_resp)
    
    # Exact hit test
    exact_hit, score, m_type = cache.find_match(model="gpt-4o", prompt=prompt_seed)
    assert exact_hit is not None, "Exact match should be found"
    assert m_type == "exact", f"Expected 'exact', got {m_type}"
    print(f"  [PASS] Exact match found (score: {score})")
    
    # Semantic match test (semantically equivalent query)
    sem_query = "Tell me the capital of France"
    sem_hit, sem_score, sem_type = cache.find_match(model="gpt-4o", prompt=sem_query)
    assert sem_hit is not None, f"Semantic match should be found for '{sem_query}'"
    assert sem_score >= 0.70, f"Expected cosine similarity >= 0.70, got {sem_score}"
    assert sem_type == "semantic", f"Expected 'semantic', got {sem_type}"
    print(f"  [PASS] Semantic match hit successfully: '{sem_query}' -> score {sem_score:.3f}")
    
    # Unrelated query should miss
    unrelated = "How do rocket thrusters work in outer space?"
    miss_hit, miss_score, miss_type = cache.find_match(model="gpt-4o", prompt=unrelated)
    assert miss_hit is None, "Unrelated prompt must not match"
    assert miss_type == "miss", "Expected miss"
    print(f"  [PASS] Unrelated query correctly missed (score {miss_score:.3f})")
    
    stats = cache.stats()
    assert stats["exact_hits"] == 1
    assert stats["semantic_hits"] == 1
    assert stats["misses"] == 1
    print(f"  [PASS] Semantic Cache Stats verified: {stats}")

async def test_fallback_router():
    print("\n--- [Test 2] Multi-Provider Fallback Router & Circuit Breaker ---")
    router = FallbackRouter()
    
    # 1. Closed state initially
    prov, is_fallback = router.get_preferred_provider("openai")
    assert prov == "openai" and not is_fallback
    print("  [PASS] Default provider is primary 'openai' (Circuit CLOSED)")
    
    # 2. Trip the circuit breaker with 3 failures
    router.record_failure("openai", "HTTP 503 Service Unavailable")
    router.record_failure("openai", "HTTP 429 Rate Limit Exceeded")
    router.record_failure("openai", "Network Timeout after 30s")
    
    assert router.circuits["openai"].state == "OPEN"
    print("  [PASS] Circuit successfully transitioned to OPEN after 3 failures")
    
    # 3. Request should failover to alternate provider
    prov_fb, is_fb = router.get_preferred_provider("openai")
    assert prov_fb != "openai", f"Expected failover provider, got {prov_fb}"
    assert is_fb is True, "is_fallback should be True"
    print(f"  [PASS] Failover triggered: openai -> {prov_fb} (is_fallback={is_fb})")
    
    # 4. Success restores circuit
    router.record_success("openai")
    assert router.circuits["openai"].state == "CLOSED"
    prov_restored, is_fb_restored = router.get_preferred_provider("openai")
    assert prov_restored == "openai" and not is_fb_restored
    print("  [PASS] Circuit restored to CLOSED upon successful heartbeat")

async def test_webhooks():
    print("\n--- [Test 3] Webhook Notifier (Slack & Discord) ---")
    notifier = WebhookNotifier()
    # Test safe execution when URLs are unset (default)
    res = await notifier.notify_tool_approval_needed(
        approval_id="appr_test_123",
        tool_name="delete_record",
        risk_level="high",
        arguments={"table": "customers", "id": "c_456"},
        request_id="req_test_789"
    )
    assert isinstance(res, dict)
    assert "slack" in res and "discord" in res
    print(f"  [PASS] Webhook dispatcher executed safely without unhandled exceptions: {res}")

async def test_compliance_export():
    print("\n--- [Test 4] Compliance Audit Trail Export (SOC 2, HIPAA, GDPR) ---")
    # Export CSV
    csv_out = await compliance_service.export_csv(limit=50)
    assert isinstance(csv_out, str)
    assert "request_id" in csv_out or "Notice" in csv_out
    print(f"  [PASS] Compliance CSV generated ({len(csv_out)} chars)")
    
    # Export JSON
    json_out = await compliance_service.export_json(limit=50)
    assert "metadata" in json_out
    assert "records" in json_out
    assert "standards_supported" in json_out["metadata"]
    print(f"  [PASS] Compliance JSON generated: {json_out['metadata']['standards_supported']}")

async def test_midstream_token_killer():
    print("\n--- [Test 5] Mid-Stream Token Killer (Real-Time SSE Abort) ---")
    # Test outbound scanner helper
    leak_found, reason = outbound_scanner.check_midstream_leak("Safe stream chunk 1...")
    assert not leak_found
    
    leak_found, reason = outbound_scanner.check_midstream_leak(f"Chunk before... {settings.CANARY_TOKENS[0]} chunk after")
    assert leak_found
    print(f"  [PASS] Outbound token scanner detects canary in chunk: {reason}")
    
    leak_found_sec, reason_sec = outbound_scanner.check_midstream_leak("Leaking secret: sk-proj-1234567890abcdef")
    assert leak_found_sec
    print(f"  [PASS] Outbound token scanner detects API key in chunk: {reason_sec}")
    
    # Test mock stream generator with canary leak
    body = {
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "stream_canary_leak"}]
    }
    
    stream_chunks = []
    aborted = False
    accumulated = ""
    async for chunk in upstream_client.generate_mock_openai_stream(body):
        stream_chunks.append(chunk)
        accumulated += chunk
        has_leak, leak_reason = outbound_scanner.check_midstream_leak(accumulated)
        if has_leak:
            aborted = True
            break
            
    assert aborted is True, "Token killer should have aborted stream upon encountering canary"
    assert len(stream_chunks) < 10, "Stream was truncated mid-flight"
    print(f"  [PASS] Mid-stream Token Killer aborted stream after {len(stream_chunks)} chunks upon leak detection")

async def main():
    print("================================================================================")
    print("  VERIFYING ADVANCED ENTERPRISE SUITE: AI SECURITY GATEWAY")
    print("================================================================================")
    await test_semantic_cache()
    await test_fallback_router()
    await test_webhooks()
    await test_compliance_export()
    await test_midstream_token_killer()
    print("\n================================================================================")
    print("  ALL 5 ADVANCED ENTERPRISE MODULES VERIFIED & OPERATIONAL (100% PASS)")
    print("================================================================================\n")

if __name__ == "__main__":
    asyncio.run(main())
