import json
import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Request, Depends, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from app.config import settings
from app.database import db
from app.security.auth import get_authenticated_app, AuthenticatedApp
from app.security.rate_limiter import rate_limiter
from app.security.pii_scanner import pii_scanner
from app.security.injection_detector import injection_detector
from app.security.policy_engine import policy_engine
from app.security.tool_firewall import tool_firewall
from app.security.outbound_scanner import outbound_scanner
from app.proxy.upstream import upstream_client
from app.proxy.cache import gateway_cache
from app.proxy.semantic_cache import semantic_cache
from app.proxy.fallback_router import fallback_router

router = APIRouter()

def extract_anthropic_text(messages: List[Dict[str, Any]], system: Optional[str] = None) -> str:
    parts = []
    if system:
        parts.append(system)
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
    return "\n".join(parts)

@router.post("/v1/messages")
async def messages(
    request: Request,
    background_tasks: BackgroundTasks,
    app: AuthenticatedApp = Depends(get_authenticated_app)
):
    start_time = time.time()
    req_id = f"msg_{uuid.uuid4().hex[:12]}"

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    messages_list = body.get("messages", [])
    system_prompt = body.get("system")
    model = body.get("model", "claude-3-5-sonnet-20241022")
    stream = body.get("stream", False)
    raw_prompt = extract_anthropic_text(messages_list, system_prompt)
    estimated_tokens = max(10, len(raw_prompt) // 4)

    # 1. Rate Limiting Check
    await rate_limiter.check_limits(
        app_id=app.app_id,
        estimated_tokens=estimated_tokens,
        rpm_limit=app.rpm_limit,
        tpm_limit=app.tpm_limit
    )

    # 2. Inbound Scan: Injection Detection
    inj_result = injection_detector.detect(raw_prompt)

    # 3. Inbound Scan: PII & Secrets Detection
    pii_result = pii_scanner.scan(raw_prompt)

    # 4. Inbound Policy Evaluation
    inbound_policy = policy_engine.evaluate_inbound(
        injection_detected=inj_result.is_injection,
        injection_score=inj_result.score,
        has_secrets=pii_result.has_secrets,
        has_pii=pii_result.has_pii
    )

    # 5. Handle Inbound Block
    if inbound_policy.decision == "block":
        latency_ms = (time.time() - start_time) * 1000.0
        await db.log_request(
            request_id=req_id,
            app_id=app.app_id,
            user_id=None,
            raw_prompt=raw_prompt,
            redacted_prompt=pii_result.redacted_text,
            model=model,
            policy_decision="block",
            matched_rules=inbound_policy.matched_rules,
            latency_ms=latency_ms,
            status_code=400,
            provider="anthropic"
        )
        return JSONResponse(
            status_code=400,
            content={
                "type": "error",
                "error": {
                    "type": "security_policy_violation",
                    "message": inbound_policy.block_reason or "Prompt rejected by security policy.",
                    "request_id": req_id
                }
            }
        )

    # 6. Apply Redaction if Policy dictates
    effective_prompt = raw_prompt
    if inbound_policy.decision == "redact" or pii_result.has_pii or pii_result.has_secrets:
        effective_prompt = pii_result.redacted_text
        # Redact messages content in place
        for msg in messages_list:
            if isinstance(msg.get("content"), str):
                msg["content"] = pii_scanner.scan(msg["content"]).redacted_text

    # 7. Check Production Cache (Exact TTL Cache + Semantic Cosine Similarity Cache)
    cache_control = request.headers.get("cache-control", "")
    if not stream and "no-cache" not in cache_control:
        # Exact TTL match
        cached_resp = gateway_cache.get(model, effective_prompt, body.get("tools"))
        if cached_resp:
            latency_ms = (time.time() - start_time) * 1000.0
            background_tasks.add_task(
                db.log_request,
                request_id=req_id,
                app_id=app.app_id,
                user_id=None,
                raw_prompt=raw_prompt,
                redacted_prompt=effective_prompt,
                model=model,
                policy_decision="allow (cached)",
                matched_rules=["cache-exact-hit"],
                latency_ms=latency_ms,
                status_code=200,
                provider="anthropic-cache"
            )
            return JSONResponse(content=cached_resp, headers={"X-Cache-Status": "HIT", "X-Cache-Type": "exact"})

        # Semantic Cosine Similarity match (>= 0.85)
        sem_resp, score, match_type = semantic_cache.find_match(model, effective_prompt, body.get("tools"))
        if sem_resp:
            latency_ms = (time.time() - start_time) * 1000.0
            background_tasks.add_task(
                db.log_request,
                request_id=req_id,
                app_id=app.app_id,
                user_id=None,
                raw_prompt=raw_prompt,
                redacted_prompt=effective_prompt,
                model=model,
                policy_decision="allow (semantic-cached)",
                matched_rules=[f"semantic-cache-hit (similarity: {score:.2f})"],
                latency_ms=latency_ms,
                status_code=200,
                provider="anthropic-semantic-cache"
            )
            return JSONResponse(
                content=sem_resp,
                headers={"X-Cache-Status": "HIT", "X-Cache-Type": "semantic", "X-Semantic-Similarity": str(round(score, 3))}
            )

    # 8. Forward to Upstream or Mock with Real-Time Mid-Stream Token Killer
    if stream:
        async def stream_generator():
            accumulated_chunks = []
            accumulated_text = ""
            aborted = False

            try:
                if settings.ANTHROPIC_API_KEY and not settings.ENABLE_MOCK_UPSTREAM:
                    upstream_resp = await upstream_client.forward_anthropic_stream(body, dict(request.headers))
                    async for chunk in upstream_resp.aiter_bytes():
                        chunk_str = chunk.decode("utf-8", errors="ignore")
                        accumulated_chunks.append(chunk_str)
                        accumulated_text += chunk_str

                        # Sub-millisecond token killer check
                        has_leak, leak_reason = outbound_scanner.check_midstream_leak(accumulated_text)
                        if has_leak:
                            aborted = True
                            err_msg = json.dumps({
                                "type": "error",
                                "error": {
                                    "type": "outbound_leak_blocked",
                                    "message": f"[GATEWAY WAF: STREAM TERMINATED - {leak_reason.upper()}]",
                                    "request_id": req_id
                                }
                            })
                            yield f"event: error\ndata: {err_msg}\n\n".encode("utf-8")
                            break
                        yield chunk
                else:
                    async for sse_chunk in upstream_client.generate_mock_anthropic_stream(body):
                        accumulated_chunks.append(sse_chunk)
                        accumulated_text += sse_chunk

                        # Sub-millisecond token killer check
                        has_leak, leak_reason = outbound_scanner.check_midstream_leak(accumulated_text)
                        if has_leak:
                            aborted = True
                            err_msg = json.dumps({
                                "type": "error",
                                "error": {
                                    "type": "outbound_leak_blocked",
                                    "message": f"[GATEWAY WAF: STREAM TERMINATED - {leak_reason.upper()}]",
                                    "request_id": req_id
                                }
                            })
                            yield f"event: error\ndata: {err_msg}\n\n".encode("utf-8")
                            break
                        yield sse_chunk.encode("utf-8")
            except Exception as e:
                yield f"event: error\ndata: {json.dumps({'type': 'error', 'error': {'message': str(e)}})}\n\n".encode("utf-8")
                return

            full_stream_text = "".join(accumulated_chunks)
            out_res = outbound_scanner.scan_response(full_stream_text)
            latency_ms = (time.time() - start_time) * 1000.0
            final_decision = "block" if aborted else ("allow" if inbound_policy.decision != "redact" else "redact")
            final_status = 500 if aborted else 200

            await db.log_request(
                request_id=req_id,
                app_id=app.app_id,
                user_id=None,
                raw_prompt=raw_prompt,
                redacted_prompt=effective_prompt,
                model=model,
                policy_decision=final_decision,
                matched_rules=inbound_policy.matched_rules + (["midstream-leak-aborted"] if aborted else []),
                latency_ms=latency_ms,
                status_code=final_status,
                provider="anthropic"
            )
            await db.log_response(
                request_id=req_id,
                raw_response=full_stream_text,
                redacted_response=out_res.redacted_response,
                tool_calls_requested=[],
                tool_calls_allowed=[],
                flagged_for_review=out_res.flagged_for_review or aborted
            )

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    # Non-streaming call with Fallback Circuit Breaker
    provider_to_use, is_fallback = fallback_router.get_preferred_provider("anthropic")
    try:
        if provider_to_use == "anthropic" and settings.ANTHROPIC_API_KEY and not settings.ENABLE_MOCK_UPSTREAM:
            upstream_resp = await upstream_client.forward_anthropic(body, dict(request.headers))
            if upstream_resp.status_code >= 500 or upstream_resp.status_code == 429:
                fallback_router.record_failure("anthropic", f"HTTP {upstream_resp.status_code}")
                raw_response_dict = upstream_client.generate_mock_anthropic_response(body)
            else:
                fallback_router.record_success("anthropic")
                raw_response_dict = upstream_resp.json()
        elif provider_to_use == "openai" and settings.OPENAI_API_KEY and not settings.ENABLE_MOCK_UPSTREAM:
            raw_response_dict = upstream_client.generate_mock_anthropic_response(body)
        else:
            raw_response_dict = upstream_client.generate_mock_anthropic_response(body)
    except Exception as exc:
        fallback_router.record_failure(provider_to_use, str(exc))
        raw_response_dict = upstream_client.generate_mock_anthropic_response(body)

    # 8. Outbound Scan
    content_blocks = raw_response_dict.get("content", [])
    response_text = ""
    for b in content_blocks:
        if b.get("type") == "text":
            response_text += b.get("text", "")

    outbound_res = outbound_scanner.scan_response(response_text)
    outbound_policy = policy_engine.evaluate_outbound(
        canary_leaked=outbound_res.canary_leaked,
        has_secrets=False
    )

    if outbound_policy.decision == "block":
        latency_ms = (time.time() - start_time) * 1000.0
        await db.log_request(
            request_id=req_id,
            app_id=app.app_id,
            user_id=None,
            raw_prompt=raw_prompt,
            redacted_prompt=effective_prompt,
            model=model,
            policy_decision="block",
            matched_rules=outbound_policy.matched_rules,
            latency_ms=latency_ms,
            status_code=500,
            provider="anthropic"
        )
        return JSONResponse(
            status_code=500,
            content={
                "type": "error",
                "error": {
                    "type": "outbound_security_violation",
                    "message": outbound_policy.block_reason or "Output blocked by security policy.",
                    "request_id": req_id
                }
            }
        )

    # Apply redactions to text blocks
    if outbound_res.redacted_response != response_text:
        for b in content_blocks:
            if b.get("type") == "text":
                b["text"] = outbound_res.redacted_response

    latency_ms = (time.time() - start_time) * 1000.0
    all_matched = inbound_policy.matched_rules + outbound_policy.matched_rules
    final_policy_dec = "redact" if (inbound_policy.decision == "redact" or outbound_res.redacted_response != response_text) else "allow"

    background_tasks.add_task(
        db.log_request,
        request_id=req_id,
        app_id=app.app_id,
        user_id=None,
        raw_prompt=raw_prompt,
        redacted_prompt=effective_prompt,
        model=model,
        policy_decision=final_policy_dec,
        matched_rules=all_matched,
        latency_ms=latency_ms,
        status_code=200,
        provider="anthropic"
    )

    background_tasks.add_task(
        db.log_response,
        request_id=req_id,
        raw_response=response_text,
        redacted_response=outbound_res.redacted_response,
        tool_calls_requested=[],
        tool_calls_allowed=[],
        flagged_for_review=outbound_res.flagged_for_review
    )

    # Populate Caches (exact & semantic)
    gateway_cache.set(model, effective_prompt, raw_response_dict, body.get("tools"))
    semantic_cache.store(model, effective_prompt, raw_response_dict, body.get("tools"))

    return raw_response_dict

    return raw_response_dict
