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

def extract_prompt_text(messages: List[Dict[str, Any]]) -> str:
    parts = []
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(part.get("text", ""))
    return "\n".join(parts)

def replace_prompt_text(messages: List[Dict[str, Any]], old_text: str, new_text: str) -> List[Dict[str, Any]]:
    # Simple replacement in latest user messages
    updated = json.loads(json.dumps(messages))
    for msg in updated:
        if isinstance(msg.get("content"), str):
            if msg["content"] in old_text or old_text in msg["content"]:
                # Apply PII redaction directly
                scan_res = pii_scanner.scan(msg["content"])
                msg["content"] = scan_res.redacted_text
    return updated

@router.get("/v1/models")
async def list_models(app: AuthenticatedApp = Depends(get_authenticated_app)):
    return {
        "object": "list",
        "data": [
            {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
            {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
            {"id": "claude-3-5-sonnet-20241022", "object": "model", "owned_by": "anthropic"}
        ]
    }

@router.post("/v1/chat/completions")
async def chat_completions(
    request: Request,
    background_tasks: BackgroundTasks,
    app: AuthenticatedApp = Depends(get_authenticated_app)
):
    start_time = time.time()
    req_id = f"req_{uuid.uuid4().hex[:12]}"

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    messages = body.get("messages", [])
    model = body.get("model", "gpt-4o")
    stream = body.get("stream", False)
    raw_prompt = extract_prompt_text(messages)
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
        # Audit log blocked request
        await db.log_request(
            request_id=req_id,
            app_id=app.app_id,
            user_id=body.get("user"),
            raw_prompt=raw_prompt,
            redacted_prompt=pii_result.redacted_text,
            model=model,
            policy_decision="block",
            matched_rules=inbound_policy.matched_rules,
            latency_ms=latency_ms,
            status_code=400,
            provider="openai"
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": inbound_policy.block_reason or "Request blocked by security policy.",
                    "type": "security_policy_violation",
                    "code": "inbound_blocked",
                    "matched_rules": inbound_policy.matched_rules,
                    "request_id": req_id
                }
            }
        )

    # 6. Apply Redaction if Policy dictates
    effective_prompt = raw_prompt
    if inbound_policy.decision == "redact" or pii_result.has_pii or pii_result.has_secrets:
        effective_prompt = pii_result.redacted_text
        body["messages"] = replace_prompt_text(messages, raw_prompt, effective_prompt)

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
                user_id=body.get("user"),
                raw_prompt=raw_prompt,
                redacted_prompt=effective_prompt,
                model=model,
                policy_decision="allow (cached)",
                matched_rules=["cache-exact-hit"],
                latency_ms=latency_ms,
                status_code=200,
                provider="openai-cache"
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
                user_id=body.get("user"),
                raw_prompt=raw_prompt,
                redacted_prompt=effective_prompt,
                model=model,
                policy_decision="allow (semantic-cached)",
                matched_rules=[f"semantic-cache-hit (similarity: {score:.2f})"],
                latency_ms=latency_ms,
                status_code=200,
                provider="openai-semantic-cache"
            )
            return JSONResponse(
                content=sem_resp,
                headers={"X-Cache-Status": "HIT", "X-Cache-Type": "semantic", "X-Semantic-Similarity": str(round(score, 3))}
            )

    # 8. Forward to Upstream or Mock Provider
    if stream:
        # Real-time Streaming Response Inspection & Mid-Stream Token Killer
        async def stream_generator():
            accumulated_chunks = []
            accumulated_text = ""
            aborted = False

            try:
                if settings.OPENAI_API_KEY and not settings.ENABLE_MOCK_UPSTREAM:
                    upstream_resp = await upstream_client.forward_openai_stream(body, dict(request.headers))
                    async for chunk in upstream_resp.aiter_bytes():
                        chunk_str = chunk.decode("utf-8", errors="ignore")
                        accumulated_chunks.append(chunk_str)
                        accumulated_text += chunk_str

                        # Sub-millisecond token killer check
                        has_leak, leak_reason = outbound_scanner.check_midstream_leak(accumulated_text)
                        if has_leak:
                            aborted = True
                            err_msg = json.dumps({
                                "error": {
                                    "message": f"[GATEWAY WAF: STREAM TERMINATED - {leak_reason.upper()}]",
                                    "type": "outbound_leak_blocked",
                                    "code": "stream_aborted",
                                    "request_id": req_id
                                }
                            })
                            yield f"data: {err_msg}\n\ndata: [DONE]\n\n".encode("utf-8")
                            break
                        yield chunk
                else:
                    async for sse_chunk in upstream_client.generate_mock_openai_stream(body):
                        accumulated_chunks.append(sse_chunk)
                        accumulated_text += sse_chunk

                        # Sub-millisecond token killer check
                        has_leak, leak_reason = outbound_scanner.check_midstream_leak(accumulated_text)
                        if has_leak:
                            aborted = True
                            err_msg = json.dumps({
                                "error": {
                                    "message": f"[GATEWAY WAF: STREAM TERMINATED - {leak_reason.upper()}]",
                                    "type": "outbound_leak_blocked",
                                    "code": "stream_aborted",
                                    "request_id": req_id
                                }
                            })
                            yield f"data: {err_msg}\n\ndata: [DONE]\n\n".encode("utf-8")
                            break
                        yield sse_chunk.encode("utf-8")
            except Exception as e:
                yield f"data: {json.dumps({'error': {'message': str(e)}})}\n\n".encode("utf-8")
                return

            # Outbound scan on accumulated stream
            full_raw_stream = "".join(accumulated_chunks)
            out_res = outbound_scanner.scan_response(full_raw_stream)
            latency_ms = (time.time() - start_time) * 1000.0
            final_decision = "block" if aborted else ("allow" if inbound_policy.decision != "redact" else "redact")
            final_status = 500 if aborted else 200

            await db.log_request(
                request_id=req_id,
                app_id=app.app_id,
                user_id=body.get("user"),
                raw_prompt=raw_prompt,
                redacted_prompt=effective_prompt,
                model=model,
                policy_decision=final_decision,
                matched_rules=inbound_policy.matched_rules + (["midstream-leak-aborted"] if aborted else []),
                latency_ms=latency_ms,
                status_code=final_status,
                provider="openai"
            )
            await db.log_response(
                request_id=req_id,
                raw_response=full_raw_stream,
                redacted_response=out_res.redacted_response,
                tool_calls_requested=[],
                tool_calls_allowed=[],
                flagged_for_review=out_res.flagged_for_review or aborted
            )

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    # Non-streaming call with Fallback Circuit Breaker
    provider_to_use, is_fallback = fallback_router.get_preferred_provider("openai")
    try:
        if provider_to_use == "openai" and settings.OPENAI_API_KEY and not settings.ENABLE_MOCK_UPSTREAM:
            upstream_resp = await upstream_client.forward_openai(body, dict(request.headers))
            if upstream_resp.status_code >= 500 or upstream_resp.status_code == 429:
                fallback_router.record_failure("openai", f"HTTP {upstream_resp.status_code}")
                raw_response_dict = upstream_client.generate_mock_openai_response(body)
            else:
                fallback_router.record_success("openai")
                raw_response_dict = upstream_resp.json()
        elif provider_to_use == "anthropic" and settings.ANTHROPIC_API_KEY and not settings.ENABLE_MOCK_UPSTREAM:
            raw_response_dict = upstream_client.generate_mock_openai_response(body)
        else:
            raw_response_dict = upstream_client.generate_mock_openai_response(body)
    except Exception as exc:
        fallback_router.record_failure(provider_to_use, str(exc))
        raw_response_dict = upstream_client.generate_mock_openai_response(body)

    # 8. Outbound Scan & Tool-Call Firewall
    first_choice = raw_response_dict.get("choices", [{}])[0]
    message_obj = first_choice.get("message", {})
    response_text = message_obj.get("content") or ""
    tool_calls = message_obj.get("tool_calls") or []

    # Outbound content inspection
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
            user_id=body.get("user"),
            raw_prompt=raw_prompt,
            redacted_prompt=effective_prompt,
            model=model,
            policy_decision="block",
            matched_rules=outbound_policy.matched_rules,
            latency_ms=latency_ms,
            status_code=500,
            provider="openai"
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "message": outbound_policy.block_reason or "Output blocked by security policy.",
                    "type": "outbound_security_violation",
                    "request_id": req_id
                }
            }
        )

    # Apply redaction to response if needed
    if outbound_res.redacted_response != response_text:
        message_obj["content"] = outbound_res.redacted_response

    # Tool-Call Firewall
    allowed_tools = []
    for tc in tool_calls:
        fn = tc.get("function", {})
        fn_name = fn.get("name", "")
        try:
            fn_args = json.loads(fn.get("arguments", "{}"))
        except Exception:
            fn_args = {}

        fw_decision = await tool_firewall.evaluate_tool_call(
            tool_name=fn_name,
            arguments=fn_args,
            request_id=req_id,
            app_id=app.app_id
        )

        if fw_decision.allowed:
            allowed_tools.append(tc)
        else:
            outbound_res.flagged_for_review = True
            if fw_decision.status == "approval_required":
                # Intercept tool call and inject approval pending status
                message_obj["content"] = (
                    f"[GATEWAY INTERCEPT]: Tool call '{fn_name}' requires human security approval "
                    f"(Approval ID: {fw_decision.approval_id}). Execution gated."
                )
            else:
                message_obj["content"] = f"[GATEWAY BLOCKED]: Tool call '{fn_name}' was blocked: {fw_decision.reason}"

    message_obj["tool_calls"] = allowed_tools if allowed_tools else None
    if not allowed_tools and "tool_calls" in message_obj and message_obj["tool_calls"] is None:
        message_obj.pop("tool_calls", None)

    latency_ms = (time.time() - start_time) * 1000.0

    # 9. Audit Logging
    all_matched = inbound_policy.matched_rules + outbound_policy.matched_rules
    final_policy_dec = "redact" if (inbound_policy.decision == "redact" or outbound_res.redacted_response != response_text) else "allow"

    background_tasks.add_task(
        db.log_request,
        request_id=req_id,
        app_id=app.app_id,
        user_id=body.get("user"),
        raw_prompt=raw_prompt,
        redacted_prompt=effective_prompt,
        model=model,
        policy_decision=final_policy_dec,
        matched_rules=all_matched,
        latency_ms=latency_ms,
        status_code=200,
        provider="openai"
    )

    background_tasks.add_task(
        db.log_response,
        request_id=req_id,
        raw_response=response_text or json.dumps(tool_calls),
        redacted_response=outbound_res.redacted_response,
        tool_calls_requested=tool_calls,
        tool_calls_allowed=allowed_tools,
        flagged_for_review=outbound_res.flagged_for_review
    )

    # Populate Caches for sub-ms future requests (exact & semantic)
    gateway_cache.set(model, effective_prompt, raw_response_dict, body.get("tools"))
    semantic_cache.store(model, effective_prompt, raw_response_dict, body.get("tools"))

    return raw_response_dict
