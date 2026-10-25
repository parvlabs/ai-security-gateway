import json
import time
import uuid
import httpx
from typing import Dict, Any, AsyncGenerator, Optional
from app.config import settings

class UpstreamClient:
    def __init__(self):
        self.http_client = httpx.AsyncClient(timeout=60.0)

    async def forward_openai(self, request_body: Dict[str, Any], headers: Dict[str, str]) -> httpx.Response:
        url = f"{settings.OPENAI_BASE_URL.rstrip('/')}/chat/completions"
        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.OPENAI_API_KEY or 'mock-key'}"
        }
        return await self.http_client.post(url, json=request_body, headers=req_headers)

    async def forward_openai_stream(self, request_body: Dict[str, Any], headers: Dict[str, str]):
        url = f"{settings.OPENAI_BASE_URL.rstrip('/')}/chat/completions"
        req_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.OPENAI_API_KEY or 'mock-key'}"
        }
        req = self.http_client.build_request("POST", url, json=request_body, headers=req_headers)
        return await self.http_client.send(req, stream=True)

    async def forward_anthropic(self, request_body: Dict[str, Any], headers: Dict[str, str]) -> httpx.Response:
        url = f"{settings.ANTHROPIC_BASE_URL.rstrip('/')}/messages"
        req_headers = {
            "Content-Type": "application/json",
            "x-api-key": settings.ANTHROPIC_API_KEY or 'mock-key',
            "anthropic-version": headers.get("anthropic-version", "2023-06-01")
        }
        return await self.http_client.post(url, json=request_body, headers=req_headers)

    async def forward_anthropic_stream(self, request_body: Dict[str, Any], headers: Dict[str, str]):
        url = f"{settings.ANTHROPIC_BASE_URL.rstrip('/')}/messages"
        req_headers = {
            "Content-Type": "application/json",
            "x-api-key": settings.ANTHROPIC_API_KEY or 'mock-key',
            "anthropic-version": headers.get("anthropic-version", "2023-06-01")
        }
        req = self.http_client.build_request("POST", url, json=request_body, headers=req_headers)
        return await self.http_client.send(req, stream=True)

    # --- MOCK PROVIDER GENERATORS FOR OFFLINE DEVELOPMENT & VERIFICATION ---
    def generate_mock_openai_response(self, request_body: Dict[str, Any]) -> Dict[str, Any]:
        messages = request_body.get("messages", [])
        last_content = messages[-1].get("content", "") if messages else ""
        model = request_body.get("model", "gpt-4o")
        req_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        now = int(time.time())

        # Check if caller asks for tool execution
        tools = request_body.get("tools", [])
        if "delete" in last_content.lower() and any(t.get("function", {}).get("name") == "delete_record" for t in tools):
            tool_call = {
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {
                    "name": "delete_record",
                    "arguments": json.dumps({"table_name": "users", "record_id": "usr_9921", "cascade": True})
                }
            }
            return {
                "id": req_id,
                "object": "chat.completion",
                "created": now,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [tool_call]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"prompt_tokens": 40, "completion_tokens": 25, "total_tokens": 65}
            }

        if "weather" in last_content.lower() and any(t.get("function", {}).get("name") == "get_weather" for t in tools):
            tool_call = {
                "id": f"call_{uuid.uuid4().hex[:8]}",
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "arguments": json.dumps({"location": "San Francisco, CA", "units": "celsius"})
                }
            }
            return {
                "id": req_id,
                "object": "chat.completion",
                "created": now,
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [tool_call]
                    },
                    "finish_reason": "tool_calls"
                }],
                "usage": {"prompt_tokens": 30, "completion_tokens": 20, "total_tokens": 50}
            }

        # Check canary leak test
        if "canary" in last_content.lower():
            reply_text = f"I am leaking internal canary: {settings.CANARY_TOKENS[0]} as requested."
        else:
            reply_text = f"Hello! I am a secured AI model response for: '{last_content[:60]}'."

        return {
            "id": req_id,
            "object": "chat.completion",
            "created": now,
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": reply_text
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 25, "completion_tokens": 15, "total_tokens": 40}
        }

    async def generate_mock_openai_stream(self, request_body: Dict[str, Any]) -> AsyncGenerator[str, None]:
        req_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"
        model = request_body.get("model", "gpt-4o")
        messages = request_body.get("messages", [])
        last_content = messages[-1].get("content", "") if messages else ""

        if "stream_canary_leak" in last_content.lower():
            words = f"Initial stream data... Exfiltrating canary: {settings.CANARY_TOKENS[0]} now followed by trailing chunks.".split()
        else:
            words = f"Hello! I am an AI stream chunk responding safely to: {last_content[:30]}".split()
        for i, word in enumerate(words):
            chunk = {
                "id": req_id,
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": {"content": word + " " if i > 0 else word},
                    "finish_reason": None
                }]
            }
            yield f"data: {json.dumps(chunk)}\n\n"

        # Final stop chunk
        stop_chunk = {
            "id": req_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        }
        yield f"data: {json.dumps(stop_chunk)}\n\n"
        yield "data: [DONE]\n\n"

    def generate_mock_anthropic_response(self, request_body: Dict[str, Any]) -> Dict[str, Any]:
        messages = request_body.get("messages", [])
        last_content = messages[-1].get("content", "") if messages else ""
        model = request_body.get("model", "claude-3-5-sonnet-20241022")
        req_id = f"msg_{uuid.uuid4().hex[:16]}"

        return {
            "id": req_id,
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{
                "type": "text",
                "text": f"This is Claude answering through the AI Security Gateway: {last_content[:50]}"
            }],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 20, "output_tokens": 18}
        }

    async def generate_mock_anthropic_stream(self, request_body: Dict[str, Any]) -> AsyncGenerator[str, None]:
        msg_id = f"msg_{uuid.uuid4().hex[:16]}"
        model = request_body.get("model", "claude-3-5-sonnet-20241022")

        yield f"event: message_start\ndata: {json.dumps({'type': 'message_start', 'message': {'id': msg_id, 'type': 'message', 'role': 'assistant', 'model': model, 'content': [], 'stop_reason': None, 'usage': {'input_tokens': 15, 'output_tokens': 1}}})}\n\n"
        yield f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}})}\n\n"

        chunks = ["Streaming ", "response ", "from ", "Anthropic ", "via ", "Security ", "Gateway."]
        for c in chunks:
            yield f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': c}})}\n\n"

        yield f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': 0})}\n\n"
        yield f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None}, 'usage': {'output_tokens': 15}})}\n\n"
        yield f"event: message_stop\ndata: {json.dumps({'type': 'message_stop'})}\n\n"

upstream_client = UpstreamClient()
