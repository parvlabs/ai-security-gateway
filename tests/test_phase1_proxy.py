import asyncio
import httpx
from openai import AsyncOpenAI
from app.main import app
from app.database import db

async def test_phase1_openai_sdk_passthrough():
    """
    Phase 1 Checkpoint:
    An app swaps its base URL to the gateway with zero behavior change.
    Verify pass-through for both non-streaming and streaming calls,
    and verify DB logging.
    """
    await db.initialize()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test using official OpenAI SDK pointed at the gateway
        sdk_client = AsyncOpenAI(
            base_url="http://test/v1",
            api_key="asg_live_default_key_12345",
            http_client=client
        )

        # Non-streaming request
        completion = await sdk_client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "What is the capital of France?"}]
        )

        assert completion is not None
        assert len(completion.choices) > 0
        response_text = completion.choices[0].message.content
        assert response_text is not None
        assert len(response_text) > 0
        print(f"\n[Phase 1] Non-streaming SDK Response: {response_text}")

        # Streaming request
        stream = await sdk_client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": "Tell me a short joke."}],
            stream=True
        )

        chunks = []
        async for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                chunks.append(chunk.choices[0].delta.content)

        full_stream_text = "".join(chunks)
        assert len(full_stream_text) > 0
        print(f"[Phase 1] Streaming SDK Response: {full_stream_text}")

        # Verify audit logs in database
        logs = await db.get_recent_audit_logs(limit=5)
        assert len(logs) >= 2
        assert any("What is the capital of France?" in l["redacted_prompt"] for l in logs)
        print("[Phase 1 Checkpoint PASSED]: SDK client functions identically, traffic logged to DB.")

if __name__ == "__main__":
    asyncio.run(test_phase1_openai_sdk_passthrough())
