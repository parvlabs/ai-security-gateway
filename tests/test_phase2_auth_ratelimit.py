import asyncio
import httpx
from app.main import app
from app.database import db

async def test_phase2_auth_and_rate_limiting():
    await db.initialize()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Test missing API key -> 401 Unauthorized
        res_no_key = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}
        )
        assert res_no_key.status_code == 401, f"Expected 401, got {res_no_key.status_code}"
        print("[Phase 2] Missing key correctly rejected (401)")

        # 2. Test invalid API key -> 403 Forbidden
        res_invalid_key = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer invalid_secret_key_xyz"},
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}
        )
        assert res_invalid_key.status_code == 403, f"Expected 403, got {res_invalid_key.status_code}"
        print("[Phase 2] Invalid key correctly rejected (403)")

        # 3. Test valid API key -> 200 OK
        valid_headers = {"Authorization": "Bearer asg_live_default_key_12345"}
        res_valid = await client.post(
            "/v1/chat/completions",
            headers=valid_headers,
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]}
        )
        assert res_valid.status_code == 200, f"Expected 200, got {res_valid.status_code}"
        print("[Phase 2] Valid key accepted (200)")

        # 4. Test Token Bucket Rate Limiting (using demo-agent key: 30 RPM limit)
        print("[Phase 2] Testing rapid rate-limit thresholding on 30 RPM app...")
        agent_headers = {"Authorization": "Bearer asg_live_agent_key_abcde"}
        rate_limited = False
        for i in range(50):
            r = await client.post(
                "/v1/chat/completions",
                headers=agent_headers,
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Short test"}]}
            )
            if r.status_code == 429:
                rate_limited = True
                print(f"[Phase 2] Rate limit triggered (429): {r.json()['detail']['message']}")
                break

        assert rate_limited, "Rate limiter did not throttle requests after exceeding RPM capacity"
        print("[Phase 2 Checkpoint PASSED]: Auth enforced and rate limiting actively protects upstream.")

if __name__ == "__main__":
    asyncio.run(test_phase2_auth_and_rate_limiting())
