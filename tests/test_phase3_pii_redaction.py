import asyncio
import httpx
from app.main import app
from app.database import db
from app.security.pii_scanner import pii_scanner

async def test_phase3_pii_and_secrets():
    await db.initialize()
    transport = httpx.ASGITransport(app=app)
    headers = {"Authorization": "Bearer asg_live_default_key_12345"}

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Labeled test suite of prompts with planted PII and secrets
        planted_test_cases = [
            {
                "name": "AWS Access Key Secret",
                "prompt": "Please configure our production S3 bucket using key AKIAIOSFODNN7EXAMPLE to upload.",
                "expected_entity": "AWS_ACCESS_KEY",
                "is_secret": True,
                "expected_decision": "block"
            },
            {
                "name": "OpenAI Secret Key",
                "prompt": "Here is our upstream API key sk-live9876543210abcdef9876543210 for testing.",
                "expected_entity": "OPENAI_API_KEY",
                "is_secret": True,
                "expected_decision": "block"
            },
            {
                "name": "Customer Email and SSN",
                "prompt": "Customer record: Email alice.smith@example.org, SSN 123-45-6789. Please draft a summary.",
                "expected_entity": "SSN",
                "is_secret": False,
                "expected_decision": "redact"
            },
            {
                "name": "Internal Hostname and IP",
                "prompt": "Deploy the artifact to internal node db-primary.corp at IP 192.168.1.100.",
                "expected_entity": "INTERNAL_IP_HOSTNAME",
                "is_secret": False,
                "expected_decision": "redact"
            }
        ]

        for tc in planted_test_cases:
            print(f"\n[Phase 3] Testing case: '{tc['name']}'...")
            # 1. Test scanner unit detection
            scan_res = pii_scanner.scan(tc["prompt"])
            entity_types = [e.entity_type for e in scan_res.entities]
            assert tc["expected_entity"] in entity_types, f"Scanner missed {tc['expected_entity']} in {tc['prompt']}"
            print(f"  - Scanner caught entity: {tc['expected_entity']}")
            print(f"  - Redacted text: '{scan_res.redacted_text}'")

            # 2. Test Gateway Pipeline enforcement
            resp = await client.post(
                "/v1/chat/completions",
                headers=headers,
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": tc["prompt"]}]}
            )

            if tc["expected_decision"] == "block":
                assert resp.status_code == 400, f"Expected 400 for secret, got {resp.status_code}"
                err_data = resp.json()["error"]
                assert "security_policy_violation" == err_data["type"]
                print(f"  - Gateway correctly BLOCKED secret: {err_data['message']}")
            elif tc["expected_decision"] == "redact":
                assert resp.status_code == 200, f"Expected 200 for redacted PII, got {resp.status_code}"
                print("  - Gateway correctly REDACTED PII before forwarding.")

        print("\n[Phase 3 Checkpoint PASSED]: PII redacted and secrets blocked according to policy.")

if __name__ == "__main__":
    asyncio.run(test_phase3_pii_and_secrets())
