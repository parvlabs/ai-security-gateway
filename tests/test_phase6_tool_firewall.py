import json
import asyncio
import httpx
from app.main import app
from app.database import db
from app.security.tool_firewall import tool_firewall

async def test_phase6_tool_firewall():
    await db.initialize()
    transport = httpx.ASGITransport(app=app)
    headers = {"Authorization": "Bearer asg_live_default_key_12345"}

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        print("\n[Phase 6] Testing tool-call firewall with mock agentic application...")

        # 1. Low-risk safe tool: get_weather
        weather_payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "What is the weather in San Francisco?"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get current weather",
                    "parameters": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}, "units": {"type": "string"}},
                        "required": ["location"]
                    }
                }
            }]
        }

        res_safe = await client.post("/v1/chat/completions", headers=headers, json=weather_payload)
        assert res_safe.status_code == 200
        safe_choice = res_safe.json()["choices"][0]["message"]
        assert "tool_calls" in safe_choice and safe_choice["tool_calls"] is not None
        assert safe_choice["tool_calls"][0]["function"]["name"] == "get_weather"
        print("  - Low-risk tool 'get_weather' allowed and passed through to app.")

        # 2. Schema violation: test evaluator on invalid parameters
        bad_args_decision = await tool_firewall.evaluate_tool_call(
            tool_name="get_weather",
            arguments={"units": "celsius"},  # missing required 'location'
            request_id="test_req_invalid",
            app_id="default-app"
        )
        assert not bad_args_decision.allowed
        assert bad_args_decision.status == "blocked_schema_violation"
        print("  - Schema violation caught and blocked: " + bad_args_decision.reason)

        # 3. Unregistered malicious tool
        unreg_decision = await tool_firewall.evaluate_tool_call(
            tool_name="unregistered_shell_exec",
            arguments={"cmd": "rm -rf /"},
            request_id="test_req_unreg",
            app_id="default-app"
        )
        assert not unreg_decision.allowed
        assert unreg_decision.status == "blocked_unregistered"
        print("  - Unregistered tool caught and blocked: " + unreg_decision.reason)

        # 4. CHECKPOINT: Dangerous High-Risk Tool (delete_record)
        # Agent calls delete_record -> Gateway intercepts and queues for human approval
        delete_payload = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "Please delete record with ID usr_9921 from the users table."}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "delete_record",
                    "description": "Delete record",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "table_name": {"type": "string"},
                            "record_id": {"type": "string"},
                            "cascade": {"type": "boolean"}
                        },
                        "required": ["table_name", "record_id"]
                    }
                }
            }]
        }

        res_delete = await client.post("/v1/chat/completions", headers=headers, json=delete_payload)
        assert res_delete.status_code == 200
        del_choice = res_delete.json()["choices"][0]["message"]
        # The tool call must NOT be allowed to execute directly by the app
        assert "tool_calls" not in del_choice or del_choice["tool_calls"] is None
        assert "[GATEWAY INTERCEPT]" in del_choice["content"]
        assert "Approval ID" in del_choice["content"]
        print(f"  - Dangerous tool intercepted: {del_choice['content']}")

        # 5. Check Approval Queue API
        approvals_res = await client.get("/api/approvals")
        assert approvals_res.status_code == 200
        pending = approvals_res.json()
        assert len(pending) > 0
        latest_approval = pending[0]
        assert latest_approval["tool_name"] == "delete_record"
        print(f"  - Verified pending approval in queue: ID={latest_approval['approval_id']}, tool={latest_approval['tool_name']}")

        # 6. Approve the request via Human-in-the-Loop API
        approve_action = await client.post(f"/api/approvals/{latest_approval['approval_id']}/approve")
        assert approve_action.status_code == 200
        assert approve_action.json()["status"] == "approved"
        print("  - Successfully resolved approval via Human-in-the-Loop API.")

        print("\n[Phase 6 Checkpoint PASSED]: Dangerous tool call caught, schema validated, and queued for approval.")

if __name__ == "__main__":
    asyncio.run(test_phase6_tool_firewall())
