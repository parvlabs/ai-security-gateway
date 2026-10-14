import asyncio
import time
from tests.test_phase1_proxy import test_phase1_openai_sdk_passthrough
from tests.test_phase2_auth_ratelimit import test_phase2_auth_and_rate_limiting
from tests.test_phase3_pii_redaction import test_phase3_pii_and_secrets
from tests.test_phase4_injection_heuristics import test_phase4_prompt_injection
from tests.test_phase5_policy_engine import test_phase5_policy_engine
from tests.test_phase6_tool_firewall import test_phase6_tool_firewall
from tests.test_phase7_output_ml_classifier import test_phase7_output_and_classifier
from tests.benchmark_latency import benchmark_latency
from tests.test_phase8_full_attack_scenario import test_full_attack_scenario

async def run_all():
    print("\n" + "=" * 70)
    print("      AI SECURITY GATEWAY — COMPLETE CHECKPOINT VERIFICATION      ")
    print("=" * 70)

    phases = [
        ("Phase 1: Pass-Through Reverse Proxy (OpenAI SDK + SSE Streaming)", test_phase1_openai_sdk_passthrough),
        ("Phase 2: Authentication & Token Bucket Rate Limiting", test_phase2_auth_and_rate_limiting),
        ("Phase 3: PII & Secrets Detection & Redaction (Planted Test Suite)", test_phase3_pii_and_secrets),
        ("Phase 4: Prompt Injection Heuristics (Base64/Homoglyph/Overrides)", test_phase4_prompt_injection),
        ("Phase 5: Configurable YAML Policy Engine (Precedence, Dry-Run, Hot-Reload)", test_phase5_policy_engine),
        ("Phase 6: Tool-Call Firewall (JSON Schema & Human Approval Queue)", test_phase6_tool_firewall),
        ("Phase 7: Outbound Response Inspection & Precision/Recall Benchmark", test_phase7_output_and_classifier),
        ("Phase 8: Latency Benchmark (<50ms Target)", benchmark_latency),
        ("Phase 8: Full End-to-End Attack Scenario & Dashboard Telemetry", test_full_attack_scenario),
    ]

    results = []
    total_start = time.perf_counter()

    for name, func in phases:
        print(f"\n>>> Running {name}...")
        t0 = time.perf_counter()
        try:
            await func()
            elapsed = (time.perf_counter() - t0) * 1000.0
            results.append((name, "PASSED", f"{elapsed:.1f}ms"))
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000.0
            results.append((name, f"FAILED: {e}", f"{elapsed:.1f}ms"))

    total_elapsed = (time.perf_counter() - total_start)

    print("\n" + "=" * 70)
    print("                         SUMMARY REPORT                         ")
    print("=" * 70)
    all_passed = True
    for name, status, duration in results:
        check = "[x]" if status == "PASSED" else "[ ]"
        print(f" {check} {name:<65} | {status:<8} | {duration}")
        if status != "PASSED":
            all_passed = False

    print("=" * 70)
    print(f"Total Verification Time: {total_elapsed:.2f}s")
    if all_passed:
        print("RESULT: ALL 8 PHASES AND CHECKPOINTS PASSED SUCCESSFULLY!")
    else:
        print("RESULT: SOME PHASES FAILED.")
    print("=" * 70 + "\n")

if __name__ == "__main__":
    asyncio.run(run_all())
