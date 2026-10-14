import time
import asyncio
import statistics
import httpx
from app.main import app
from app.database import db

async def benchmark_latency():
    """
    Phase 8 Requirement:
    Load testing / latency verification: confirm <50ms inspection latency overhead.
    """
    await db.initialize()
    transport = httpx.ASGITransport(app=app)
    headers = {"Authorization": "Bearer asg_live_default_key_12345"}

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        print("\n=== AI Security Gateway Latency Benchmark ===")
        # Warm-up
        for _ in range(5):
            await client.post(
                "/v1/chat/completions",
                headers=headers,
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "warmup"}]}
            )

        latencies = []
        num_requests = 100

        print(f"Running {num_requests} concurrent/sequential requests through the full security pipeline...")
        for i in range(num_requests):
            t0 = time.perf_counter()
            resp = await client.post(
                "/v1/chat/completions",
                headers=headers,
                json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": f"Request {i}: What are the best practices for secure API gateway design?"}]
                }
            )
            t1 = time.perf_counter()
            elapsed_ms = (t1 - t0) * 1000.0
            latencies.append(elapsed_ms)
            assert resp.status_code == 200

        avg_latency = statistics.mean(latencies)
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        p99 = sorted(latencies)[int(len(latencies) * 0.99)]

        print(f"  - Average Round-Trip Latency: {avg_latency:.2f} ms")
        print(f"  - P50 (Median) Latency:       {p50:.2f} ms")
        print(f"  - P95 Latency:                {p95:.2f} ms")
        print(f"  - P99 Latency:                {p99:.2f} ms")

        # Gateway overhead target: < 50ms
        assert avg_latency < 50.0, f"Average latency {avg_latency:.2f}ms exceeded 50ms threshold!"
        print(f"\n[Latency Benchmark PASSED]: Average latency {avg_latency:.2f}ms is well within the <50ms requirement!")

if __name__ == "__main__":
    asyncio.run(benchmark_latency())
