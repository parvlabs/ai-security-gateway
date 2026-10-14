import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import db
from app.proxy.openai_proxy import router as openai_router
from app.proxy.anthropic_proxy import router as anthropic_router
from app.security.policy_engine import policy_engine
from app.security.tool_firewall import tool_firewall
from app.dashboard.html_ui import DASHBOARD_HTML

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables and policies
    await db.initialize()
    policy_engine.load_policies()
    tool_firewall.load_tools()
    print("[AI Security Gateway] Core proxy engine initialized successfully.")
    yield
    # Shutdown
    print("[AI Security Gateway] Shutting down.")

app = FastAPI(
    title="AI Security Gateway",
    description="Drop-in reverse proxy WAF for OpenAI and Anthropic SDK traffic",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for frontend clients / dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount SDK Proxy Routers
app.include_router(openai_router, tags=["OpenAI Compatible Proxy"])
app.include_router(anthropic_router, tags=["Anthropic Compatible Proxy"])

# Serve Web Dashboard
@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

# Gateway Health Check
@app.get("/api/health", tags=["Health"])
async def health():
    return {
        "status": "healthy",
        "service": "ai-security-gateway",
        "mock_upstream": settings.ENABLE_MOCK_UPSTREAM,
        "openai_configured": bool(settings.OPENAI_API_KEY),
        "anthropic_configured": bool(settings.ANTHROPIC_API_KEY)
    }

# Gateway Metrics & Stats
@app.get("/api/stats", tags=["Telemetry"])
async def get_stats():
    from app.proxy.cache import gateway_cache
    stats_data = await db.get_stats()
    stats_data.update(gateway_cache.stats())
    return stats_data

# Gateway Audit Log Feed
@app.get("/api/audit-logs", tags=["Telemetry"])
async def get_audit_logs(limit: int = 50):
    return await db.get_recent_audit_logs(limit=limit)

# Tool Approvals Management
@app.get("/api/approvals", tags=["Tool Firewall"])
async def get_pending_approvals():
    return await db.get_pending_approvals()

@app.post("/api/approvals/{approval_id}/approve", tags=["Tool Firewall"])
@app.post("/api/approvals/{approval_id}/approved", tags=["Tool Firewall"])
async def approve_tool(approval_id: str):
    success = await db.resolve_tool_approval(approval_id, "approved")
    if not success:
        raise HTTPException(status_code=404, detail="Approval request not found or already resolved.")
    return {"status": "approved", "approval_id": approval_id}

@app.post("/api/approvals/{approval_id}/reject", tags=["Tool Firewall"])
@app.post("/api/approvals/{approval_id}/rejected", tags=["Tool Firewall"])
async def reject_tool(approval_id: str):
    success = await db.resolve_tool_approval(approval_id, "rejected")
    if not success:
        raise HTTPException(status_code=404, detail="Approval request not found or already resolved.")
    return {"status": "rejected", "approval_id": approval_id}

# Policy Management & Hot-Reload
@app.get("/api/policy/rules", tags=["Policy Engine"])
async def get_policy_rules():
    return {
        "rules": [r.model_dump() for r in policy_engine.rules]
    }

@app.post("/api/policy/reload", tags=["Policy Engine"])
async def reload_policies():
    policy_engine.load_policies()
    tool_firewall.load_tools()
    return {"status": "reloaded", "rules_count": len(policy_engine.rules)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
