import json
import sqlite3
import aiosqlite
import hashlib
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
from app.config import settings

def hash_text(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

class Database:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or settings.SQLITE_DB_PATH
        self._initialized = False

    @asynccontextmanager
    async def get_connection(self):
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL;")
        try:
            yield conn
        finally:
            await conn.close()

    async def initialize(self):
        if self._initialized:
            return
        async with self.get_connection() as conn:
            # API Keys table
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                app_id TEXT PRIMARY KEY,
                api_key TEXT UNIQUE NOT NULL,
                app_name TEXT NOT NULL,
                rpm_limit INTEGER DEFAULT 60,
                tpm_limit INTEGER DEFAULT 100000,
                is_active INTEGER DEFAULT 1,
                created_at TEXT NOT NULL
            );
            """)

            # Request log table
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS request_logs (
                request_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                app_id TEXT,
                user_id TEXT,
                raw_prompt_hash TEXT,
                redacted_prompt TEXT,
                model TEXT,
                policy_decision TEXT,
                matched_rules TEXT,
                latency_ms REAL,
                status_code INTEGER DEFAULT 200,
                provider TEXT
            );
            """)

            # Response log table
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS response_logs (
                request_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                raw_response_hash TEXT,
                redacted_response TEXT,
                tool_calls_requested TEXT,
                tool_calls_allowed TEXT,
                flagged_for_review INTEGER DEFAULT 0,
                FOREIGN KEY (request_id) REFERENCES request_logs(request_id)
            );
            """)

            # Tool Approvals table
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS tool_approvals (
                approval_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                app_id TEXT,
                tool_name TEXT NOT NULL,
                tool_arguments TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            """)

            # Insert default demo API keys if not exist
            now = datetime.now(timezone.utc).isoformat()
            default_keys = [
                ("default-app", "asg_live_default_key_12345", "Production App", 120, 200000, 1, now),
                ("test-client", "asg_live_test_key_67890", "Test Client", 60, 50000, 1, now),
                ("demo-agent", "asg_live_agent_key_abcde", "Autonomous Agent", 30, 30000, 1, now),
            ]
            for app_id, key, name, rpm, tpm, active, dt in default_keys:
                await conn.execute("""
                INSERT OR IGNORE INTO api_keys (app_id, api_key, app_name, rpm_limit, tpm_limit, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (app_id, key, name, rpm, tpm, active, dt))

            await conn.commit()
            self._initialized = True

    async def get_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        async with self.get_connection() as conn:
            async with conn.execute("SELECT * FROM api_keys WHERE api_key = ? AND is_active = 1", (api_key,)) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def log_request(self, request_id: str, app_id: Optional[str], user_id: Optional[str],
                          raw_prompt: str, redacted_prompt: str, model: str,
                          policy_decision: str, matched_rules: List[str],
                          latency_ms: float, status_code: int = 200, provider: str = "openai"):
        now = datetime.now(timezone.utc).isoformat()
        prompt_hash = hash_text(raw_prompt)
        rules_json = json.dumps(matched_rules)
        async with self.get_connection() as conn:
            await conn.execute("""
            INSERT OR REPLACE INTO request_logs 
            (request_id, timestamp, app_id, user_id, raw_prompt_hash, redacted_prompt, model, policy_decision, matched_rules, latency_ms, status_code, provider)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (request_id, now, app_id, user_id, prompt_hash, redacted_prompt, model, policy_decision, rules_json, latency_ms, status_code, provider))
            await conn.commit()

    async def log_response(self, request_id: str, raw_response: str, redacted_response: str,
                           tool_calls_requested: List[Dict[str, Any]],
                           tool_calls_allowed: List[Dict[str, Any]],
                           flagged_for_review: bool = False):
        now = datetime.now(timezone.utc).isoformat()
        resp_hash = hash_text(raw_response)
        requested_json = json.dumps(tool_calls_requested)
        allowed_json = json.dumps(tool_calls_allowed)
        async with self.get_connection() as conn:
            await conn.execute("""
            INSERT OR REPLACE INTO response_logs 
            (request_id, timestamp, raw_response_hash, redacted_response, tool_calls_requested, tool_calls_allowed, flagged_for_review)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (request_id, now, resp_hash, redacted_response, requested_json, allowed_json, 1 if flagged_for_review else 0))
            await conn.commit()

    async def create_tool_approval(self, approval_id: str, request_id: str, app_id: Optional[str],
                                   tool_name: str, tool_arguments: Dict[str, Any], risk_level: str):
        now = datetime.now(timezone.utc).isoformat()
        args_json = json.dumps(tool_arguments)
        async with self.get_connection() as conn:
            await conn.execute("""
            INSERT INTO tool_approvals (approval_id, request_id, app_id, tool_name, tool_arguments, risk_level, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """, (approval_id, request_id, app_id, tool_name, args_json, risk_level, now))
            await conn.commit()

    async def resolve_tool_approval(self, approval_id: str, status: str) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        async with self.get_connection() as conn:
            cur = await conn.execute("""
            UPDATE tool_approvals 
            SET status = ?, resolved_at = ? 
            WHERE approval_id = ? AND status = 'pending'
            """, (status, now, approval_id))
            await conn.commit()
            return cur.rowcount > 0

    async def get_tool_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        async with self.get_connection() as conn:
            async with conn.execute("SELECT * FROM tool_approvals WHERE approval_id = ?", (approval_id,)) as cur:
                row = await cur.fetchone()
                return dict(row) if row else None

    async def get_pending_approvals(self) -> List[Dict[str, Any]]:
        async with self.get_connection() as conn:
            async with conn.execute("SELECT * FROM tool_approvals WHERE status = 'pending' ORDER BY created_at DESC") as cur:
                rows = await cur.fetchall()
                res = []
                for r in rows:
                    item = dict(r)
                    try:
                        item["tool_arguments"] = json.loads(item["tool_arguments"])
                    except Exception:
                        pass
                    res.append(item)
                return res

    async def get_recent_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        async with self.get_connection() as conn:
            query = """
            SELECT r.request_id, r.timestamp, r.app_id, r.user_id, r.raw_prompt_hash, 
                   r.redacted_prompt, r.model, r.policy_decision, r.matched_rules, 
                   r.latency_ms, r.status_code, r.provider,
                   resp.raw_response_hash, resp.redacted_response, 
                   resp.tool_calls_requested, resp.tool_calls_allowed, resp.flagged_for_review
            FROM request_logs r
            LEFT JOIN response_logs resp ON r.request_id = resp.request_id
            ORDER BY r.timestamp DESC
            LIMIT ?
            """
            async with conn.execute(query, (limit,)) as cur:
                rows = await cur.fetchall()
                results = []
                for r in rows:
                    item = dict(r)
                    if item.get("matched_rules"):
                        try:
                            item["matched_rules"] = json.loads(item["matched_rules"])
                        except Exception:
                            item["matched_rules"] = []
                    if item.get("tool_calls_requested"):
                        try:
                            item["tool_calls_requested"] = json.loads(item["tool_calls_requested"])
                        except Exception:
                            item["tool_calls_requested"] = []
                    if item.get("tool_calls_allowed"):
                        try:
                            item["tool_calls_allowed"] = json.loads(item["tool_calls_allowed"])
                        except Exception:
                            item["tool_calls_allowed"] = []
                    results.append(item)
                return results

    async def get_stats(self) -> Dict[str, Any]:
        async with self.get_connection() as conn:
            total_requests = 0
            blocked_requests = 0
            flagged_reviews = 0
            avg_latency = 0.0
            
            async with conn.execute("SELECT COUNT(*) as count, AVG(latency_ms) as avg_lat FROM request_logs") as cur:
                row = await cur.fetchone()
                if row:
                    total_requests = row["count"] or 0
                    avg_latency = row["avg_lat"] or 0.0

            async with conn.execute("SELECT COUNT(*) as count FROM request_logs WHERE policy_decision = 'block'") as cur:
                row = await cur.fetchone()
                if row:
                    blocked_requests = row["count"] or 0

            async with conn.execute("SELECT COUNT(*) as count FROM response_logs WHERE flagged_for_review = 1") as cur:
                row = await cur.fetchone()
                if row:
                    flagged_reviews = row["count"] or 0

            async with conn.execute("SELECT COUNT(*) as count FROM tool_approvals WHERE status = 'pending'") as cur:
                row = await cur.fetchone()
                pending_approvals = row["count"] if row else 0

            return {
                "total_requests": total_requests,
                "blocked_requests": blocked_requests,
                "allowed_requests": total_requests - blocked_requests,
                "flagged_for_review": flagged_reviews,
                "pending_tool_approvals": pending_approvals,
                "avg_latency_ms": round(avg_latency, 2)
            }

db = Database()
