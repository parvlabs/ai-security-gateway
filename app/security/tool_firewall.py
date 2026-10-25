import os
import uuid
import yaml
import json
import jsonschema
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel
from app.config import settings
from app.database import db
from app.security.webhooks import webhook_notifier

class ToolSpec(BaseModel):
    name: str
    description: str
    risk_level: str
    requires_approval: bool
    json_schema: Dict[str, Any]

class ToolFirewallDecision(BaseModel):
    allowed: bool
    status: str  # "allowed", "blocked_unregistered", "blocked_schema_violation", "approval_required"
    risk_level: str
    reason: str
    approval_id: Optional[str] = None

class ToolFirewall:
    def __init__(self, tools_config_path: str = None):
        self.config_path = tools_config_path or settings.TOOLS_FILE_PATH
        self.tools: Dict[str, ToolSpec] = {}
        self.load_tools()

    def load_tools(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if data and "tools" in data:
                        for t in data["tools"]:
                            self.tools[t["name"]] = ToolSpec(
                                name=t["name"],
                                description=t.get("description", ""),
                                risk_level=t.get("risk_level", "medium"),
                                requires_approval=t.get("requires_approval", False),
                                json_schema=t.get("json_schema", {})
                            )
            except Exception as e:
                print(f"[ToolFirewall] Error loading tools config: {e}")

    async def evaluate_tool_call(self, tool_name: str, arguments: Dict[str, Any], request_id: str, app_id: Optional[str] = None) -> ToolFirewallDecision:
        # 1. Check if tool is registered
        if tool_name not in self.tools:
            return ToolFirewallDecision(
                allowed=False,
                status="blocked_unregistered",
                risk_level="high",
                reason=f"Tool '{tool_name}' is not in the registered tool allowlist."
            )

        spec = self.tools[tool_name]

        # 2. Validate JSON Schema
        if spec.json_schema:
            try:
                jsonschema.validate(instance=arguments, schema=spec.json_schema)
            except jsonschema.ValidationError as ve:
                return ToolFirewallDecision(
                    allowed=False,
                    status="blocked_schema_violation",
                    risk_level=spec.risk_level,
                    reason=f"Arguments for tool '{tool_name}' violated JSON schema: {ve.message}"
                )

        # 3. Check approval requirement
        if spec.requires_approval or spec.risk_level == "high":
            approval_id = f"appr_{uuid.uuid4().hex[:12]}"
            await db.create_tool_approval(
                approval_id=approval_id,
                request_id=request_id,
                app_id=app_id,
                tool_name=tool_name,
                tool_arguments=arguments,
                risk_level=spec.risk_level
            )
            # Dispatch human-in-the-loop alert via Slack & Discord webhook
            try:
                import asyncio
                asyncio.create_task(
                    webhook_notifier.notify_tool_approval_needed(
                        approval_id=approval_id,
                        tool_name=tool_name,
                        risk_level=spec.risk_level,
                        arguments=arguments,
                        request_id=request_id,
                        app_id=app_id or "default-app"
                    )
                )
            except Exception:
                pass
            return ToolFirewallDecision(
                allowed=False,
                status="approval_required",
                risk_level=spec.risk_level,
                reason=f"Tool '{tool_name}' is classified as {spec.risk_level} risk and requires human approval.",
                approval_id=approval_id
            )

        return ToolFirewallDecision(
            allowed=True,
            status="allowed",
            risk_level=spec.risk_level,
            reason="Tool call validated against allowlist schema."
        )

tool_firewall = ToolFirewall()
