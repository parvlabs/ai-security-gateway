"""
Webhook Dispatcher for Human-in-the-Loop Tool Approvals (Slack & Discord).
Dispatches rich actionable alert cards when a high-risk tool call is intercepted by the Tool Firewall.
"""

import json
import logging
import httpx
from typing import Dict, Any, Optional
from app.config import settings

logger = logging.getLogger("gateway.webhooks")

class WebhookNotifier:
    def __init__(self):
        self.slack_url = settings.SLACK_WEBHOOK_URL
        self.discord_url = settings.DISCORD_WEBHOOK_URL
        self.base_url = settings.PUBLIC_GATEWAY_URL.rstrip("/")

    async def notify_tool_approval_needed(
        self,
        approval_id: str,
        tool_name: str,
        risk_level: str,
        arguments: Dict[str, Any],
        request_id: str,
        app_id: Optional[str] = "default-app"
    ) -> Dict[str, bool]:
        """
        Dispatches approval notifications to configured Slack and Discord webhooks.
        Returns a dict indicating dispatch status per provider: {"slack": bool, "discord": bool}.
        """
        status = {"slack": False, "discord": False}
        approve_url = f"{self.base_url}/api/approvals/{approval_id}/approve"
        reject_url = f"{self.base_url}/api/approvals/{approval_id}/reject"
        args_str = json.dumps(arguments, indent=2)
        if len(args_str) > 500:
            args_str = args_str[:500] + "... [truncated]"

        # 1. Slack Dispatch
        if self.slack_url:
            try:
                slack_payload = {
                    "text": f"🚨 [AI Gateway] Human Approval Required: `{tool_name}` ({risk_level.upper()})",
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": "🛡️ AI Security Gateway — Tool Execution Intercepted"
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Tool:*\n`{tool_name}`"},
                                {"type": "mrkdwn", "text": f"*Risk Level:*\n*{risk_level.upper()}*"},
                                {"type": "mrkdwn", "text": f"*Approval ID:*\n`{approval_id}`"},
                                {"type": "mrkdwn", "text": f"*App ID:*\n`{app_id}`"}
                            ]
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Arguments:*\n```{args_str}```"
                            }
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "✅ Approve Tool Call"},
                                    "style": "primary",
                                    "url": approve_url
                                },
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "❌ Reject Tool Call"},
                                    "style": "danger",
                                    "url": reject_url
                                }
                            ]
                        }
                    ]
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(self.slack_url, json=slack_payload)
                    status["slack"] = (resp.status_code == 200)
            except Exception as e:
                logger.error(f"[WebhookNotifier] Slack notification error: {e}")

        # 2. Discord Dispatch
        if self.discord_url:
            try:
                color = 0xEF4444 if risk_level == "high" else 0xF59E0B
                discord_payload = {
                    "username": "AI Security Gateway",
                    "avatar_url": "https://img.icons8.com/color/96/shield.png",
                    "embeds": [
                        {
                            "title": f"🚨 Tool Execution Approval Required: {tool_name}",
                            "description": f"The AI Security Gateway intercepted a **{risk_level.upper()}** risk tool invocation requiring explicit human authorization.",
                            "color": color,
                            "fields": [
                                {"name": "Tool Name", "value": f"`{tool_name}`", "inline": True},
                                {"name": "Risk Level", "value": f"**{risk_level.upper()}**", "inline": True},
                                {"name": "Approval ID", "value": f"`{approval_id}`", "inline": False},
                                {"name": "Request ID", "value": f"`{request_id}`", "inline": False},
                                {"name": "Arguments", "value": f"```{args_str}```", "inline": False},
                                {"name": "Quick Action Links", "value": f"[✅ Approve Tool Call]({approve_url}) | [❌ Reject Tool Call]({reject_url})", "inline": False}
                            ],
                            "footer": {
                                "text": "AI-WAF Sentinel • Zero-Trust LLM Tool Firewall"
                            }
                        }
                    ]
                }
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.post(self.discord_url, json=discord_payload)
                    status["discord"] = (resp.status_code in (200, 204))
            except Exception as e:
                logger.error(f"[WebhookNotifier] Discord notification error: {e}")

        return status

webhook_notifier = WebhookNotifier()
