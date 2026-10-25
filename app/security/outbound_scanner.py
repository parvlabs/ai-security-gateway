import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.config import settings
from app.security.pii_scanner import pii_scanner

class OutboundScanResult(BaseModel):
    is_safe: bool
    flagged_for_review: bool
    reasons: List[str]
    redacted_response: str
    canary_leaked: bool

class OutboundScanner:
    def __init__(self, canary_tokens: List[str] = None):
        self.canary_tokens = canary_tokens or settings.CANARY_TOKENS
        self.exfil_markdown_regex = re.compile(r"!\[.*?\]\((https?://[^\s)]+)\)")
        self.system_prompt_markers = [
            "You are a helpful assistant instructed by",
            "CONFIDENTIAL INSTRUCTIONS:",
            "BEGIN INTERNAL SYSTEM PROMPT",
            "DO NOT SHARE THIS PROMPT WITH USERS"
        ]

    def scan_response(self, response_text: str, known_system_prompt: Optional[str] = None) -> OutboundScanResult:
        if not response_text:
            return OutboundScanResult(
                is_safe=True,
                flagged_for_review=False,
                reasons=[],
                redacted_response="",
                canary_leaked=False
            )

        reasons = []
        canary_leaked = False
        flagged = False

        # 1. Check canary token leaks (static & dynamic Rebuff tokens)
        from app.security.canary_service import canary_manager
        dynamic_canary = canary_manager.check_leak(response_text)
        if dynamic_canary:
            canary_leaked = True
            flagged = True
            reasons.append(f"Dynamic canary token '{dynamic_canary}' detected in response (Rebuff guardrail violation).")

        for canary in self.canary_tokens:
            if canary in response_text:
                canary_leaked = True
                flagged = True
                reasons.append(f"Canary token '{canary}' detected in response (System prompt leakage).")

        # 2. Check system prompt markers
        for marker in self.system_prompt_markers:
            if marker.lower() in response_text.lower():
                flagged = True
                reasons.append(f"Internal system prompt marker '{marker}' detected in response.")

        # 3. Check known system prompt verbatim chunk overlap if provided
        if known_system_prompt and len(known_system_prompt) > 30:
            # Check 30-char sliding windows
            clean_sys = known_system_prompt.strip()
            if len(clean_sys) > 50 and clean_sys[:50] in response_text:
                flagged = True
                reasons.append("Verbatim prefix of system prompt detected in response.")

        # 4. Check data exfiltration links (markdown image tracking)
        exfil_matches = self.exfil_markdown_regex.findall(response_text)
        if exfil_matches:
            flagged = True
            reasons.append(f"Suspicious markdown image link detected (potential data exfiltration): {exfil_matches[0]}")

        # 5. Check secrets/PII in outbound response
        pii_res = pii_scanner.scan(response_text)
        if pii_res.has_secrets:
            flagged = True
            reasons.append("Secret key or credential detected in outbound response.")
            cleaned_text = pii_res.redacted_text
        elif pii_res.has_pii:
            cleaned_text = pii_res.redacted_text
        else:
            cleaned_text = response_text

        # Redact canary if leaked
        for canary in self.canary_tokens:
            cleaned_text = cleaned_text.replace(canary, "[REDACTED_SYSTEM_CANARY]")

        is_safe = not canary_leaked and not any("Secret" in r for r in reasons)

        return OutboundScanResult(
            is_safe=is_safe,
            flagged_for_review=flagged,
            reasons=reasons,
            redacted_response=cleaned_text,
            canary_leaked=canary_leaked
        )

    def check_midstream_leak(self, text: str) -> Tuple[bool, str]:
        """
        Sub-millisecond sliding window check for streaming responses (Token Killer).
        Returns: (has_leak: bool, reason: str)
        """
        if not text:
            return False, ""
        # Check static canaries
        for canary in self.canary_tokens:
            if canary in text:
                return True, f"Canary token '{canary}' detected mid-stream"
        # Check dynamic canary pattern (rb_canary_)
        if "rb_canary_" in text:
            return True, "Dynamic canary token prefix detected mid-stream"
        # Check high-severity secret patterns
        if "sk-proj-" in text or "sk-ant-" in text or "ghp_" in text or "AKIA" in text:
            return True, "API Key / Cloud Secret detected mid-stream"
        return False, ""

outbound_scanner = OutboundScanner()
