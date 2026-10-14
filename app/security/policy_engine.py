import os
import yaml
import time
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.config import settings

class PolicyRule(BaseModel):
    name: str
    on: str  # "inbound", "outbound", "tool_call"
    match: Any  # "injection_heuristic", "secret_detected", "pii_detected", or {"tool": "xxx"}
    action: str  # "allow", "block", "redact", "require_approval", "flag"
    min_confidence: Optional[float] = 0.5
    dry_run: bool = False
    message: Optional[str] = None

class PolicyEvaluationResult(BaseModel):
    decision: str  # "allow", "block", "redact", "require_approval"
    matched_rules: List[str]
    block_reason: Optional[str] = None
    dry_run_matches: List[str] = []

class PolicyEngine:
    def __init__(self, policy_path: str = None):
        self.policy_path = policy_path or settings.POLICY_FILE_PATH
        self.rules: List[PolicyRule] = []
        self._last_loaded_mtime: float = 0
        self.load_policies()

    def check_and_reload(self):
        """Hot-reload policies if the YAML file was modified."""
        if os.path.exists(self.policy_path):
            current_mtime = os.path.getmtime(self.policy_path)
            if current_mtime > self._last_loaded_mtime:
                self.load_policies()

    def load_policies(self):
        if not os.path.exists(self.policy_path):
            print(f"[PolicyEngine] Policy file {self.policy_path} not found. Using default rules.")
            return

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                new_rules = []
                if data and "rules" in data:
                    for r in data["rules"]:
                        on_val = r.get("on") if "on" in r else r.get(True, "inbound")
                        new_rules.append(PolicyRule(
                            name=r["name"],
                            on=str(on_val),
                            match=r.get("match"),
                            action=r.get("action", "allow"),
                            min_confidence=r.get("min_confidence", 0.5),
                            dry_run=r.get("dry_run", False),
                            message=r.get("message")
                        ))
                self.rules = new_rules
                self._last_loaded_mtime = os.path.getmtime(self.policy_path)
                print(f"[PolicyEngine] Loaded {len(self.rules)} rules from {self.policy_path}")
        except Exception as e:
            print(f"[PolicyEngine] Failed to load policy file: {e}")

    def evaluate_inbound(self, injection_detected: bool, injection_score: float, 
                         has_secrets: bool, has_pii: bool) -> PolicyEvaluationResult:
        self.check_and_reload()
        decision = "allow"
        matched_rules = []
        dry_run_matches = []
        block_reason = None

        for rule in self.rules:
            if rule.on != "inbound":
                continue

            matched = False
            # Match condition
            if rule.match == "injection_heuristic" and injection_detected:
                if injection_score >= (rule.min_confidence or 0.5):
                    matched = True
            elif rule.match == "secret_detected" and has_secrets:
                matched = True
            elif rule.match == "pii_detected" and has_pii:
                matched = True

            if matched:
                if rule.dry_run:
                    dry_run_matches.append(rule.name)
                    # Dry run does not alter decision
                    continue

                matched_rules.append(rule.name)
                if rule.action == "block":
                    decision = "block"
                    block_reason = rule.message or f"Blocked by rule '{rule.name}'"
                    # Highest priority, stop processing
                    break
                elif rule.action == "redact":
                    if decision != "block":
                        decision = "redact"

        return PolicyEvaluationResult(
            decision=decision,
            matched_rules=matched_rules,
            block_reason=block_reason,
            dry_run_matches=dry_run_matches
        )

    def evaluate_outbound(self, canary_leaked: bool, has_secrets: bool) -> PolicyEvaluationResult:
        self.check_and_reload()
        decision = "allow"
        matched_rules = []
        dry_run_matches = []
        block_reason = None

        for rule in self.rules:
            if rule.on != "outbound":
                continue

            matched = False
            if rule.match == "system_prompt_leak" and canary_leaked:
                matched = True
            elif rule.match == "secret_detected" and has_secrets:
                matched = True

            if matched:
                if rule.dry_run:
                    dry_run_matches.append(rule.name)
                    continue

                matched_rules.append(rule.name)
                if rule.action == "block":
                    decision = "block"
                    block_reason = rule.message or f"Response blocked by rule '{rule.name}'"
                    break
                elif rule.action == "redact":
                    if decision != "block":
                        decision = "redact"

        return PolicyEvaluationResult(
            decision=decision,
            matched_rules=matched_rules,
            block_reason=block_reason,
            dry_run_matches=dry_run_matches
        )

policy_engine = PolicyEngine()
