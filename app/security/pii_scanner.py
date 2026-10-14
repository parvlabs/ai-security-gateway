import re
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel

class DetectedEntity(BaseModel):
    entity_type: str
    original: str
    start: int
    end: int
    confidence: float
    is_secret: bool = False

class ScanResult(BaseModel):
    text: str
    redacted_text: str
    has_pii: bool
    has_secrets: bool
    entities: List[DetectedEntity]

def luhn_checksum(card_number: str) -> bool:
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0

class PIIScanner:
    def __init__(self):
        # Compiled patterns
        self.secret_patterns = [
            ("AWS_ACCESS_KEY", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 1.0),
            ("OPENAI_API_KEY", re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,})\b"), 0.99),
            ("ANTHROPIC_API_KEY", re.compile(r"\b(sk-ant-[a-zA-Z0-9_-]{20,})\b"), 0.99),
            ("GITHUB_TOKEN", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"), 1.0),
            ("PRIVATE_KEY", re.compile(r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----"), 1.0),
            ("GENERIC_BEARER_SECRET", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})['\"]?\b"), 0.85),
        ]

        self.pii_patterns = [
            ("SSN", re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), 0.95),
            ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), 0.98),
            ("PHONE_NUMBER", re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"), 0.85),
            ("INTERNAL_IP_HOSTNAME", re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9_\-]+\.(?:internal|corp|local))\b"), 0.90),
        ]

        self.credit_card_pattern = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    def scan(self, text: str) -> ScanResult:
        if not text:
            return ScanResult(text="", redacted_text="", has_pii=False, has_secrets=False, entities=[])

        entities: List[DetectedEntity] = []

        # 1. Scan Secrets
        for name, pattern, conf in self.secret_patterns:
            for match in pattern.finditer(text):
                matched_val = match.group(0)
                entities.append(DetectedEntity(
                    entity_type=name,
                    original=matched_val,
                    start=match.start(),
                    end=match.end(),
                    confidence=conf,
                    is_secret=True
                ))

        # 2. Scan PII
        for name, pattern, conf in self.pii_patterns:
            for match in pattern.finditer(text):
                matched_val = match.group(0)
                entities.append(DetectedEntity(
                    entity_type=name,
                    original=matched_val,
                    start=match.start(),
                    end=match.end(),
                    confidence=conf,
                    is_secret=False
                ))

        # 3. Credit Card with Luhn validation
        for match in self.credit_card_pattern.finditer(text):
            raw_candidate = match.group(0)
            cleaned = re.sub(r"\D", "", raw_candidate)
            if luhn_checksum(cleaned):
                entities.append(DetectedEntity(
                    entity_type="CREDIT_CARD",
                    original=raw_candidate,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.99,
                    is_secret=False
                ))

        # Deduplicate overlapping entities (prefer higher confidence / longer match)
        entities.sort(key=lambda e: (e.start, -(e.end - e.start)))
        filtered_entities: List[DetectedEntity] = []
        last_end = -1
        for e in entities:
            if e.start >= last_end:
                filtered_entities.append(e)
                last_end = e.end

        # Build redacted text
        redacted_chars = list(text)
        # Apply redaction in reverse order to keep character indices stable
        for e in sorted(filtered_entities, key=lambda x: x.start, reverse=True):
            placeholder = f"[REDACTED_{e.entity_type}]"
            redacted_chars[e.start:e.end] = list(placeholder)

        redacted_text = "".join(redacted_chars)
        has_pii = any(not e.is_secret for e in filtered_entities)
        has_secrets = any(e.is_secret for e in filtered_entities)

        return ScanResult(
            text=text,
            redacted_text=redacted_text,
            has_pii=has_pii,
            has_secrets=has_secrets,
            entities=filtered_entities
        )

pii_scanner = PIIScanner()
