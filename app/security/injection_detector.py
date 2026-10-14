import re
import base64
import unicodedata
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel

class InjectionMatch(BaseModel):
    category: str
    pattern_name: str
    matched_phrase: str
    confidence: float
    details: str

class InjectionResult(BaseModel):
    is_injection: bool
    score: float
    confidence_level: str  # "none", "low", "medium", "high", "critical"
    matched_patterns: List[InjectionMatch]
    normalized_text: str

# Common leetspeak substitutions
LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'
}

# Cyrillic and lookalike homoglyphs to ASCII mapping
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
    'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X'
}

from app.security.signatures import VIGIL_SIGNATURES

class PromptInjectionDetector:
    def __init__(self):
        # Base heuristic rules
        self.rules = [
            # Inbound Threat Signatures from Vigil & Rebuff
            *[(cat, sid, regex, score) for sid, cat, regex, score, _ in VIGIL_SIGNATURES],
            # 1. Direct instruction overrides
            ("instruction_override", "ignore_previous", 
             re.compile(r"(?i)\b(?:ignore|disregard|forget|override|neglect|bypass)\s+(?:all\s+)?(?:previous|prior|above|system|ethical|safety)?\s*(?:instructions|prompts|rules|guidelines|context|filters)\b"), 0.95),
            ("instruction_override", "new_persona_instruction", 
             re.compile(r"(?i)\b(?:from\s+now\s+on\s+you\s+are|you\s+are\s+now|act\s+as\s+an?\s+(?:unfiltered|evil|jailbroken|malicious)|behave\s+as\s+an?\s+(?:hacker|evil\s+ai|unrestricted))\b"), 0.85),
            ("instruction_override", "stop_being_an_ai", 
             re.compile(r"(?i)\b(?:stop\s+being\s+an?\s+ai|drop\s+your\s+ethical\s+guidelines|no\s+rules\s+apply)\b"), 0.90),

            # 2. Known jailbreak personas & phrases
            ("jailbreak_persona", "dan_jailbreak", 
             re.compile(r"(?i)\b(?:dan\s+mode|do\s+anything\s+now|jailbreak\s+mode|developer\s+mode\s+v[0-9]|aim\s+mode|chaos\s+mode)\b"), 0.98),
            ("jailbreak_persona", "hypothetical_bypass", 
             re.compile(r"(?i)\b(?:in\s+a\s+hypothetical\s+fictional\s+world\s+where\s+(?:morals|rules|safety|laws)\s+do\s+not\s+exist|pretend\s+there\s+are\s+no\s+safety\s+filters)\b"), 0.88),
            ("jailbreak_persona", "grandma_exploit", 
             re.compile(r"(?i)\b(?:my\s+grandma\s+used\s+to\s+read\s+me\s+napalm\s+recipes|grandma\s+bedtime\s+story\s+about\s+making\s+(?:bombs|malware|drugs))\b"), 0.95),

            # 3. System prompt leak / extraction attempts
            ("prompt_extraction", "print_system_prompt", 
             re.compile(r"(?i)\b(?:print|repeat|output|show|reveal|display|leak)\s+(?:me\s+)?(?:the\s+|your\s+)?(?:system\s+prompt|initial\s+instructions|instructions\s+above|everything\s+before\s+this|confidential\s+prompt)\b"), 0.92),
            ("prompt_extraction", "verbatim_repetition", 
             re.compile(r"(?i)\b(?:repeat\s+the\s+exact\s+text\s+of\s+(?:your\s+)?(?:system\s+)?prompt|what\s+are\s+the\s+exact\s+words\s+written\s+above)\b"), 0.88),

            # 4. Delimiter and token spoofing
            ("delimiter_spoofing", "system_tag_injection", 
             re.compile(r"(?i)(?:<\|?im_start\|?system|<system>|\[SYSTEM\]|<<SYS>>|<<<SYSTEM>>>|<assistant>|\[INST\])"), 0.90),
            ("delimiter_spoofing", "fake_dialogue_turn", 
             re.compile(r"(?i)(?:\n\s*Human:\s*.*\n\s*Assistant:\s*|\n\s*System:\s*You\s+are)"), 0.85),

            # 5. Dangerous exfiltration triggers
            ("exfiltration", "markdown_image_exfil", 
             re.compile(r"!\[.*?\]\(https?://[^\s)]+\?[^\s)]*=(?:[^\s)]+)\)"), 0.80),
        ]

    def normalize(self, text: str) -> str:
        """Strip zero-width characters, homoglyphs, collapse leetspeak, normalize whitespace."""
        # 1. Unicode decomposition
        normalized = unicodedata.normalize('NFKD', text)
        
        # 2. Homoglyph translation
        homoglyph_clean = "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in normalized)

        # 3. Strip zero-width and control characters
        cleaned = re.sub(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]", "", homoglyph_clean)

        # 4. Collapse whitespace
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned

    def check_base64_payloads(self, text: str) -> List[Tuple[str, str]]:
        """Finds base64 encoded strings (>16 chars), decodes them, and returns decoded payloads."""
        results = []
        b64_candidate_regex = re.compile(r"\b([A-Za-z0-9+/]{16,}={0,2})\b")
        for match in b64_candidate_regex.finditer(text):
            candidate = match.group(1)
            try:
                decoded_bytes = base64.b64decode(candidate)
                decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
                # If decoded text looks like natural language or commands (ASCII printable)
                if len(decoded_text) > 8 and all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in decoded_text):
                    results.append((candidate, decoded_text))
            except Exception:
                continue
        return results

    def detect(self, text: str) -> InjectionResult:
        if not text or not text.strip():
            return InjectionResult(
                is_injection=False,
                score=0.0,
                confidence_level="none",
                matched_patterns=[],
                normalized_text=""
            )

        norm_text = self.normalize(text)
        matched_patterns: List[InjectionMatch] = []
        highest_score = 0.0

        # Scan normalized text
        for category, pattern_name, regex, base_score in self.rules:
            for match in regex.finditer(norm_text):
                matched_patterns.append(InjectionMatch(
                    category=category,
                    pattern_name=pattern_name,
                    matched_phrase=match.group(0),
                    confidence=base_score,
                    details=f"Matched heuristic rule {pattern_name} with confidence {base_score}"
                ))
                if base_score > highest_score:
                    highest_score = base_score

        # Check leetspeak variant
        leet_transformed = "".join(LEET_MAP.get(ch.lower(), ch) for ch in norm_text)
        if leet_transformed != norm_text:
            for category, pattern_name, regex, base_score in self.rules:
                for match in regex.finditer(leet_transformed):
                    # Only add if not already matched
                    if not any(m.pattern_name == pattern_name for m in matched_patterns):
                        matched_patterns.append(InjectionMatch(
                            category=category,
                            pattern_name=f"{pattern_name}_leetspeak",
                            matched_phrase=match.group(0),
                            confidence=base_score * 0.95,
                            details="Detected via leetspeak deobfuscation"
                        ))
                        if (base_score * 0.95) > highest_score:
                            highest_score = base_score * 0.95

        # Check base64 obfuscated payloads
        b64_payloads = self.check_base64_payloads(text)
        for raw_b64, decoded in b64_payloads:
            for category, pattern_name, regex, base_score in self.rules:
                for match in regex.finditer(decoded):
                    matched_patterns.append(InjectionMatch(
                        category=category,
                        pattern_name=f"base64_obfuscated_{pattern_name}",
                        matched_phrase=f"Base64 '{raw_b64}' -> '{match.group(0)}'",
                        confidence=base_score,
                        details="Detected hidden payload inside Base64 encoding"
                    ))
                    if base_score > highest_score:
                        highest_score = base_score

        # Multi-factor score boost: if multiple distinct categories triggered, increase score
        distinct_categories = set(m.category for m in matched_patterns)
        composite_score = highest_score
        if len(distinct_categories) > 1:
            composite_score = min(1.0, highest_score + (len(distinct_categories) - 1) * 0.05)

        # Confidence level categorization
        if composite_score >= 0.85:
            conf_level = "critical"
        elif composite_score >= 0.70:
            conf_level = "high"
        elif composite_score >= 0.50:
            conf_level = "medium"
        elif composite_score > 0.0:
            conf_level = "low"
        else:
            conf_level = "none"

        is_injection = composite_score >= 0.70

        return InjectionResult(
            is_injection=is_injection,
            score=round(composite_score, 3),
            confidence_level=conf_level,
            matched_patterns=matched_patterns,
            normalized_text=norm_text
        )

injection_detector = PromptInjectionDetector()
