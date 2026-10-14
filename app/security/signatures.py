"""
Threat signature library synthesized from Vigil LLM, Rebuff, and Gandalf/JailbreakBench corpora.
Covers:
- Tokenizer & ChatML Delimiter Injections
- Role-play & Cognitive Hacking Personas
- System Instruction Extraction & Inversion
- Adversarial Suffixes & Control Token Spoofing
- Indirect Injection & Multi-Turn Primers
"""

import re
from typing import List, Tuple

# Compiled regex signatures: (id, category, regex, severity, description)
VIGIL_SIGNATURES: List[Tuple[str, str, re.Pattern, float, str]] = [
    # 1. ChatML & Tokenizer Delimiter Injections
    (
        "SIG_CHATML_DELIM",
        "tokenizer_injection",
        re.compile(r"(?i)(?:<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|\[/?INST\]|<<SYS>>|<SYS>|\[/?SYSTEM\]|<\|begin_of_text\|>)"),
        0.98,
        "Attempt to inject raw model tokenizer delimiters or ChatML control tags."
    ),
    (
        "SIG_PSEUDO_SYSTEM_BLOCK",
        "delimiter_spoofing",
        re.compile(r"(?i)(?:###\s*System(?:\s*Prompt)?\s*:|System:\s*You\s+are\s+now|<<\s*PROMPT\s*OVERRIDE\s*>>|===SYSTEM INSTRUCTIONS===)"),
        0.92,
        "Attempt to forge an authentic System instruction header inside user message."
    ),

    # 2. Universal Instruction Inversion & Overrides
    (
        "SIG_OVERRIDE_PRIOR",
        "instruction_override",
        re.compile(r"(?i)\b(?:ignore|disregard|forget|overwrite|nullify|bypass|abandon)\s+(?:all\s+)?(?:prior|previous|initial|established|system|safety|security)\s+(?:rules|instructions|prompts|guidelines|guardrails|constraints)\b"),
        0.98,
        "Explicit attempt to override all established system prompts and constraints."
    ),
    (
        "SIG_NEW_DIRECTIVE",
        "instruction_override",
        re.compile(r"(?i)\b(?:your\s+new\s+(?:task|mandate|instructions?|rules?)\s+(?:are|is)|everything\s+before\s+this\s+was\s+(?:a\s+test|false|irrelevant)|reset\s+to\s+factory\s+state)\b"),
        0.90,
        "Attempt to declare a new authoritative directive resetting previous instructions."
    ),

    # 3. Known Adversarial Personas (DAN, AIM, Chaos, Jailbreaks)
    (
        "SIG_DAN_PERSONAS",
        "adversarial_persona",
        re.compile(r"(?i)\b(?:DAN\s*(?:mode|v[0-9]+)?|Do\s+Anything\s+Now|AIM\s+mode|Always\s+Intelligent\s+and\s+Machiavellian|AntiGPT|DUDE\s+mode|STAN\s+mode|Jailbreak\s+Prompt)\b"),
        0.99,
        "Known jailbreak persona signature matching DAN, AIM, AntiGPT or variants."
    ),
    (
        "SIG_EVIL_TWIN",
        "adversarial_persona",
        re.compile(r"(?i)\b(?:pretend\s+you\s+have\s+an\s+evil\s+twin|respond\s+as\s+your\s+evil\s+counterpart|act\s+as\s+a\s+rogue\s+ai|generate\s+two\s+responses:\s*one\s+normal\s+and\s+one\s+unfiltered)\b"),
        0.95,
        "Dual-response or evil-twin cognitive evasion technique."
    ),

    # 4. Prompt Extraction & Reconnaissance
    (
        "SIG_PROMPT_LEAK",
        "prompt_extraction",
        re.compile(r"(?i)\b(?:what\s+(?:are|were)\s+your\s+(?:exact\s+)?(?:instructions|rules|system\s+prompt)|output\s+(?:your\s+)?(?:full\s+)?initial\s+prompt|repeat\s+everything\s+above\s+starting\s+with)\b"),
        0.92,
        "Direct attempt to extract internal system instructions or reconnaissance."
    ),
    (
        "SIG_CANARY_PROBE",
        "prompt_extraction",
        re.compile(r"(?i)\b(?:reveal|show|print|echo)\s+(?:the\s+)?(?:canary|secret\s+key|confidential\s+token|system\s+uuid)\b"),
        0.88,
        "Attempt to extract confidential canary security tokens."
    ),

    # 5. Dangerous Content Exploits (Grandma / Fictional Evasion)
    (
        "SIG_FICTIONAL_EXPLOIT",
        "cognitive_evasion",
        re.compile(r"(?i)\b(?:write\s+a\s+fiction(?:al)?\s+story\s+where\s+(?:a\s+character\s+makes|how\s+to\s+build)\s+(?:a\s+bomb|malware|ransomware|nerve\s+agent)|in\s+a\s+movie\s+script\s+explain\s+how\s+to\s+synthesize)\b"),
        0.94,
        "Fictional framing designed to extract dangerous weaponized or harmful material."
    ),
    (
        "SIG_GRANDMA_EXPLOIT",
        "cognitive_evasion",
        re.compile(r"(?i)\b(?:my\s+deceased\s+grandmother\s+used\s+to\s+work\s+in\s+a\s+chemical\s+plant|grandmother\s+used\s+to\s+read\s+me\s+napalm\s+recipes\s+as\s+a\s+lullaby)\b"),
        0.98,
        "Famous emotional appeal exploit to bypass chemical/weapons guardrails."
    ),

    # 6. SSRF & Dangerous Tool Execution Primers
    (
        "SIG_TOOL_SSRF_TRIGGER",
        "tool_abuse",
        re.compile(r"(?i)(?:http://(?:169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1:[0-9]+|localhost:[0-9]+)|file:///etc/passwd|file:///windows/win\.ini)"),
        0.96,
        "Cloud metadata service or local file SSRF attack payload."
    )
]
