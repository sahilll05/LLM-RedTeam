# VAJRA — Vulnerability Analysis for Jailbreak & RAG Attacks

<p align="center">
  <img src="logo.png" alt="VAJRA Logo" width="600">
</p>

> **VAJRA** — *Vulnerability Analysis for Jailbreak & RAG Attacks*
>
> Inspired by the **Vajra (वज्र)**, the divine thunderbolt weapon of Indra in Hindu mythology —
> symbolizing strength and the power to overcome formidable forces.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP LLM Top 10](https://img.shields.io/badge/taxonomy-OWASP%20LLM%20Top%2010-red.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

VAJRA is an open-source LLM red-teaming framework that introduces **mechanical ground-truth verification** to AI security testing. Instead of relying solely on heuristic keyword matching or unreliable LLM-as-a-judge scoring, VAJRA proves vulnerabilities cryptographically (via Canary Token exfiltration) and mechanically (via live Sandboxed code execution). 

Think of it as **Burp Suite, but for AI apps.**

---

## Core Innovations

| Feature | Details |
|---|---|
| **Mechanical Verification** | Live sandbox execution for code injection (SQLi, CMDi, XSS) and high-entropy Canary Tokens for proving exfiltration. |
| **Adaptive Orchestrator** | Uses a PAIR-style iterative loop with semantic deduplication to automatically refine and mutate attacks that were initially refused. |
| **Decomposed Rubric Judge** | A specialized JSON-schema scorer that achieves a **0.0% False Positive Rate** by distinguishing between theoretical discussion and actionable exploits. |
| **5 attack suites** | Jailbreak, Direct Injection, Exfiltration, Indirect Injection (RAG), Multi-Turn Escalation. |
| **5 target adapters** | Ollama (local/free), OpenAI, Anthropic, generic HTTP endpoint, RAG pipeline simulation. |
| **Resumable Architecture** | Checkpoint-based JSON state tracking ensures long-running adaptive campaigns never lose data upon interruption. |
| **Zero API cost** | Full demo loop runs locally via Ollama — no tokens spent. |
| **HTML + CLI reports** | Risk score, category breakdown, response snippets, OWASP mitigations. |

---

## Quick Start

### Prerequisites

1. **Python 3.11+** and **Git**
2. **Ollama** (for zero-cost local testing):
   - Download: https://ollama.com/download
   - Pull a model: `ollama pull hermes` or `ollama pull llama3`

### Install

```bash
git clone https://github.com/sahilll05/LLM-RedTeam.git
cd LLM-RedTeam
pip install -r requirements.txt
```

### Run your first scan

```bash
# Validate config and target connectivity first
python vajra.py validate

# Run a scan (uses config.yaml defaults: Ollama, jailbreak + injection + exfiltration)
python vajra.py scan

# Run specific suites only
python vajra.py scan --suite jailbreak --suite injection

# Run with overrides (target, model, scoring, output)
python vajra.py scan --target ollama --model gpt-4o-mini --scoring llm_judge --output json

# Dry-run: list payloads without sending any requests
python vajra.py scan --dry-run
```

The HTML report opens automatically in your browser after the scan.

### Ingest Research Datasets (Optional)

Enhance your test suites by downloading massive, academic-grade adversarial datasets. They are cached locally so all future runs are 100% offline.

```bash
# Ingest 100 payloads from AllenAI's WildJailbreak dataset
python vajra.py ingest --dataset wildjailbreak --count 100

# Add it to config.yaml 'suites:', then run scan
```

---

## Configuration

Edit `config.yaml` to point at your target:

```yaml
target:
  type: ollama      # ollama | openai | anthropic | http | rag
  model: hermes
  base_url: http://localhost:11434
  system_prompt: "You are a helpful customer support assistant."

suites:
  - jailbreak
  - injection
  - exfiltration

scoring:
  mode: heuristic   # heuristic | llm_judge | both
```

### Testing a real chatbot HTTP endpoint

```yaml
target:
  type: http
  endpoint: http://localhost:8080/chat
  request_template: '{"message": "$prompt"}'
  response_field: reply
```

### Testing a RAG pipeline (indirect injection)

```yaml
target:
  type: rag
  inner_target_type: ollama
  model: hermes
  base_url: http://localhost:11434
  knowledge_base_dir: ./data/docs
```

### Using OpenAI or Anthropic

```yaml
target:
  type: openai
  model: gpt-4o-mini
  # api_key: set here or export OPENAI_API_KEY=<your-key>
```

---

## Attack Suites

| Suite | Payloads | Attack Type | OWASP Reference |
|---|---|---|---|
| `jailbreak` | 8 | Role-play overrides, fictional framing, developer mode | LLM01 |
| `injection` | 7 | Direct instruction override, system prompt replacement | LLM01 |
| `exfiltration` | 7 | System prompt leakage, config disclosure | LLM06 |
| `indirect_injection` | 6 | RAG/document poisoning, hidden instructions | LLM01 (Indirect) |
| `multi_turn` | 5 | Gradual escalation over conversation sequences | LLM01 |
| `wildjailbreak` | 100+ | Auto-ingested from Hugging Face research | LLM01 |

---

## Scoring

**Weighted Heuristic scorer** (default):
Uses a continuous confidence score (0.0–1.0) and config-driven **per-suite thresholds** (e.g. exfiltration requires higher sensitivity). It weighs:
- **Positive indicators**: Evidence of compliance
- **Refusal patterns**: Regex library of 13+ refusal patterns
- **Negative indicators**: Explicit refusal phrases defined per-payload to suppress false positives
- **Strong refusal override**: If the model clearly refused, incidental keyword matches cannot drag the verdict to COMPLIED.

Returns one of three verdicts:
- `COMPLIED` — attack succeeded
- `REFUSED` — model safely declined
- `PARTIAL_LEAK` — ambiguous result (score falls between thresholds)

**LLM-as-judge** (enable with `scoring.mode: llm_judge` or `both`):
A separate model evaluates `(attack_prompt, model_response)` pairs. It is prompted with **5 curated few-shot examples** and uses robust JSON parsing to return a structured verdict with a justification. In `both` mode, the judge is only called for `PARTIAL_LEAK` results, saving API costs while maintaining high accuracy.

**Risk score**: `(1 - avg_pass_rate) × 100`. Ranges from 0 (fully secure) to 100 (critical).

---

## CLI Reference

```
python vajra.py scan          Run a scan (use --help to see all options like -t, -m, -o, -s)
python vajra.py validate      Check config, payloads, and target connectivity
python vajra.py list-runs     List all past scan runs
python vajra.py report <id>   Regenerate report for a past run
python vajra.py ingest        Ingest Hugging Face datasets into VAJRA format
```

---

## Extending the Framework

### Add a target adapter

1. Create `targets/my_target.py`, inherit from `BaseTarget`
2. Implement `send(prompt, system_prompt, history) -> str`
3. Add a branch in `engine/core.py::load_target()`

### Add a payload suite

1. Create `payloads/my_suite.yaml` following the existing schema
2. Add `my_suite` to `suites:` in `config.yaml`

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full details.

---

## Ethical Use

- Only test systems you **own** or have **explicit written permission** to test
- This payload library is a **security research and defensive testing tool**, not an exploit kit
- Payload techniques are categorised by OWASP LLM Top 10 taxonomy
- Do not use against production systems without a signed security testing agreement

---

## Comparison to Existing Tools

| Feature | VAJRA | NVIDIA garak | Microsoft PyRIT |
|---|---|---|---|
| Canary exfiltration proofs | ✅ | ❌ | ❌ |
| Sandboxed exploit verifier | ✅ | ❌ | ❌ |
| Decomposed rubric judge | ✅ | ❌ | Partial |
| Adaptive (PAIR) orchestrator | ✅ | ❌ | ✅ |
| Target: any HTTP endpoint | ✅ | ❌ | ❌ |
| Open-source, local-first | ✅ | ✅ | Partial |

---

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Greshake et al. (2023) — Indirect Prompt Injection](https://arxiv.org/abs/2302.12173)
- [Perez & Ribeiro (2022) — Ignore Previous Prompt](https://arxiv.org/abs/2211.09527)
- [AllenAI WildJailbreak Dataset](https://huggingface.co/datasets/allenai/wildjailbreak)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

---

## Author

**Sahil Powar** — [github.com/sahilll05](https://github.com/sahilll05)

Project repository: [github.com/sahilll05/LLM-RedTeam](https://github.com/sahilll05/LLM-RedTeam)

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute with attribution.

> This tool is for **defensive security research only**. Only test systems you own
> or have explicit written permission to test. See [LICENSE](LICENSE) for the full ethical use notice.
