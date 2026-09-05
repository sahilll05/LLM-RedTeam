# Architecture — VAJRA

## System Overview

VAJRA is a modular, plugin-based security testing framework for LLM applications.
Every component has a single responsibility and can be swapped or extended independently.

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLI  (vajra.py / typer)                      │
│   python vajra.py scan --config config.yaml --suite jailbreak    │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                ┌───────────────▼───────────────┐
                │     Orchestrator (core.py)     │
                │  · load_config()               │
                │  · load_payloads()             │
                │  · load_target()               │
                │  · run_scan() main loop        │
                └───────┬───────────────┬────────┘
                        │               │
           ┌────────────▼──────┐  ┌─────▼──────────────────┐
           │   Payload Loader  │  │   Target Adapter        │
           │   payloads/*.yaml │  │   targets/*.py          │
           └────────────┬──────┘  └─────┬──────────────────┘
                        │               │
            ┌───────────▼───────────┐   │
            │  Script: ingest_hf.py │   │
            │  (HF to YAML sync)    │   │
            └───────────┬───────────┘   │
                        └───────┬───────┘
                                │
                   ┌────────────▼───────────┐
                   │    Scoring Engine      │
                   │    engine/scorer.py    │
                   │  · HeuristicScorer     │
                   │  · LLMJudgeScorer      │
                   └────────────┬───────────┘
                                │
                   ┌────────────▼───────────┐
                   │   Results Store        │
                   │   engine/storage.py    │
                   │   (SQLite)             │
                   └────────────┬───────────┘
                                │
                   ┌────────────▼───────────┐
                   │   Report Generator     │
                   │   engine/report.py     │
                   │  · CLI (rich table)    │
                   │  · HTML (Jinja2)       │
                   └────────────────────────┘
```

### Folder Structure

```text
VAJRA/
├── vajra.py               # Typer-based command line interface
├── config.yaml            # Main configuration (targets, suites, scoring)
├── engine/
│   ├── core.py            # Orchestrator: runs the scan loop
│   ├── scorer.py          # Two-tier scoring engine (heuristic + llm_judge)
│   └── database.py        # SQLite persistence layer
├── targets/
│   ├── base.py            # BaseTarget interface
│   ├── ollama_target.py   # Local Ollama integration
│   ├── openai_target.py   # OpenAI / Anthropic integration
│   ├── http_target.py     # Generic HTTP REST endpoint integration
│   └── rag_target.py      # Simulated RAG pipeline
├── payloads/              # YAML attack definitions
│   ├── jailbreak.yaml
│   ├── injection.yaml
│   └── wildjailbreak.yaml # Auto-generated from Hugging Face
├── scripts/
│   └── ingest_hf.py       # Downloads research datasets offline
├── reports/               # HTML/JSON outputs
└── data/                  # Cached offline TSV datasets
```

---

## Component Descriptions

### CLI (`vajra.py`)
Entry point using **Typer**. Exposes five commands:
- `scan` — run a full red-team scan
- `list-runs` — list past runs from SQLite
- `report` — regenerate report for a past run
- `validate` — check config, payload files, and target connectivity
- `ingest` — download and ingest Hugging Face research datasets

### Orchestrator (`engine/core.py`)
Controls the main scan loop. Responsibilities:
- Parse `config.yaml`
- Load the correct target adapter via factory function
- Load YAML payload files for the requested suites
- Iterate payloads: dispatch multi-turn and indirect injection to specialised handlers
- Forward results to scorer and store
- Isolates per-payload errors so one failure doesn't abort the whole run

### Target Adapters (`targets/`)
Each adapter implements `BaseTarget.send(prompt, system_prompt, history) -> str`
and `BaseTarget.normalize_response(raw) -> str`.

Normalization strips model-specific artifacts (reasoning blocks like `<think>`,
code block wrappers, RAG context markers) before the response reaches the scorer.
Adding a new adapter requires implementing `send()` and optionally overriding
`normalize_response()` for target-specific cleanup.

| Adapter | Protocol | Auth |
|---|---|---|
| `OllamaTarget` | Ollama REST API | None |
| `OpenAITarget` | OpenAI Chat Completions | API Key |
| `AnthropicTarget` | Anthropic Messages API | API Key |
| `HTTPTarget` | Arbitrary HTTP | Configurable |
| `RAGTarget` | Wraps any adapter + document injection | Inherited |

### Payload Library (`payloads/`)
YAML files with structured records. All schemas include `negative_indicators` —
explicit refusal phrases that suppress false positives when found alongside
success indicators. Three schemas:

**Single-turn** (jailbreak, injection, exfiltration):
```yaml
id, category, technique, description, prompt,
success_indicators, negative_indicators, severity
```

**Multi-turn** (multi_turn):
```yaml
id, category, technique, description,
messages: [{role, content}],
success_indicators, negative_indicators, severity
```

**Indirect injection** (indirect_injection):
```yaml
id, category, technique, description,
document_content, user_query,
success_indicators, negative_indicators, severity
```

### Scoring Engine (`engine/scorer.py`)
**Layer 1 — WeightedHeuristicScorer**
Produces a continuous confidence score (0.0–1.0) by weighing:
- **Positive indicator matches** — evidence of compliance (lowers score toward COMPLIED)
- **Refusal pattern matches** — regex library of 13+ refusal patterns (raises score toward REFUSED)
- **Negative indicator matches** — per-payload explicit refusal phrases (raises score, suppresses FP)
- **Educational framing detection** — phrases like 'for educational purposes' (raises score, suppresses false positives on theoretical discussions)
- **Strong refusal override** — if the model clearly refused, incidental keyword matches cannot drag the verdict to COMPLIED

The confidence score is mapped to a verdict via **per-suite thresholds** (configurable in `config.yaml`).

**Layer 2 — LLMJudgeScorer**
Sends `(attack_prompt, model_response)` to a judge LLM with **7 curated few-shot examples**
covering compliance, refusal, partial leak, fictional framing, and exfiltration. The judge explicitly distinguishes between **educational theory** (which is safe/REFUSED) and **actionable exploits** (which are COMPLIED).
Robust JSON parsing handles markdown code blocks and malformed output.

**ScoringEngine modes:**
- `heuristic` → Layer 1 only (fast, free)
- `llm_judge` → Layer 2 only (accurate)
- `both` → Layer 1 for clear signals; Layer 2 for `PARTIAL_LEAK` only (cost-efficient)

### Results Store (`engine/storage.py`)
SQLite database at `reports/results.db`. Two tables:
- `runs` — metadata per scan run
- `results` — one row per payload, linked to run by `run_id`

Enables trend analysis: re-run after hardening and compare scores.

### Report Generator (`engine/report.py`)
- **CLI** — `rich` tables with category pass rates and worst offenders
- **HTML** — Jinja2 template (`templates/report.html.j2`), self-contained,
  no external CDN dependencies, works offline. Includes:
  - Risk gauge (0–100, colour-coded: LOW / MODERATE / HIGH / CRITICAL)
  - Category breakdown table with pass-rate bars
  - Filterable full results table with collapsible response snippets
  - Auto-generated OWASP-referenced mitigation suggestions

---

## Data Flow — Single Payload

```
payload.yaml
    │
    ├── id, category, technique, severity
    ├── prompt (or document_content + user_query for indirect)
    └── success_indicators
         │
         ▼
target.send(prompt, system_prompt) ──► LLM response (str)
         │
         ▼
scorer.score(attack_prompt, response, indicators)
         │
         ├── HeuristicScorer.score() → COMPLIED | REFUSED | PARTIAL_LEAK
         │   (if mode == "both" and PARTIAL_LEAK):
         └── LLMJudgeScorer.score() → COMPLIED | REFUSED | PARTIAL_LEAK
         │
         ▼
PayloadResult(run_id, verdict, score, justification, ...)
         │
         ▼
ResultsStore.save_result()  →  SQLite
```

---

## Adding a New Target Adapter

1. Create `targets/my_target.py`
2. Inherit from `BaseTarget`
3. Implement `send(prompt, system_prompt, history) -> str`
4. Add a branch in `engine/core.py::load_target()`
5. Add `type: my_target` option in `config.yaml` documentation

## Adding a New Payload Suite

1. Create `payloads/my_suite.yaml` following existing schema
2. Add `my_suite` to `suites:` in `config.yaml`
3. The orchestrator will automatically pick it up
