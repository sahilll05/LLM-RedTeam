# DATASETS.md — Dataset Sourcing, Licenses, and Redistribution Policy

This document lists every third-party dataset integrated into VAJRA, its origin, license, access terms, and redistribution rules.

> [!CAUTION]
> **NEVER commit raw prompt text from gated datasets to this repository.**
> WildJailbreak and the Young & Moody prompt bank are both gated on Hugging Face under research-use terms. Only ingestion scripts are committed. Generated YAML files from gated data are listed in `.gitignore`. Anyone wishing to reproduce experiments must accept the respective dataset terms and authenticate with their own Hugging Face token.

---

## 1. WildJailbreak (AllenAI)

| Field | Value |
|---|---|
| **Authors** | Jiang et al. (NeurIPS 2024) |
| **Paper** | [arXiv:2406.18510](https://arxiv.org/abs/2406.18510) |
| **HF Dataset Card** | [allenai/wildjailbreak](https://huggingface.co/datasets/allenai/wildjailbreak) |
| **License** | AI2 Responsible Use License (gated) |
| **Access** | Requires accepting AI2's Responsible Use Agreement on the HF dataset page + HF token |
| **What we use** | `adversarial_harmful` split → `payloads/wildjailbreak.yaml` (attack payloads)<br>`vanilla_benign` + `adversarial_benign` splits → `payloads/calibration/wjb_benign_vanilla.yaml`, `payloads/calibration/wjb_benign_adversarial.yaml` (false-positive calibration) |
| **Accurate description** | WildJailbreak is a **synthetic** dataset. Its WildTeaming pipeline mines jailbreak *tactics* (5.7K unique clusters) from real in-the-wild user-chatbot interactions, then uses GPT-4/Mixtral-8x7B to **compose new synthetic prompts** by applying combinations of those mined tactics to harmful queries. Say it this way in papers; do NOT describe it as "262,000+ prompts collected from real users." |
| **Gitignore rule** | `payloads/wildjailbreak.yaml`, `payloads/calibration/wjb_*.yaml`, and `data/wildjailbreak_train.tsv` are gitignored. |
| **Setup** | Accept terms → `huggingface-cli login` → `python scripts/ingest_hf.py` |

---

## 2. JailbreakBench (JBB-Behaviors)

| Field | Value |
|---|---|
| **Authors** | Chao et al. (NeurIPS 2024, Datasets & Benchmarks Track) |
| **Paper** | [arXiv:2404.01318](https://arxiv.org/abs/2404.01318) |
| **HF Dataset Card** | [JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors) |
| **License** | MIT License — safe to redistribute |
| **Access** | Public (no gating) |
| **What we use** | `behaviors.csv` (100 harmful behaviors) → `payloads/jailbreak.yaml` seeds<br>`benign-behaviors.csv` (100 topic-matched benign counterparts) → `payloads/calibration/jbb_benign.yaml` |
| **Accurate description** | 100 harmful behaviors across 10 categories aligned with OpenAI's usage policy, **plus** 100 topic-matched benign counterparts (the `benign-behaviors.csv` file). This benign split is uniquely suited for testing whether a scorer distinguishes *intent* while holding *topic* constant. NOT just "200 specific malicious behaviors." |
| **Gitignore rule** | MIT-licensed; YAML output may be committed. However, to keep the repo lean, `data/jbb_behaviors.csv` (raw download cache) is gitignored; only the processed YAML is committed. |
| **Setup** | Public — `python scripts/ingest_hf.py --dataset jbb` (no HF token required) |

---

## 3. Young & Moody Consensus-Labeled Prompt Bank

| Field | Value |
|---|---|
| **Authors** | Young & Moody (2026) |
| **Primary paper** | [arXiv:2605.03179](https://arxiv.org/abs/2605.03179) — "Executable Weapons vs. Security Knowledge" |
| **Companion paper** | [arXiv:2605.28734](https://arxiv.org/abs/2605.28734) — expanded release |
| **HF Dataset Card** | Research-use gated — verify exact ID on HF before first use |
| **License** | Research-use terms (gated) |
| **Access** | Requires accepting terms on HF dataset page + HF token |
| **What we use** | Full bank (1,554 prompts) for external validation of VAJRA's decomposed rubric judge. Labeled CODE (actionable malicious) vs. KNOWLEDGE (non-actionable security theory) via 5-LLM consensus (Fleiss' κ = 0.876). |
| **Gitignore rule** | `payloads/calibration/young_moody_*.yaml` and `data/young_moody_bank.json` are gitignored. |
| **Setup** | Accept terms → `huggingface-cli login` → `python scripts/ingest_young_moody.py` |

---

## Calibration Set Rationale

A calibration set of benign prompts is required to measure VAJRA's false-positive rate on superficially sensitive but genuinely safe queries. Rather than building a custom calibration set from scratch, VAJRA uses existing, purpose-built, published calibration data from the datasets above:

| Calibration Split | Source | Rows | What it tests |
|---|---|---|---|
| `vanilla_benign` | WildJailbreak | 50,050 | Benign prompts that superficially resemble unsafe requests |
| `adversarial_benign` | WildJailbreak | 78,706 | Benign prompts run through the same adversarial tactic transformation as harmful ones |
| `benign-behaviors.csv` | JailbreakBench | 100 | Topic-matched benign counterparts (intent vs. topic) |
| Young & Moody KNOWLEDGE | Young & Moody | ~777 | Non-actionable security knowledge questions |

This follows the methodology of XSTest (Röttger et al., 2024) and is strictly better for paper purposes than a self-constructed calibration set.

---

## Gitignore Summary

The following patterns in `.gitignore` enforce the redistribution policy:

```
# Gated dataset raw data — never commit
data/
payloads/calibration/
payloads/wildjailbreak.yaml
```

---

## Setting Up Your Own HF Token

1. Create a Hugging Face account at [huggingface.co](https://huggingface.co)
2. Go to each gated dataset's card and accept the terms of use
3. Authenticate: `huggingface-cli login` (or set the `HF_TOKEN` environment variable)
4. Run the ingestion scripts as documented above
