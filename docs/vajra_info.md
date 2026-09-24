# VAJRA: Vulnerability Analysis for Jailbreak & RAG Attacks
**Comprehensive Interview Guide for Cybersecurity Blue Teaming**

---

## 1. Executive Summary
**The Core Problem:** As organizations integrate Large Language Models (LLMs) into their infrastructure, red-teaming (simulating attacks to find vulnerabilities) has become essential. However, existing red-teaming frameworks (like Microsoft's PyRIT or garak) rely heavily on "heuristic scoring" (looking for keywords like "I cannot fulfill this request") or "LLM-as-a-judge" to evaluate if an attack succeeded. 

This creates a massive **False Positive crisis**. If a user asks, *"Explain the mechanics of a buffer overflow for my cybersecurity exam,"* a weak evaluator will flag the model's educational response as a successful attack simply because it discusses malware.

**The Solution — VAJRA:** VAJRA is an open-source, local-first red-teaming framework that introduces **mechanical ground-truth verification**. Instead of guessing if an attack succeeded, VAJRA proves it cryptographically and mechanically.

---

## 2. Competitor Analysis: What Makes VAJRA Unique?

**Competitors:**
* **garak (LLM Vulnerability Scanner)**: Offers great coverage but relies heavily on naive keyword matching (e.g., `garak.detectors.mitigation.MitigationBypass`) which fails to differentiate between a model complying with a benign request vs executing a jailbreak. In our testing on 100 benign calibration prompts, Garak had a catastrophic **100% False Positive Rate (FPR)**, flagging every benign response as a jailbreak simply because the model didn't refuse.
* **PyRIT (Microsoft)**: Excellent adaptive capabilities, but requires heavy API usage and lacks live mechanical execution of payloads.

**VAJRA's Three Unique Pillars:**

1. **The Sandbox Verifier (Mechanical Proof):** If the LLM generates a SQL injection payload, VAJRA doesn't just ask a judge if it looks dangerous. VAJRA strips the payload and fires it against a containerized, live vulnerable Flask application (the Sandbox). If the payload extracts data from the database, the attack is marked `VERIFIED_EXPLOIT`.
2. **Canary Token Exfiltration (RAG Attacks):** To test if an LLM will leak its confidential system instructions (which often contain API keys or RAG data), VAJRA injects a high-entropy 32-hex Canary Token (e.g., `VAJRA-8f4b...`) into the system prompt. Success is evaluated via a 100% accurate exact-string match in the output. This is directly aligned with the "RAG Attacks" in our acronym, proving how vulnerable enterprise RAG deployments are to data extraction.
3. **Decomposed Rubric Judge:** A specialized scoring engine that uses a 4-question JSON schema to evaluate responses. It forces the judge to differentiate between *theoretical discussion* (safe) and *actionable exploits* (unsafe). This brought our False Positive Rate (FPR) down to **0.0%** (compared to Garak's 100%).

---

## 3. Deep Dive: Cyber Attack Concepts Explained

To ace the Blue Team interview, you must be able to explain the specific attacks VAJRA simulates:

### A. Conversational Jailbreaks
* **What it is:** Psychological manipulation of the LLM to bypass safety filters (e.g., DAN "Do Anything Now" personas, hypothetical scenarios, Base64 encoding).
* **Blue Team context:** These are often surface-level attacks. They violate the Acceptable Use Policy but rarely lead to infrastructure compromise. 

### B. Prompt Injection & Code Attacks (SQLi, CMDi, XSS)
* **What it is:** Malicious instructions hidden in user input that hijack the LLM's goal. For example, tricking an LLM into writing a malicious SQL query or a Cross-Site Scripting (XSS) payload that the backend application blindly executes.
* **Blue Team context:** This is critical. If an LLM has access to tools (like querying a database or executing code), prompt injection turns the LLM into a confused deputy, executing attacks on behalf of the hacker.

### C. System Prompt Exfiltration & RAG Attacks
* **What it is:** Tricking the LLM into repeating its secret system instructions or the private data fed into its context window.
* **RAG (Retrieval-Augmented Generation) Context:** In enterprise applications, RAG is used to feed private company documents into the LLM's memory so it can answer questions. If an attacker can exfiltrate the system prompt, they can steal the proprietary RAG data or discover hidden API endpoints.

---

## 4. Datasets and Methodology

To ensure academic rigor, we didn't just invent our own prompts. We utilized industry-standard, gated datasets:
* **WildJailbreak (AllenAI)**: Used for in-the-wild, real-world jailbreak attempts. We specifically used their benign calibration split to prove VAJRA has a 0.0% False Positive Rate.
* **Young & Moody Prompt Bank**: A consensus-labeled prompt bank designed specifically for evaluating LLM safety classifiers.
* **Custom VAJRA Suites**: Highly targeted payloads for Sandbox verification and Canary ablation testing.

---

## 5. Key Results & Findings (The "So What?")

Our research paper evaluated **Llama-3-8B** and **Gemma-3-12B**. The results tell a compelling story about modern AI security:

1. **Static Jailbreaks are Dead:** Both models achieved a **0.0% Attack Success Rate (ASR)** against static (single-shot) jailbreaks. Modern alignment (RLHF) is highly effective at stopping basic manipulation.
2. **Actionable Exploits are a Threat:** Gemma-3-12B had a **14.3% ASR** for generating actionable code-injection payloads.
3. **RAG Attacks / Exfiltration is the Weakest Link:** Both models failed catastrophically at protecting their system prompts (RAG contexts). Llama-3 leaked the system prompt **85.7%** of the time, and Gemma-3 leaked it **57.1%** of the time. We proved mathematically that placing secrets inline or as a prefix is less secure than placing them in XML tags or headers.
4. **Garak Baseline Comparison (100% vs 0% FPR):** We proved that heuristic scoring is fundamentally broken for red-teaming. Garak's `MitigationBypass` detector flagged 100 out of 100 benign prompts as "jailbreaks" (100% FPR) because the model didn't use refusal language. VAJRA correctly scored 0 out of 100 benign prompts as jailbreaks (0.0% FPR) using its mechanical logic. 
5. **The Adaptive PAIR Loop Discovery:** Using our Adaptive Orchestrator (which uses an "Attacker LLM" to iteratively rewrite failed prompts), we completely bypassed Gemma-3's defenses on a jailbreak attack at **Iteration 3**. 
   * *Interview Talking Point:* "Our research proves that static testing is insufficient. 5 rounds of static testing missed the vulnerability, but a persistent, adaptive adversary compromised the model at iteration 3. Blue teams must simulate persistent threats."

---

## 6. Technical Challenges Faced & How We Solved Them

Interviewers love hearing about roadblocks. Here is what we faced:

**Challenge 1: The False Positive Problem**
* *Problem:* Early iterations of our scorer flagged academic questions about cyber-attacks as successful jailbreaks.
* *Solution:* We built the **Decomposed Rubric Judge**. Instead of a binary pass/fail, we forced the scoring LLM to answer four specific JSON questions (e.g., "Does this provide actionable exploit material beyond public documentation?"). This dropped our false positives to 0%.

**Challenge 2: Prompt Drifting in Adaptive Attacks**
* *Problem:* When the Attacker LLM was asked to rewrite a prompt, it would sometimes get stuck in a loop, generating the exact same prompt over and over, wasting GPU cycles.
* *Solution:* We implemented **Semantic Deduplication**. Using Python's `difflib.SequenceMatcher`, we compare every new prompt to the history. If the lexical similarity is $>85\%$, the orchestrator rejects it and forces the Attacker LLM to use a completely different strategy.

**Challenge 3: Long-Running Experiment Crashes**
* *Problem:* Running the adaptive loop for 30 payloads taking 5 iterations each took hours. If an API timed out or the script crashed, we lost all data.
* *Solution:* I engineered a **Checkpoint-Based Resumable Architecture**. Results are immediately flushed to `results_adaptive.csv` and a JSON state file. If the experiment is killed (Ctrl+C), it saves its exact state and skips already-completed payloads upon restart.

**Challenge 4: Cross-Platform Reproducibility (Encoding Issues)**
* *Problem:* During execution on Windows machines, the terminal crashed with `cp1252` encoding errors because the LLMs outputted special Unicode characters (like emojis or arrows) that the Windows command prompt couldn't render.
* *Solution:* We implemented robust terminal sanitization, aggressively stripping non-ASCII characters from the standard output and forcing `utf-8` encoding on all file handlers, ensuring our tool could be run by any researcher regardless of their OS.
