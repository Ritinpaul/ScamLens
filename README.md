# ScamLens 🔍🛡️

**Privacy-First Local Scam & Social Engineering Analyzer**

> Built for the **Hacktoberfest 2026 Weekend Challenge**.

---

## 🎯 What is ScamLens?

ScamLens is an open-source, local-first security tool designed to protect everyday users, friends, and family from predatory scams arriving via WhatsApp, SMS, Telegram, emails, and delivery alerts.

Unlike typical cloud scanners that upload personal chats and screenshots to third-party APIs, **ScamLens performs 100% of its analysis locally** on your machine using an open-source model via Ollama and deterministic security checks.

---

## 🏗️ Architecture: Separation of Concerns

ScamLens operates under a core security principle:

> **"The model understands the message. The verifier checks the message. The decision layer combines both."**

```
                     ┌───────────────────────────────┐
                     │ User Input: Screenshot or Text│
                     └───────────────┬───────────────┘
                                     │
                     ┌───────────────▼───────────────┐
                     │   Input Normalization & OCR   │
                     │    (EasyOCR / Clean Unicode)  │
                     └───────┬───────────────┬───────┘
                             │               │
                             │               │
             ┌───────────────▼───────┐   ┌───▼───────────────────────────┐
             │   Local AI Model      │   │ Deterministic Verifier        │
             │   (Ollama / Llama 3)  │   │ - Shortened & IP URLs         │
             │                       │   │ - OTP & PIN Harvest Detection │
             │ Semantic Understanding:│   │ - Direct Payment / UPI Leaks  │
             │ - Urgency & Pressure  │   │ - Domain Mismatches           │
             │ - Authority Imperson. │   │ - Known Scam Keywords         │
             │ - Emotional Pretext   │   │ - Suspicious URL Schemes      │
             └───────────────┬───────┘   └───┬───────────────────────────┘
                             │               │
                             │   Strict JSON │ Signals & Findings
                             │   Validation  │
                             │               │
                     ┌───────▼───────────────▼───────┐
                     │    Unified Decision Engine    │
                     │   - Precedence Rules          │
                     │   - Conflict Resolution       │
                     │   - Transparent Uncertainty   │
                     └───────────────┬───────────────┘
                                     │
                     ┌───────────────▼───────────────┐
                     │     Explainable Output        │
                     │  (Non-technical Action Plan)  │
                     └───────────────────────────────┘
```

### Why Both Layers Are Required:
1. **The Model Alone Is Not Enough:** Small local models can be jailbroken or miss subtle domain obfuscations (e.g., `paytm.security-update.xyz`).
2. **Deterministic Rules Alone Are Not Enough:** Regex cannot detect subtle social engineering, empathetic extortion, conversational grooming, or informal urgent threats without hardcoded keywords.
3. **The Decision Engine Resolves Conflicts:** If the model thinks a message is "harmless update" but the deterministic verifier catches a raw IP link asking for OTP, the deterministic rule overrides to flag the risk.

---

## 🔒 Privacy & Safety Guarantees

- **Zero Cloud Leakage:** All inference runs on your own hardware via local Ollama.
- **No Automatic Browsing:** ScamLens **never** fetches or executes links found in suspicious messages.
- **No Code Execution:** Untrusted user input is treated as raw data only.
- **No Synthesized / Mock Results:** Real model inference and real deterministic parsers are executed.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+ (tested on Python 3.12)
- [Ollama](https://ollama.ai) installed and running locally
- Pull a local model:
  ```bash
  ollama pull llama3:latest
  ```

### Running Backend
```bash
# From workspace root
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Running Tests
```bash
python -m pytest backend/tests -v
```
