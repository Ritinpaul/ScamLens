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

### Screenshot Analysis Pipeline
ScamLens uses **Local High-Resolution OCR + Local Open-Source LLM Semantic Analysis**:
- Rather than pretending that Llama 3 is a vision model, ScamLens transparently executes a two-stage local pipeline:
  1. **Native-Resolution OCR:** Extracted via local `EasyOCR` with image contrast enhancement to capture exact URLs, numbers, and punctuation without downscaling artifacts.
  2. **Semantic Understanding:** The extracted text is analyzed by `Llama 3 (8B)` running locally via Ollama to evaluate psychological tactics (urgency, authority impersonation, fear extortion).
  3. **Deterministic Verification:** Ground-truth security patterns (raw IP links, URL shorteners, OTP harvesting, UPI handles) are independently verified.
  4. **Decision Engine Synthesis:** Resolves conflicts, enforces safety overrides, and provides a clear non-technical action plan.

```
                     ┌───────────────────────────────┐
                     │ User Input: Screenshot or Text│
                     └───────────────┬───────────────┘
                                     │
                     ┌───────────────▼───────────────┐
                     │   Image Validation & OCR      │
                     │  (Magic bytes, EasyOCR CPU)   │
                     └───────┬───────────────┬───────┘
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
                             │ Strict JSON   │ Ground-Truth Signals
                             │ (source:model)│ (source:deterministic)
                             │               │
                     ┌───────▼───────────────▼───────┐
                     │    Unified Decision Engine    │
                     │   (source:decision_engine)    │
                     │   - Precedence & Overrides    │
                     │   - Conflict Resolution       │
                     │   - Traceable Evidence        │
                     └───────────────┬───────────────┘
                                     │
                     ┌───────────────▼───────────────┐
                     │     Explainable Output        │
                     │  (Non-technical Action Plan)  │
                     └───────────────────────────────┘
```

---

## 🔒 Privacy & Safety Guarantees

- **Zero Cloud Leakage:** All inference runs on your own hardware via local Ollama.
- **No Automatic Browsing:** ScamLens **never** fetches or executes links found in suspicious messages, preventing attacker telemetry and drive-by downloads.
- **No Code Execution:** Untrusted user input is treated strictly as plain data.
- **Auditable Provenance:** Every response clearly delineates `model` claims from `deterministic` ground truth.

---

## 💻 Hardware Requirements

- **OS:** Windows 10/11, Linux, or macOS
- **RAM:** Minimum 8 GB (16 GB recommended)
- **GPU:** Optional (NVIDIA GPU with 4GB+ VRAM supported; CPU offloading supported via Ollama)
- **Tested Environment:** AMD Ryzen 7 6800H, 16 GB RAM, NVIDIA RTX 3050 Ti (4GB VRAM)

---

## 🚀 Getting Started

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.12)
- Node.js 18+ (tested on Node.js 20+)
- [Ollama](https://ollama.ai) installed and running locally
- Pull the local model:
  ```bash
  ollama serve
  ollama pull llama3:latest
  ```

### 2. Running Backend (FastAPI)
```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```
Health endpoint: `http://127.0.0.1:8000/health`
Interactive docs: `http://127.0.0.1:8000/docs`

### 3. Running Frontend (Vite + React + TypeScript)
```powershell
cd frontend
npm install
npm run dev
```
Open application: `http://localhost:5173`

### 4. Running Verification Tests

**Backend Tests (32 tests):**
```powershell
python -m pytest backend/tests -v
```

**Frontend Tests (5 tests):**
```powershell
cd frontend
npm test
```

**Production Build:**
```powershell
cd frontend
npm run build
```
