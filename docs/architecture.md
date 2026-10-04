# ScamLens Architecture & Multi-Stage Pipeline

## 1. Concrete Pipeline Architecture

ScamLens uses **Path B: Local High-Resolution OCR + Local Open-Source LLM Semantic Analysis**:

```
[Raw User Input]
   ├── Text input (pasted message / email / chat)
   └── Image input (screenshot PNG, JPEG, WebP)
           │
           ▼
[Image Validation & Local OCR Layer]
   ├── True Magic Bytes Inspection (rejects non-images, corrupt files, >10MB)
   ├── Dimension Bounds Check (min 50x50, max 8000x8000)
   ├── Contrast & Grayscale Preprocessing (PIL Lanczos/Enhance)
   └── Native-Resolution Character Extraction (EasyOCR on CPU)
           │
           ▼
[Text Normalization Engine]
   ├── Unicode NFKC Normalization (canonical character mapping)
   ├── Invisible Evasion Strip (zero-width spaces \u200B-\u200D, \uFEFF)
   └── Excessive Whitespace & Newline Standardizer
           │
           ├──────────────────────────────────────────────┐
           ▼                                              ▼
[Deterministic Security Verifier]             [Local Open-Source LLM]
(Source: "deterministic")                     (Source: "model" via Ollama Llama 3)
- Raw IP Address URL Hosts                    - Authority Impersonation Analysis
- Shortener Domain Evasion (bit.ly, t.co)     - Artificial Urgency & Fear Pressure
- Suspicious Disposable TLDs (.xyz, .top)     - Indirect Pretext & Social Engineering
- Direct OTP / 6-Digit Harvest Patterns       - Victim Solicitations & Entities
- Bank Password & MPIN Harvesting             - Qualitative Uncertainty Statement
- Direct UPI Addresses (*@okhdfcbank, etc.)   - Strictly Enforced JSON Schema
- Institution-to-Domain Mismatches
           │                                              │
           └──────────────────────┬───────────────────────┘
                                  ▼
                   [Unified Decision Engine]
                   (Source: "decision_engine")
                   - Precedence & Safety Overrides (critical rules veto model false-negatives)
                   - Conflict Resolution (reconciles model vs. signature flags)
                   - Evidence Traceability (preserves raw snippet & OCR line metadata)
                   - Actionable Non-Technical Plan ("Do NOT share OTP...")
```

---

## 2. Why Path B (OCR + LLM) Was Chosen Over Tiny Multimodal Models (Moondream/LLaVA)

During Stage 2 empirical evaluation on the host hardware (NVIDIA RTX 3050 Ti 4GB VRAM):
- **Multimodal Candidate Tested:** `moondream:latest` (1.8B vision model).
- **Empirical Failure:** When presented with a mobile screenshot containing `http://sbi-kyc.xyz/verify`, `moondream` suffered severe visual hallucination—it invented `"State Bank of Hawaii"`, omitted the critical URL entirely, and generated conversational prose instead of strictly conforming to the required security JSON schema.
- **Root Cause:** Small vision encoders downsample images to low-resolution patch grids (384x384), destroying small alphanumeric characters essential for security analysis (e.g. URLs, phone numbers, OTP warnings).
- **The Solution:** Native-resolution OCR (`EasyOCR`) extracts exact characters without downsampling distortion. `Llama 3 (8B)` then applies social engineering reasoning to the uncorrupted text. ScamLens honestly documents this as **Local OCR + Local LLM Semantic Analysis**, rather than misleadingly claiming the LLM has native vision.

---

## 3. Explicit Source Separation & Data Contract

To prevent confusion between statistical model claims and verified deterministic signals, every output field includes an explicit `source` tag:

1. **`ai_interpretation` (`source: "model"`):**
   - Psychological tactics identified (e.g. `authority_impersonation`, `artificial_urgency`)
   - Entities claimed by the sender
   - Explicitly marked with `"confidence_label": "model_unvalidated"`
2. **`deterministic_findings` (`source: "deterministic"`):**
   - Exact regex signature matches, IP host flags, OTP indicators, UPI IDs
3. **`final_decision` (`source: "decision_engine"`):**
   - Final verdict, confidence explanation, and human-readable action plan
4. **`evidence_trace`:**
   - Full provenance: `input_type` ("pasted_text" vs "screenshot_ocr"), `extracted_ocr_text`, image dimensions, and line count.

---

## 4. Privacy & Threat Model

- **100% Offline / Local Execution:** No data is sent to external cloud APIs (OpenAI, Anthropic, Google).
- **Zero URL Fetching:** ScamLens **never** performs HTTP GET/HEAD requests to extracted URLs, preventing attacker telemetry, IP logging, and DNS beaconing.
- **Zero Code Execution:** Untrusted messages are parsed solely as text strings. No `eval` or execution paths exist.
