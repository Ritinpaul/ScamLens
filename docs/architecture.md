# ScamLens Architecture Documentation

## Core Design Principles

1. **Separation of Concerns**:
   - The AI understands context, manipulation tactics, and intent.
   - The Deterministic Verifier checks ground-truth facts: IP addresses, shortened links, OTP harvesting, UPI IDs, domain mismatches.
   - The Decision Engine synthesizes both layers and enforces safety precedence rules.

2. **Zero-Trust AI Precedence**:
   - If deterministic checks flag a **CRITICAL** danger (such as direct OTP theft or raw IP banking links), the decision engine immediately marks the message as a **SCAM**, regardless of whether the model was deceived or perceived the message as benign.

3. **Privacy by Default**:
   - All models run locally via Ollama.
   - No data leaves the machine.
   - Suspicious links are **never automatically fetched or resolved**, preventing beaconing or drive-by attacks.

4. **Honest Uncertainty**:
   - Model confidence is explicitly reported as qualitative and unvalidated, rather than fake pseudo-statistical probabilities.
   - Ambiguous or short inputs are marked as `insufficient_evidence`.
