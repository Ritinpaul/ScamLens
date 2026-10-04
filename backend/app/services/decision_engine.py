from backend.app.models.ai_schema import AiAnalysisOutput, AiVerdict
from backend.app.models.verifier_schema import VerifierOutput, SignalSeverity
from backend.app.models.analysis_result import (
    AnalysisResponse,
    FinalVerdict,
    ConfidenceRating,
)

class DecisionEngine:
    """
    Combines AI understanding with deterministic ground-truth verification.
    Preserves auditability, explains conflict resolution, and ensures safety.
    """

    def synthesize(
        self,
        ai_output: AiAnalysisOutput | None,
        verifier_output: VerifierOutput,
        normalized_length: int,
        input_type: str = "text"
    ) -> AnalysisResponse:
        rationale: list[str] = []
        tactics_list: list[str] = []
        evidence_list: list[str] = []

        # 1. Collect deterministic evidence
        for sig in verifier_output.signals:
            evidence_list.append(f"[{sig.category.upper()}] {sig.pattern_matched}: '{sig.snippet}'")

        # 2. Collect AI tactics if available
        if ai_output:
            for t in ai_output.tactics:
                tactics_list.append(f"{t.type}: {t.evidence}")
            for req in ai_output.requests:
                evidence_list.append(f"[REQUEST] {req}")

        # Check for very short / ambiguous inputs
        if normalized_length < 15 and not verifier_output.signals:
            rationale.append("Input text is extremely brief and contains no identifiable deterministic indicators.")
            return AnalysisResponse(
                verdict=FinalVerdict.INSUFFICIENT_EVIDENCE,
                confidence=ConfidenceRating.LOW,
                confidence_explanation="The message contains too few characters to establish intent safely.",
                plain_english_summary="The provided message is too brief or ambiguous to reliably determine whether it is safe or harmful.",
                recommended_action="Do not respond or click unknown links without verifying the sender's identity through official channels.",
                ai_findings=ai_output,
                deterministic_findings=verifier_output,
                decision_rationale=rationale,
                detected_manipulation_tactics=tactics_list,
                extracted_evidence=evidence_list,
                input_type=input_type,
                normalized_input_length=normalized_length,
            )

        # Evaluate deterministic risk
        has_critical_verifier = any(s.severity == SignalSeverity.CRITICAL for s in verifier_output.signals)
        has_high_verifier = any(s.severity == SignalSeverity.HIGH for s in verifier_output.signals)

        # Default working verdict based on AI
        ai_verdict = ai_output.verdict if ai_output else None

        # 3. Decision Matrix with Precedence
        if has_critical_verifier:
            verdict = FinalVerdict.SCAM
            confidence = ConfidenceRating.HIGH
            conf_exp = "Deterministic checks identified high-danger indicators (e.g. OTP harvesting, credential solicitation, or unverified IP links)."
            rationale.append("CRITICAL RULE TRIGGERED: One or more critical deterministic rules matched (direct OTP/credential harvest or IP link).")
            if ai_output and ai_output.verdict in (AiVerdict.LIKELY_LEGITIMATE, AiVerdict.INSUFFICIENT_EVIDENCE):
                rationale.append("SAFETY OVERRIDE: The AI model considered the message benign/insufficient, but deterministic inspection proved direct credential/OTP threats.")

        elif ai_verdict == AiVerdict.SCAM:
            verdict = FinalVerdict.SCAM
            if has_high_verifier:
                confidence = ConfidenceRating.HIGH
                conf_exp = "Both the AI model and deterministic security signatures flagged this message as malicious."
                rationale.append("AGREEMENT: AI semantic analysis and deterministic checks independently classified this as a scam.")
            else:
                confidence = ConfidenceRating.MEDIUM
                conf_exp = "The AI model identified clear manipulation tactics, though no hardcoded blacklisted patterns were matched."
                rationale.append("SEMANTIC DETECTION: The AI model detected scam intent through contextual manipulation and deceptive pretext.")

        elif has_high_verifier:
            verdict = FinalVerdict.SUSPICIOUS
            confidence = ConfidenceRating.MEDIUM
            conf_exp = "Deterministic verification found suspicious indicators (e.g. urgency coercion or URL shorteners), requiring caution."
            rationale.append("DETERMINISTIC FLAG: Detected shortened links or artificial urgency patterns typical of unverified outreach.")

        elif ai_verdict == AiVerdict.SUSPICIOUS:
            verdict = FinalVerdict.SUSPICIOUS
            confidence = ConfidenceRating.MEDIUM
            conf_exp = "The AI model identified subtle persuasion or unverified claims, though no explicit malicious payloads were found."
            rationale.append("AI FLAG: Contextual signals suggest caution due to unverified claims or unexpected communication style.")

        elif ai_verdict == AiVerdict.LIKELY_LEGITIMATE:
            if not verifier_output.signals:
                verdict = FinalVerdict.LIKELY_LEGITIMATE
                confidence = ConfidenceRating.MEDIUM
                conf_exp = "Neither the AI model nor deterministic rules detected suspicious manipulation patterns."
                rationale.append("CLEAN SIGNALS: The text appears to be standard routine communication with no detected threats.")
            else:
                verdict = FinalVerdict.SUSPICIOUS
                confidence = ConfidenceRating.LOW
                conf_exp = "The AI model perceived the message as benign, but minor deterministic flags were found."
                rationale.append("DISCREPANCY: Minor signals detected despite general conversational tone.")

        elif ai_verdict == AiVerdict.INSUFFICIENT_EVIDENCE:
            verdict = FinalVerdict.INSUFFICIENT_EVIDENCE
            confidence = ConfidenceRating.LOW
            conf_exp = "The model was unable to determine malicious or legitimate intent with available text."
            rationale.append("UNCERTAINTY: Ambiguous text with insufficient context to render a definitive verdict.")

        else:
            # Fallback if no AI output was provided (e.g. offline fallback)
            if has_high_verifier:
                verdict = FinalVerdict.SUSPICIOUS
                confidence = ConfidenceRating.LOW
                conf_exp = "Analyzed exclusively with deterministic checks (AI model was unavailable)."
                rationale.append("DETERMINISTIC-ONLY: AI provider was inactive; verdict rendered on pattern signatures.")
            else:
                verdict = FinalVerdict.INSUFFICIENT_EVIDENCE
                confidence = ConfidenceRating.UNVERIFIED
                conf_exp = "AI analysis was unavailable and no deterministic signals matched."
                rationale.append("UNVERIFIED: Insufficient data without AI semantic analysis.")

        # Summary and Actionable recommendation
        plain_summary = self._generate_summary(verdict, ai_output, verifier_output)
        recommended_action = self._generate_action(verdict, verifier_output)

        return AnalysisResponse(
            verdict=verdict,
            confidence=confidence,
            confidence_explanation=conf_exp,
            plain_english_summary=plain_summary,
            recommended_action=recommended_action,
            ai_findings=ai_output,
            deterministic_findings=verifier_output,
            decision_rationale=rationale,
            detected_manipulation_tactics=tactics_list,
            extracted_evidence=evidence_list,
            input_type=input_type,
            normalized_input_length=normalized_length,
        )

    def _generate_summary(
        self,
        verdict: FinalVerdict,
        ai_output: AiAnalysisOutput | None,
        verifier: VerifierOutput
    ) -> str:
        if ai_output and ai_output.summary:
            return ai_output.summary

        if verdict == FinalVerdict.SCAM:
            return "This message exhibits strong characteristics of an attempt to defraud you, capture sensitive credentials, or solicit unauthorized payments."
        if verdict == FinalVerdict.SUSPICIOUS:
            return "This message contains suspicious elements such as urgency pressure, unverified links, or unfamiliar requests that require careful scrutiny."
        if verdict == FinalVerdict.LIKELY_LEGITIMATE:
            return "This message appears to be ordinary communication with no obvious signs of deception or extortion."
        return "There is not enough clear information in this message to determine whether it is genuine or harmful."

    def _generate_action(self, verdict: FinalVerdict, verifier: VerifierOutput) -> str:
        if verifier.has_otp_request:
            return "CRITICAL WARNING: NEVER share your OTP or 6-digit verification code with anyone. Real banks and service providers will never ask you to disclose an OTP."
        if verifier.has_credential_request:
            return "DO NOT enter passwords, PINs, or banking details. Delete the message and block the sender."
        if verdict == FinalVerdict.SCAM:
            return "Do NOT click any links, do NOT send money, and do NOT reply. Block the sender and report the number."
        if verdict == FinalVerdict.SUSPICIOUS:
            return "Do NOT click any links in this message. If you suspect an issue with your account, contact the institution directly via their official app or website."
        if verdict == FinalVerdict.LIKELY_LEGITIMATE:
            return "No suspicious activity detected. Continue standard caution and never share one-time passwords."
        return "Verify the sender's identity through a separate, trusted channel before taking any action or clicking links."
