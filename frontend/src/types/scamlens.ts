export type FinalVerdict = 'scam' | 'suspicious' | 'likely_legitimate' | 'insufficient_evidence';

export type ConfidenceRating = 'high' | 'medium' | 'low' | 'unverified';

export interface TacticItem {
  type: string;
  evidence: string;
}

export interface AiAnalysisOutput {
  source: 'model';
  model_name: string;
  verdict: FinalVerdict;
  summary: string;
  tactics: TacticItem[];
  requests: string[];
  entities: string[];
  urls: string[];
  recommended_action: string;
  uncertainty_reason: string;
  confidence_label: string;
}

export interface DetectedUrl {
  raw_url: string;
  scheme: string;
  host: string;
  path: string;
  is_ip_address: boolean;
  is_shortener: boolean;
  is_suspicious_tld: boolean;
  notes: string[];
}

export interface DetectedSignal {
  category: string;
  pattern_matched: string;
  snippet: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface VerifierOutput {
  source: 'deterministic';
  urls: DetectedUrl[];
  signals: DetectedSignal[];
  has_otp_request: boolean;
  has_credential_request: boolean;
  has_payment_request: boolean;
  has_shortened_url: boolean;
  has_ip_url: boolean;
  has_urgency: boolean;
  deterministic_risk_level: string;
}

export interface EvidenceTrace {
  input_type: 'pasted_text' | 'screenshot_ocr';
  raw_input_snippet: string;
  extracted_ocr_text?: string | null;
  normalized_input_length: number;
  image_metadata?: {
    format?: string;
    dimensions?: string;
    line_count?: number;
    raw_ocr_length?: number;
  } | null;
}

export interface AnalysisResponse {
  source: 'decision_engine';
  verdict: FinalVerdict;
  confidence: ConfidenceRating;
  confidence_explanation: string;
  plain_english_summary: string;
  recommended_action: string;
  ai_interpretation?: AiAnalysisOutput | null;
  deterministic_findings: VerifierOutput;
  decision_rationale: string[];
  detected_manipulation_tactics: string[];
  extracted_evidence: string[];
  evidence_trace: EvidenceTrace;
  analyzed_at: string;
}

export interface HealthStatus {
  status: string;
  app: string;
  version: string;
  environment: string;
  model_provider: {
    provider: string;
    configured_model: string;
    base_url: string;
    available: boolean;
    status_message: string;
  };
  ocr_enabled: boolean;
}
