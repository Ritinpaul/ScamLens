import React from 'react';
import { FinalVerdict, ConfidenceRating } from '../types/scamlens';

interface VerdictCardProps {
  verdict: FinalVerdict;
  confidence: ConfidenceRating;
  confidenceExplanation: string;
  summary: string;
  recommendedAction: string;
}

const VERDICT_LABELS: Record<FinalVerdict, string> = {
  scam: '🚨 SCAM DETECTED',
  suspicious: '⚠️ SUSPICIOUS',
  likely_legitimate: '✅ LIKELY LEGITIMATE',
  insufficient_evidence: 'ℹ️ INSUFFICIENT EVIDENCE',
};

export const VerdictCard: React.FC<VerdictCardProps> = ({
  verdict,
  confidence,
  confidenceExplanation,
  summary,
  recommendedAction,
}) => {
  return (
    <div className={`panel verdict-card ${verdict}`}>
      <div className="verdict-badge-row">
        <span className={`verdict-badge ${verdict}`}>
          {VERDICT_LABELS[verdict] || verdict.toUpperCase()}
        </span>
        <span className="confidence-tag">
          Confidence: {confidence.toUpperCase()}
        </span>
      </div>

      <p className="verdict-summary">{summary}</p>

      {confidenceExplanation && (
        <p className="section-subtitle" style={{ marginBottom: '1rem' }}>
          {confidenceExplanation}
        </p>
      )}

      <div className="action-box">
        <div className="action-title">🛡️ WHAT SHOULD I DO?</div>
        <p className="action-text">{recommendedAction}</p>
      </div>
    </div>
  );
};
