import React from 'react';
import ErrorOutlineOutlined from '@mui/icons-material/ErrorOutlineOutlined';
import WarningAmberOutlined from '@mui/icons-material/WarningAmberOutlined';
import CheckCircleOutlineOutlined from '@mui/icons-material/CheckCircleOutlineOutlined';
import InfoOutlined from '@mui/icons-material/InfoOutlined';
import ShieldOutlined from '@mui/icons-material/ShieldOutlined';
import { FinalVerdict, ConfidenceRating } from '../types/scamlens';

interface VerdictCardProps {
  verdict: FinalVerdict;
  confidence: ConfidenceRating;
  confidenceExplanation: string;
  summary: string;
  recommendedAction: string;
}

const renderVerdictIcon = (verdict: FinalVerdict) => {
  switch (verdict) {
    case 'scam':
      return <ErrorOutlineOutlined className="verdict-icon" style={{ fontSize: '1.35rem' }} />;
    case 'suspicious':
      return <WarningAmberOutlined className="verdict-icon" style={{ fontSize: '1.35rem' }} />;
    case 'likely_legitimate':
      return <CheckCircleOutlineOutlined className="verdict-icon" style={{ fontSize: '1.35rem' }} />;
    case 'insufficient_evidence':
    default:
      return <InfoOutlined className="verdict-icon" style={{ fontSize: '1.35rem' }} />;
  }
};

const VERDICT_TEXT: Record<FinalVerdict, string> = {
  scam: 'SCAM DETECTED',
  suspicious: 'SUSPICIOUS',
  likely_legitimate: 'LIKELY LEGITIMATE',
  insufficient_evidence: 'INSUFFICIENT EVIDENCE',
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
          {renderVerdictIcon(verdict)}
          <span className="verdict-label-text">{VERDICT_TEXT[verdict] || verdict.toUpperCase()}</span>
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
        <div className="action-title">
          <ShieldOutlined style={{ fontSize: '1.05rem', verticalAlign: 'middle', marginRight: '0.35rem' }} />
          WHAT SHOULD I DO?
        </div>
        <p className="action-text">{recommendedAction}</p>
      </div>
    </div>
  );
};
