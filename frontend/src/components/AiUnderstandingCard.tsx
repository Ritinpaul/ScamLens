import React from 'react';
import PsychologyOutlined from '@mui/icons-material/PsychologyOutlined';
import { AiAnalysisOutput } from '../types/scamlens';

interface AiUnderstandingCardProps {
  ai: AiAnalysisOutput | null | undefined;
}

export const AiUnderstandingCard: React.FC<AiUnderstandingCardProps> = ({ ai }) => {
  if (!ai) {
    return (
      <div className="panel">
        <div className="section-header">
          <div className="section-title">
            <PsychologyOutlined sx={{ fontSize: '1.1rem', color: '#818cf8' }} />
            <span>AI UNDERSTANDING</span>
            <span className="source-tag ai">Local Model</span>
          </div>
        </div>
        <p className="section-subtitle">
          Local semantic model analysis was offline or unavailable during this assessment.
        </p>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="section-header">
        <div className="section-title">
          <PsychologyOutlined sx={{ fontSize: '1.1rem', color: '#818cf8' }} />
          <span>AI UNDERSTANDING</span>
          <span className="source-tag ai">Local Model ({ai.model_name})</span>
        </div>
        <span className="section-subtitle">
          {ai.confidence_label
            ? `Model confidence: ${ai.confidence_label.replace(/^model_/, '')}`
            : 'Model confidence: unvalidated'}
        </span>
      </div>

      <p className="item-card-content" style={{ marginBottom: '1.25rem' }}>
        {ai.summary}
      </p>

      {ai.tactics && ai.tactics.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <div className="item-card-title">DETECTED MANIPULATION TACTICS:</div>
          <div className="card-list">
            {ai.tactics.map((t, idx) => (
              <div key={idx} className="item-card">
                <div style={{ fontWeight: 600, color: '#a5b4fc', textTransform: 'capitalize', fontSize: '0.85rem' }}>
                  {t.type.replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: '0.9rem', marginTop: '0.2rem' }}>
                  &ldquo;{t.evidence}&rdquo;
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {ai.requests && ai.requests.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <div className="item-card-title">ACTIONS DEMANDED OF RECIPIENT:</div>
          <ul style={{ paddingLeft: '1.25rem', fontSize: '0.9rem', color: 'var(--text-primary)' }}>
            {ai.requests.map((r, idx) => (
              <li key={idx} style={{ marginBottom: '0.25rem' }}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      {ai.entities && ai.entities.length > 0 && (
        <div>
          <div className="item-card-title">CLAIMED ORGANIZATIONS / BRANDS:</div>
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.35rem' }}>
            {ai.entities.map((ent, idx) => (
              <span
                key={idx}
                style={{
                  backgroundColor: 'var(--bg-input)',
                  border: '1px solid var(--border-color)',
                  padding: '0.2rem 0.6rem',
                  borderRadius: '4px',
                  fontSize: '0.8rem',
                }}
              >
                {ent}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
