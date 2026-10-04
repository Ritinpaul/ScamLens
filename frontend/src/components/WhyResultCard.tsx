import React from 'react';

interface WhyResultCardProps {
  rationale: string[];
}

export const WhyResultCard: React.FC<WhyResultCardProps> = ({ rationale }) => {
  if (!rationale || rationale.length === 0) return null;

  return (
    <div className="panel">
      <div className="section-header">
        <div className="section-title">
          ⚖️ WHY THIS RESULT?
          <span className="source-tag" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
            Source: Decision Engine
          </span>
        </div>
      </div>

      <div className="card-list">
        {rationale.map((reason, idx) => (
          <div key={idx} className="item-card" style={{ borderLeft: '3px solid var(--color-det)' }}>
            <div className="item-card-content">{reason}</div>
          </div>
        ))}
      </div>
    </div>
  );
};
