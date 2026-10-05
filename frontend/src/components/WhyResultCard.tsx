import React from 'react';
import GavelOutlined from '@mui/icons-material/GavelOutlined';

interface WhyResultCardProps {
  rationale: string[];
}

export const WhyResultCard: React.FC<WhyResultCardProps> = ({ rationale }) => {
  if (!rationale || rationale.length === 0) return null;

  return (
    <div className="panel">
      <div className="section-header">
        <div className="section-title">
          <GavelOutlined sx={{ fontSize: '1.1rem', color: '#94a3b8' }} />
          <span>WHY THIS RESULT?</span>
          <span className="source-tag" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
            Decision Engine
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
