import React from 'react';
import DataObjectOutlined from '@mui/icons-material/DataObjectOutlined';
import InfoOutlined from '@mui/icons-material/InfoOutlined';
import { EvidenceTrace } from '../types/scamlens';

interface EvidenceTraceCardProps {
  trace: EvidenceTrace;
}

export const EvidenceTraceCard: React.FC<EvidenceTraceCardProps> = ({ trace }) => {
  const isOcr = trace.input_type === 'screenshot_ocr';

  return (
    <div className="panel">
      <div className="section-header">
        <div className="section-title">
          <DataObjectOutlined sx={{ fontSize: '1.1rem', color: '#94a3b8' }} />
          <span>EVIDENCE TRACE</span>
        </div>
        <span className="source-tag" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
          {isOcr ? 'Screenshot OCR' : 'Pasted Text'}
        </span>
      </div>

      {isOcr && trace.image_metadata && (
        <div className="evidence-metadata-row">
          <span className="evidence-badge">
            <span className="badge-key">Format:</span> {trace.image_metadata.format || 'Unknown'}
          </span>
          <span className="evidence-badge">
            <span className="badge-key">Dimensions:</span> {trace.image_metadata.dimensions || 'Unknown'}
          </span>
          <span className="evidence-badge">
            <span className="badge-key">Extracted Lines:</span> {trace.image_metadata.line_count ?? 'N/A'}
          </span>
          <span className="evidence-badge">
            <span className="badge-key">Length:</span> {trace.normalized_input_length} chars
          </span>
        </div>
      )}

      <div className="item-card-title">
        {isOcr ? 'EXACT TEXT EXTRACTED FROM SCREENSHOT:' : 'NORMALIZED INPUT TEXT:'}
      </div>

      <pre className="trace-block">
        {trace.extracted_ocr_text || trace.raw_input_snippet}
      </pre>

      {isOcr && (
        <div className="trace-notice">
          <InfoOutlined sx={{ fontSize: '1rem', flexShrink: 0, color: 'var(--text-muted)' }} />
          <span>
            OCR extraction fidelity depends on screenshot resolution and contrast. Low-resolution glyphs or unusual fonts may introduce minor character variance.
          </span>
        </div>
      )}
    </div>
  );
};
