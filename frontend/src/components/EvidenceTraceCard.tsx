import React from 'react';
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
          📋 EVIDENCE TRACE
        </div>
        <span className="source-tag" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
          {isOcr ? 'Source: Screenshot OCR' : 'Source: Pasted Text'}
        </span>
      </div>

      {isOcr && trace.image_metadata && (
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '0.75rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          <span><strong>Format:</strong> {trace.image_metadata.format || 'Unknown'}</span>
          <span><strong>Dimensions:</strong> {trace.image_metadata.dimensions || 'Unknown'}</span>
          <span><strong>Extracted Lines:</strong> {trace.image_metadata.line_count ?? 'N/A'}</span>
          <span><strong>Normalized Length:</strong> {trace.normalized_input_length} chars</span>
        </div>
      )}

      <div className="item-card-title">
        {isOcr ? 'EXACT TEXT EXTRACTED FROM SCREENSHOT:' : 'NORMALIZED INPUT TEXT:'}
      </div>

      <pre className="trace-block">
        {trace.extracted_ocr_text || trace.raw_input_snippet}
      </pre>

      {isOcr && (
        <p className="trace-notice">
          ⚠️ Some text or punctuation in the URL above may have been misread from the screenshot due to image resolution or fonts.
        </p>
      )}
    </div>
  );
};
