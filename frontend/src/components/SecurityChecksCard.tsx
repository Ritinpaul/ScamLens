import React from 'react';
import { VerifierOutput } from '../types/scamlens';

interface SecurityChecksCardProps {
  verifier: VerifierOutput;
}

export const SecurityChecksCard: React.FC<SecurityChecksCardProps> = ({ verifier }) => {
  const hasSignals = verifier.signals && verifier.signals.length > 0;
  const hasUrls = verifier.urls && verifier.urls.length > 0;

  return (
    <div className="panel">
      <div className="section-header">
        <div className="section-title">
          🔍 SECURITY CHECKS
          <span className="source-tag det">Source: Deterministic Verifier</span>
        </div>
        <span className="section-subtitle">
          Risk: {verifier.deterministic_risk_level.toUpperCase()}
        </span>
      </div>

      {!hasSignals && !hasUrls ? (
        <p className="section-subtitle">
          No deterministic security violations, suspicious URLs, or credential harvesting patterns were triggered.
        </p>
      ) : (
        <>
          {hasSignals && (
            <div style={{ marginBottom: '1.25rem' }}>
              <div className="item-card-title">RULE-BASED SECURITY SIGNALS:</div>
              <div className="signals-list">
                {verifier.signals.map((sig, idx) => (
                  <div key={idx} className="signal-row">
                    <div className="signal-info">
                      <div className="signal-category">
                        <span style={{ textTransform: 'uppercase', fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.15rem' }}>
                          Category: {sig.category.replace(/_/g, ' ')}
                        </span>
                        {sig.pattern_matched}
                      </div>
                      <div>
                        Snippet: <span className="signal-snippet">{sig.snippet}</span>
                      </div>
                    </div>
                    <span className={`severity-badge ${sig.severity}`}>
                      {sig.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {hasUrls && (
            <div>
              <div className="item-card-title">EXTRACTED URLS & DOMAIN INSPECTION:</div>
              <div className="card-list" style={{ marginTop: '0.4rem' }}>
                {verifier.urls.map((u, idx) => (
                  <div key={idx} className="item-card">
                    <div style={{ wordBreak: 'break-all', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                      {u.raw_url}
                    </div>
                    <div style={{ marginTop: '0.35rem', display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      {u.is_ip_address && (
                        <span className="severity-badge critical">Numerical IP Host</span>
                      )}
                      {u.is_shortener && (
                        <span className="severity-badge high">Shortener Evasion</span>
                      )}
                      {u.is_suspicious_tld && (
                        <span className="severity-badge high">Disposable TLD</span>
                      )}
                      {u.scheme === 'http' && (
                        <span className="severity-badge medium">Unencrypted HTTP</span>
                      )}
                    </div>
                    {u.notes && u.notes.length > 0 && (
                      <ul style={{ paddingLeft: '1.2rem', marginTop: '0.3rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                        {u.notes.map((n, i) => (
                          <li key={i}>{n}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};
