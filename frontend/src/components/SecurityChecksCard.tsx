import React from 'react';
import FactCheckOutlined from '@mui/icons-material/FactCheckOutlined';
import LinkOutlined from '@mui/icons-material/LinkOutlined';
import KeyOutlined from '@mui/icons-material/KeyOutlined';
import VpnKeyOutlined from '@mui/icons-material/VpnKeyOutlined';
import PaymentOutlined from '@mui/icons-material/PaymentOutlined';
import ScheduleOutlined from '@mui/icons-material/ScheduleOutlined';
import CheckCircleOutlineOutlined from '@mui/icons-material/CheckCircleOutlineOutlined';
import ErrorOutlineOutlined from '@mui/icons-material/ErrorOutlineOutlined';
import { VerifierOutput } from '../types/scamlens';

interface SecurityChecksCardProps {
  verifier: VerifierOutput;
}

export const SecurityChecksCard: React.FC<SecurityChecksCardProps> = ({ verifier }) => {
  const hasSignals = verifier.signals && verifier.signals.length > 0;
  const hasUrls = verifier.urls && verifier.urls.length > 0;
  const hasSuspiciousUrl =
    verifier.has_shortened_url ||
    verifier.has_ip_url ||
    (verifier.urls && verifier.urls.some((u) => u.is_suspicious_tld));

  const CHECKS = [
    {
      id: 'urls',
      icon: <LinkOutlined style={{ fontSize: '1.1rem' }} />,
      label: 'Suspicious URLs & Domains',
      flagged: hasSuspiciousUrl,
      statusText: hasSuspiciousUrl
        ? 'Flagged'
        : hasUrls
        ? 'Clean'
        : 'None detected',
      detail: verifier.has_ip_url
        ? 'Numerical IP host detected'
        : verifier.has_shortened_url
        ? 'Shortener evasion detected'
        : undefined,
    },
    {
      id: 'credentials',
      icon: <KeyOutlined style={{ fontSize: '1.1rem' }} />,
      label: 'Credential Requests',
      flagged: verifier.has_credential_request,
      statusText: verifier.has_credential_request ? 'Violation detected' : 'None detected',
      detail: verifier.has_credential_request ? 'Password, PIN, or CVV harvesting pattern' : undefined,
    },
    {
      id: 'otp',
      icon: <VpnKeyOutlined style={{ fontSize: '1.1rem' }} />,
      label: 'OTP / 2FA Solicitation',
      flagged: verifier.has_otp_request,
      statusText: verifier.has_otp_request ? 'Critical violation' : 'None detected',
      detail: verifier.has_otp_request ? 'Direct attempt to extract incoming authentication code' : undefined,
    },
    {
      id: 'payment',
      icon: <PaymentOutlined style={{ fontSize: '1.1rem' }} />,
      label: 'Payment Requests',
      flagged: verifier.has_payment_request,
      statusText: verifier.has_payment_request ? 'Violation detected' : 'None detected',
      detail: verifier.has_payment_request ? 'Unverified fund transfer or reverse QR solicitation' : undefined,
    },
    {
      id: 'urgency',
      icon: <ScheduleOutlined style={{ fontSize: '1.1rem' }} />,
      label: 'Coercive Urgency',
      flagged: verifier.has_urgency,
      statusText: verifier.has_urgency ? 'Pressure detected' : 'None detected',
      detail: verifier.has_urgency ? 'Threat of imminent disconnection or arrest' : undefined,
    },
  ];

  return (
    <div className="panel security-checks-panel">
      <div className="section-header">
        <div className="section-title">
          <FactCheckOutlined style={{ fontSize: '1.15rem', verticalAlign: 'middle', marginRight: '0.4rem' }} />
          SECURITY CHECKS
          <span className="source-tag det">Source: Deterministic Verifier</span>
        </div>
        <span className={`risk-badge ${verifier.deterministic_risk_level}`}>
          Risk: {verifier.deterministic_risk_level.toUpperCase()}
        </span>
      </div>

      <div className="security-telemetry-grid">
        {CHECKS.map((c) => (
          <div key={c.id} className={`telemetry-row ${c.flagged ? 'flagged' : 'clean'}`}>
            <div className="telemetry-lead">
              <span className="telemetry-icon">{c.icon}</span>
              <span className="telemetry-label">{c.label}</span>
            </div>
            <div className="telemetry-result">
              {c.flagged ? (
                <span className="status-indicator flag">
                  <ErrorOutlineOutlined style={{ fontSize: '0.9rem', marginRight: '0.25rem' }} />
                  {c.statusText}
                </span>
              ) : (
                <span className="status-indicator ok">
                  <CheckCircleOutlineOutlined style={{ fontSize: '0.9rem', marginRight: '0.25rem' }} />
                  {c.statusText}
                </span>
              )}
            </div>
            {c.detail && <div className="telemetry-subdetail">{c.detail}</div>}
          </div>
        ))}
      </div>

      {!hasSignals && !hasUrls ? (
        <p className="section-subtitle" style={{ marginTop: '1rem', marginBottom: '0' }}>
          No deterministic security violations, suspicious URLs, or credential harvesting patterns were triggered.
        </p>
      ) : (
        <>
          {hasSignals && (
            <div className="telemetry-section" style={{ marginTop: '1.25rem' }}>
              <div className="item-card-title">RULE-BASED SECURITY SIGNALS:</div>
              <div className="signals-list">
                {verifier.signals.map((sig, idx) => (
                  <div key={idx} className="signal-row">
                    <div className="signal-info">
                      <div className="signal-category">
                        <span className="category-meta">
                          Category: {sig.category.replace(/_/g, ' ')}
                        </span>
                        {sig.pattern_matched}
                      </div>
                      <div className="signal-snippet-row">
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
            <div className="telemetry-section" style={{ marginTop: '1.25rem' }}>
              <div className="item-card-title">EXTRACTED URLS & DOMAIN INSPECTION:</div>
              <div className="card-list" style={{ marginTop: '0.4rem' }}>
                {verifier.urls.map((u, idx) => (
                  <div key={idx} className="item-card url-item-card">
                    <div className="url-raw-line">{u.raw_url}</div>
                    <div className="url-badge-row">
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
                      <ul className="url-notes-list">
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
