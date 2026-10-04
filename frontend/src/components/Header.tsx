import React from 'react';
import { HealthStatus } from '../types/scamlens';

interface HeaderProps {
  health: HealthStatus | null;
  loadingHealth: boolean;
}

export const Header: React.FC<HeaderProps> = ({ health, loadingHealth }) => {
  const isOnline = health?.status === 'ok';
  const modelName = health?.model_provider?.configured_model || '';

  return (
    <header className="app-header">
      <div className="brand-section">
        <h1 className="brand-title">
          <span className="brand-icon">🛡️</span> ScamLens
        </h1>
        <p className="brand-subtitle">Private scam analysis. Runs locally.</p>
      </div>

      <div className="status-container">
        {loadingHealth ? (
          <div className="status-badge" role="status">
            <span className="status-dot"></span> Checking Engine...
          </div>
        ) : isOnline ? (
          <div className="status-badge" title={`Model: ${modelName}`}>
            <span className="status-dot online"></span>
            LOCAL ENGINE &bull; READY
          </div>
        ) : (
          <div className="status-badge" title="Backend not reachable">
            <span className="status-dot offline"></span>
            LOCAL ENGINE &bull; OFFLINE
          </div>
        )}
      </div>
    </header>
  );
};
