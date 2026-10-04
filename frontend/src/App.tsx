import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { InputArea } from './components/InputArea';
import { VerdictCard } from './components/VerdictCard';
import { WhyResultCard } from './components/WhyResultCard';
import { AiUnderstandingCard } from './components/AiUnderstandingCard';
import { SecurityChecksCard } from './components/SecurityChecksCard';
import { EvidenceTraceCard } from './components/EvidenceTraceCard';
import { checkHealth, analyzeText, analyzeImage, ApiError } from './services/api';
import { AnalysisResponse, HealthStatus } from './types/scamlens';
import './styles/scamlens.css';

export function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    checkHealth()
      .then((data) => {
        if (isMounted) {
          setHealth(data);
          setLoadingHealth(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.warn('Backend health check failed:', err);
          setHealth(null);
          setLoadingHealth(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const handleAnalyzeText = async (text: string) => {
    setError(null);
    setIsAnalyzing(true);
    try {
      const res = await analyzeText(text);
      setResult(res);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred during message analysis. Please try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyzeImage = async (file: File) => {
    setError(null);
    setIsAnalyzing(true);
    try {
      const res = await analyzeImage(file);
      setResult(res);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred during screenshot analysis. Please try again.');
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setError(null);
  };

  return (
    <div className="scamlens-app">
      <Header health={health} loadingHealth={loadingHealth} />

      {error && (
        <div className="error-banner" role="alert">
          <div className="error-title">⚠️ Analysis Error</div>
          <div>{error}</div>
        </div>
      )}

      {!result ? (
        <InputArea
          onAnalyzeText={handleAnalyzeText}
          onAnalyzeImage={handleAnalyzeImage}
          isAnalyzing={isAnalyzing}
          disabled={loadingHealth}
        />
      ) : (
        <main className="results-container" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <VerdictCard
            verdict={result.verdict}
            confidence={result.confidence}
            confidenceExplanation={result.confidence_explanation}
            summary={result.plain_english_summary}
            recommendedAction={result.recommended_action}
          />

          <WhyResultCard rationale={result.decision_rationale} />

          <AiUnderstandingCard ai={result.ai_interpretation} />

          <SecurityChecksCard verifier={result.deterministic_findings} />

          <EvidenceTraceCard trace={result.evidence_trace} />

          <div className="reset-row">
            <button className="reset-btn" onClick={handleReset}>
              🔄 Analyze Another Message
            </button>
          </div>
        </main>
      )}

      <footer className="app-footer">
        <p>
          🔒 <strong>Privacy Assurance:</strong> Your message is analyzed locally on this device using open-source models. ScamLens never sends your data to third-party cloud APIs.
        </p>
      </footer>
    </div>
  );
}

export default App;
