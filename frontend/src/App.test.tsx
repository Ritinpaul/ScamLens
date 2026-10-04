import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import App from './App';
import * as api from './services/api';
import { AnalysisResponse, HealthStatus } from './types/scamlens';

const mockHealthOnline: HealthStatus = {
  status: 'ok',
  app: 'ScamLens',
  version: '0.1.0',
  environment: 'development',
  model_provider: {
    provider: 'Ollama',
    configured_model: 'llama3:latest',
    base_url: 'http://127.0.0.1:11434',
    available: true,
    status_message: 'Ollama online',
  },
  ocr_enabled: true,
};

const mockScamResponse: AnalysisResponse = {
  source: 'decision_engine',
  verdict: 'scam',
  confidence: 'high',
  confidence_explanation: 'Matched critical security rules and social engineering tactics.',
  plain_english_summary: 'This message attempts to capture banking credentials via a fake SBI portal.',
  recommended_action: 'Do NOT click the link. Block the sender and report to cybercrime.gov.in.',
  ai_interpretation: {
    source: 'model',
    model_name: 'llama3:latest',
    verdict: 'scam',
    summary: 'Phishing message attempting to induce panic about account suspension.',
    tactics: [
      {
        type: 'authority_impersonation',
        evidence: 'State Bank Alert',
      },
      {
        type: 'artificial_urgency',
        evidence: 'within 12 hours',
      },
    ],
    requests: ['Click link to update KYC'],
    entities: ['State Bank of India'],
    urls: ['http://sbi-kyc.xyz'],
    recommended_action: 'Do not click.',
    uncertainty_reason: 'None',
    confidence_label: 'model_unvalidated',
  },
  deterministic_findings: {
    source: 'deterministic',
    urls: [
      {
        raw_url: 'http://sbi-kyc.xyz',
        scheme: 'http',
        host: 'sbi-kyc.xyz',
        path: '',
        is_ip_address: false,
        is_shortener: false,
        is_suspicious_tld: true,
        notes: ['Disposable TLD .xyz'],
      },
    ],
    signals: [
      {
        category: 'credential_solicitation',
        pattern_matched: 'Request for banking secrets/passwords/PIN',
        snippet: 'update netbanking password',
        severity: 'critical',
      },
    ],
    has_otp_request: false,
    has_credential_request: true,
    has_payment_request: false,
    has_shortened_url: false,
    has_ip_url: false,
    has_urgency: true,
    deterministic_risk_level: 'critical',
  },
  decision_rationale: [
    'CRITICAL RULE TRIGGERED: One or more critical deterministic rules matched.',
    'AGREEMENT: AI semantic analysis and deterministic checks independently classified this as a scam.',
  ],
  detected_manipulation_tactics: [
    'authority_impersonation: State Bank Alert',
    'artificial_urgency: within 12 hours',
  ],
  extracted_evidence: [
    '[CREDENTIAL_SOLICITATION] Request for banking secrets: update netbanking password',
  ],
  evidence_trace: {
    input_type: 'pasted_text',
    raw_input_snippet: 'Dear customer update KYC http://sbi-kyc.xyz',
    normalized_input_length: 50,
  },
  analyzed_at: '2026-10-04T12:00:00Z',
};

describe('ScamLens UI Integration Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders initial page and displays online status when health check succeeds', async () => {
    vi.spyOn(api, 'checkHealth').mockResolvedValue(mockHealthOnline);

    render(<App />);

    expect(screen.getByRole('heading', { name: /ScamLens/i })).toBeInTheDocument();
    expect(screen.getByText(/Private scam analysis. Runs locally./i)).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText(/LOCAL ENGINE • READY/i)).toBeInTheDocument();
    });
  });

  it('allows text input and submits for analysis', async () => {
    vi.spyOn(api, 'checkHealth').mockResolvedValue(mockHealthOnline);
    const analyzeTextSpy = vi.spyOn(api, 'analyzeText').mockResolvedValue(mockScamResponse);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/LOCAL ENGINE • READY/i)).toBeInTheDocument();
    });

    // Switch to Paste Text tab
    fireEvent.click(screen.getByRole('tab', { name: /Paste Text/i }));

    const textarea = screen.getByLabelText(/Suspicious message input/i);
    fireEvent.change(textarea, { target: { value: 'Dear customer, your SBI account is suspended.' } });

    const analyzeBtn = screen.getByRole('button', { name: /Analyze Message/i });
    expect(analyzeBtn).not.toBeDisabled();

    fireEvent.click(analyzeBtn);

    expect(analyzeTextSpy).toHaveBeenCalledWith('Dear customer, your SBI account is suspended.');

    // Loading state appears
    await waitFor(() => {
      expect(screen.getByText(/SCAM DETECTED/i)).toBeInTheDocument();
    });

    // Check Verdict Card
    expect(screen.getByText(/This message attempts to capture banking credentials/i)).toBeInTheDocument();
    expect(screen.getByText(/Do NOT click the link/i)).toBeInTheDocument();

    // Check AI Understanding Card
    expect(screen.getByText(/AI UNDERSTANDING/i)).toBeInTheDocument();
    expect(screen.getByText(/authority impersonation/i)).toBeInTheDocument();

    // Check Security Checks Card
    expect(screen.getByText(/SECURITY CHECKS/i)).toBeInTheDocument();
    expect(screen.getByText(/Request for banking secrets/i)).toBeInTheDocument();

    // Check Reset flow
    const resetBtn = screen.getByRole('button', { name: /Analyze Another Message/i });
    fireEvent.click(resetBtn);

    // Screen returns to input area
    expect(screen.queryByText(/SCAM DETECTED/i)).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /Screenshot/i })).toBeInTheDocument();
  });

  it('handles image selection and analysis submission', async () => {
    vi.spyOn(api, 'checkHealth').mockResolvedValue(mockHealthOnline);
    const analyzeImageSpy = vi.spyOn(api, 'analyzeImage').mockResolvedValue({
      ...mockScamResponse,
      evidence_trace: {
        input_type: 'screenshot_ocr',
        raw_input_snippet: 'OCR text here',
        extracted_ocr_text: 'OCR text extracted from screenshot',
        normalized_input_length: 30,
        image_metadata: {
          format: 'PNG',
          dimensions: '600x200',
          line_count: 2,
        },
      },
    });

    // Mock URL.createObjectURL and revokeObjectURL
    global.URL.createObjectURL = vi.fn(() => 'blob:mock-preview-url');
    global.URL.revokeObjectURL = vi.fn();

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/LOCAL ENGINE • READY/i)).toBeInTheDocument();
    });

    const file = new File(['fake-png-content'], 'test.png', { type: 'image/png' });
    const fileInput = document.querySelector('.file-input-hidden') as HTMLInputElement;

    fireEvent.change(fileInput, { target: { files: [file] } });

    // Preview rendered
    expect(screen.getByAltText(/Uploaded screenshot preview/i)).toBeInTheDocument();

    const analyzeBtn = screen.getByRole('button', { name: /Analyze Message/i });
    fireEvent.click(analyzeBtn);

    expect(analyzeImageSpy).toHaveBeenCalledWith(file);

    await waitFor(() => {
      expect(screen.getByText(/SCAM DETECTED/i)).toBeInTheDocument();
      expect(screen.getByText(/EVIDENCE TRACE/i)).toBeInTheDocument();
      expect(screen.getByText(/EXACT TEXT EXTRACTED FROM SCREENSHOT/i)).toBeInTheDocument();
      expect(screen.getByText(/OCR text extracted from screenshot/i)).toBeInTheDocument();
    });
  });

  it('displays error banner when backend analysis fails', async () => {
    vi.spyOn(api, 'checkHealth').mockResolvedValue(mockHealthOnline);
    vi.spyOn(api, 'analyzeText').mockRejectedValue(
      new api.ApiError('Connection to ScamLens engine failed. Verify that the backend is active.')
    );

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/LOCAL ENGINE • READY/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('tab', { name: /Paste Text/i }));
    fireEvent.change(screen.getByLabelText(/Suspicious message input/i), {
      target: { value: 'Suspicious test' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Message/i }));

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(screen.getByText(/Connection to ScamLens engine failed/i)).toBeInTheDocument();
    });
  });

  it('renders qualitative AI confidence without fake probabilities and shows deterministic findings', async () => {
    vi.spyOn(api, 'checkHealth').mockResolvedValue(mockHealthOnline);
    vi.spyOn(api, 'analyzeText').mockResolvedValue(mockScamResponse);

    render(<App />);

    await waitFor(() => {
      expect(screen.getByText(/LOCAL ENGINE • READY/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('tab', { name: /Paste Text/i }));
    fireEvent.change(screen.getByLabelText(/Suspicious message input/i), {
      target: { value: 'Test message for security analysis' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Message/i }));

    await waitFor(() => {
      // Must display qualitative unvalidated notice, NOT fake percentages like 92%
      expect(screen.getByText(/Model confidence: unvalidated/i)).toBeInTheDocument();
      // Must not display a fake probability percentage
      expect(screen.queryByText(/92%/i)).not.toBeInTheDocument();

      // Check deterministic signals & URL findings
      expect(screen.getAllByText(/CRITICAL/i).length).toBeGreaterThan(0);
      expect(screen.getByText(/credential solicitation/i)).toBeInTheDocument();
      expect(screen.getAllByText(/sbi-kyc\.xyz/i).length).toBeGreaterThan(0);

      // Check Why This Result
      expect(screen.getByText(/WHY THIS RESULT\?/i)).toBeInTheDocument();
      expect(screen.getAllByText(/CRITICAL RULE TRIGGERED/i).length).toBeGreaterThan(0);
    });
  });
});
