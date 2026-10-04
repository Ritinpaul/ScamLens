import { AnalysisResponse, HealthStatus } from '../types/scamlens';

const API_BASE = ''; // Uses Vite proxy in development or relative path

export class ApiError extends Error {
  statusCode?: number;
  details?: unknown;

  constructor(message: string, statusCode?: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorMessage = `Server error (${res.status})`;
    try {
      const errorData = await res.json();
      if (errorData.detail) {
        errorMessage = typeof errorData.detail === 'string' ? errorData.detail : JSON.stringify(errorData.detail);
      }
    } catch {
      // Body was not JSON
    }

    if (res.status === 503) {
      errorMessage = 'Local AI model runtime is unavailable. Please ensure Ollama is running and Llama 3 is loaded.';
    } else if (res.status === 422) {
      // Format error from image or input validation
      if (!errorMessage.includes('Image processing error') && !errorMessage.includes('Unsupported file format')) {
        errorMessage = `Input validation error: ${errorMessage}`;
      }
    }

    throw new ApiError(errorMessage, res.status);
  }

  return (await res.json()) as T;
}

export async function checkHealth(): Promise<HealthStatus> {
  try {
    const res = await fetch(`${API_BASE}/health`, { method: 'GET' });
    return await handleResponse<HealthStatus>(res);
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(
      "ScamLens couldn't reach the local analysis engine. Make sure the backend server is running on http://127.0.0.1:8000.",
      0
    );
  }
}

export async function analyzeText(text: string): Promise<AnalysisResponse> {
  try {
    const res = await fetch(`${API_BASE}/api/analyze/text`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });
    return await handleResponse<AnalysisResponse>(res);
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(
      "Connection to ScamLens engine failed. Verify that the backend is active on http://127.0.0.1:8000.",
      0
    );
  }
}

export async function analyzeImage(file: File): Promise<AnalysisResponse> {
  try {
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_BASE}/api/analyze/image`, {
      method: 'POST',
      body: formData,
    });
    return await handleResponse<AnalysisResponse>(res);
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(
      "Connection to ScamLens engine failed during screenshot upload. Verify that the backend is running.",
      0
    );
  }
}
