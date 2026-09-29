// src/utils/api.ts
// Typed API client for the PrivacyGuard backend

const BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080';

export interface ScanRequest {
  url: string;
}

export interface ScanResponse {
  scanId: number;
  url: string;
  status: string;
  message: string;
}

export interface Finding {
  id: number;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
  title: string;
  description: string;
  recommendation: string;
  evidence?: string;
}

export interface ScanResult {
  id: number;
  url: string;
  scanDate: string;
  overallScore: number;
  gdprScore: number;
  ccpaScore: number;
  coppaScore: number;
  httpsEnabled: boolean;
  sslValid: boolean;
  sslExpiryDays: number;
  privacyPolicyFound: boolean;
  cookiePolicyFound: boolean;
  cookieConsentFound: boolean;
  status: string;
  findings: Finding[];
}

export interface ScanStatus {
  scanId: number;
  status: string;
  errorMessage?: string;
}

class ApiClient {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  private headers(): HeadersInit {
    const h: HeadersInit = { 'Content-Type': 'application/json' };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    return h;
  }

  private async request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${BASE_URL}${path}`, {
      ...init,
      headers: { ...this.headers(), ...(init?.headers || {}) },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: response.statusText }));
      throw new Error(error.message || `API error ${response.status}`);
    }

    return response.json() as Promise<T>;
  }

  /** POST /api/scan — initiate a new scan */
  async startScan(url: string): Promise<ScanResponse> {
    return this.request<ScanResponse>('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  }

  /** GET /api/results/:scanId/status — poll scan progress */
  async getScanStatus(scanId: number): Promise<ScanStatus> {
    return this.request<ScanStatus>(`/api/results/${scanId}/status`);
  }

  /** GET /api/results/:scanId — full scan results */
  async getScanResult(scanId: number): Promise<ScanResult> {
    return this.request<ScanResult>(`/api/results/${scanId}`);
  }

  /** Poll status until COMPLETED or FAILED */
  async pollUntilComplete(
    scanId: number,
    onProgress?: (status: string) => void,
    intervalMs = 2000,
    maxWaitMs = 120_000
  ): Promise<ScanResult> {
    const deadline = Date.now() + maxWaitMs;
    return new Promise((resolve, reject) => {
      const poll = async () => {
        try {
          const status = await this.getScanStatus(scanId);
          onProgress?.(status.status);
          if (status.status === 'COMPLETED') {
            const result = await this.getScanResult(scanId);
            resolve(result);
          } else if (status.status === 'FAILED') {
            reject(new Error(status.errorMessage || 'Scan failed'));
          } else if (Date.now() > deadline) {
            reject(new Error('Scan timed out'));
          } else {
            setTimeout(poll, intervalMs);
          }
        } catch (err) {
          reject(err);
        }
      };
      poll();
    });
  }

  /** GET /api/report/:scanId?format=pdf|json */
  async downloadReport(scanId: number, format: 'pdf' | 'json'): Promise<void> {
    const response = await fetch(`${BASE_URL}/api/report/${scanId}?format=${format}`, {
      headers: this.headers(),
    });
    if (!response.ok) throw new Error('Failed to download report');
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `privacy-report-${scanId}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  /** POST /api/auth/register */
  async register(email: string, password: string, fullName: string): Promise<{ token: string }> {
    return this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, fullName }),
    });
  }

  /** POST /api/auth/login */
  async login(email: string, password: string): Promise<{ token: string }> {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  /** GET /api/scans — user scan history */
  async getUserScans(page = 0, size = 20): Promise<ScanResult[]> {
    return this.request(`/api/scans?page=${page}&size=${size}`);
  }
}

export const api = new ApiClient();
export default api;
