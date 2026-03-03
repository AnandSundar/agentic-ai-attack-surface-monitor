import type {
    StartScanRequest,
    StartScanResponse,
    ScanWithFindings,
    RecentScan,
} from './types';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

async function fetchAPI<T>(
    endpoint: string,
    options: RequestInit = {}
): Promise<T> {
    const url = `${API_URL}${endpoint}`;

    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
        },
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        throw new Error(error.error || `HTTP error ${response.status}`);
    }

    return response.json();
}

export async function startScan(domain: string): Promise<StartScanResponse> {
    return fetchAPI<StartScanResponse>('/api/scan', {
        method: 'POST',
        body: JSON.stringify({ domain } as StartScanRequest),
    });
}

export async function getScan(scanId: string): Promise<ScanWithFindings> {
    return fetchAPI<ScanWithFindings>(`/api/scan/${scanId}`);
}

export async function getRecentScans(limit = 20): Promise<RecentScan[]> {
    return fetchAPI<RecentScan[]>(`/api/scans?limit=${limit}`);
}

export async function checkHealth(): Promise<{ status: string }> {
    return fetchAPI<{ status: string }>('/health');
}

export function getWsUrl(scanId: string): string {
    const wsUrl = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080';
    return `${wsUrl}/ws/scan/${scanId}`;
}
