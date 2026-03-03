// WebSocket event types
export type WSEventType =
    | 'agent_thought'
    | 'tool_call'
    | 'tool_result'
    | 'finding'
    | 'complete'
    | 'error';

export interface WSEvent {
    type: WSEventType;
    message?: string;
    tool?: string;
    input?: Record<string, unknown>;
    data?: unknown;
    subdomain?: string;
    risk?: 'safe' | 'warning' | 'critical';
    details?: Finding;
    summary?: string;
}

// Scan types
export interface Scan {
    id: string;
    domain: string;
    status: 'running' | 'complete' | 'error';
    summary?: string;
    created_at: string;
    updated_at: string;
}

export interface ScanWithFindings extends Scan {
    findings: Finding[];
}

// Finding types
export interface Finding {
    id: string;
    scan_id: string;
    subdomain: string;
    risk: 'safe' | 'warning' | 'critical';
    open_ports: number[];
    tech?: string;
    tech_version?: string;
    outdated: boolean;
    headers?: Record<string, string>;
}

// API response types
export interface StartScanRequest {
    domain: string;
}

export interface StartScanResponse {
    scan_id: string;
    status: string;
}

export interface RecentScan {
    id: string;
    domain: string;
    status: string;
    created_at: string;
}

// Graph types for Nivo
export interface GraphNode {
    id: string;
    label: string;
    risk: 'safe' | 'warning' | 'critical' | 'root';
    type: 'root' | 'subdomain';
}

export interface GraphLink {
    source: string;
    target: string;
}

export interface GraphData {
    nodes: GraphNode[];
    links: GraphLink[];
}

// Activity feed types
export interface ActivityItem {
    id: string;
    event: WSEvent;
    timestamp: Date;
}

// Stats types
export interface ScanStats {
    totalSubdomains: number;
    critical: number;
    warning: number;
    safe: number;
    openServices: number;
}
