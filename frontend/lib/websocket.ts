'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { getWsUrl } from './api';
import type { WSEvent, Finding, ActivityItem } from './types';

type ConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

interface UseWebSocketReturn {
    events: ActivityItem[];
    findings: Finding[];
    status: ConnectionStatus;
    error: string | null;
    clearEvents: () => void;
}

export function useWebSocket(scanId: string): UseWebSocketReturn {
    const [events, setEvents] = useState<ActivityItem[]>([]);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [status, setStatus] = useState<ConnectionStatus>('connecting');
    const [error, setError] = useState<string | null>(null);
    const wsRef = useRef<WebSocket | null>(null);

    const addEvent = useCallback((event: WSEvent) => {
        const activityItem: ActivityItem = {
            id: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            event,
            timestamp: new Date(),
        };
        setEvents((prev) => [...prev, activityItem]);

        // Extract findings from events
        if (event.type === 'finding' && event.details) {
            const finding = event.details as Finding;
            setFindings((prev) => {
                // Avoid duplicates
                const exists = prev.some((f) => f.subdomain === finding.subdomain);
                if (exists) {
                    return prev.map((f) =>
                        f.subdomain === finding.subdomain ? finding : f
                    );
                }
                return [...prev, finding];
            });
        }
    }, []);

    const connect = useCallback(() => {
        if (!scanId) return;

        // Close existing connection
        if (wsRef.current) {
            wsRef.current.close();
        }

        setStatus('connecting');
        const wsUrl = getWsUrl(scanId);

        try {
            const ws = new WebSocket(wsUrl);
            wsRef.current = ws;

            ws.onopen = () => {
                setStatus('connected');
                setError(null);
                console.log('WebSocket connected');
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data) as WSEvent;
                    addEvent(data);
                } catch (err) {
                    console.error('Failed to parse WebSocket message:', err);
                }
            };

            ws.onerror = (event) => {
                console.error('WebSocket error:', event);
                setStatus('error');
                setError('WebSocket connection error');
            };

            ws.onclose = (event) => {
                console.log('WebSocket closed:', event.code, event.reason);
                setStatus('disconnected');

                // Don't auto-reconnect - let the parent component manage reconnection
                // This prevents infinite loops when the server completes the scan
            };
        } catch (err) {
            console.error('Failed to create WebSocket:', err);
            setStatus('error');
            setError('Failed to connect to WebSocket');
        }
    }, [scanId, addEvent]);

    useEffect(() => {
        connect();

        return () => {
            if (wsRef.current) {
                wsRef.current.close();
            }
        };
    }, [connect]);

    const clearEvents = useCallback(() => {
        setEvents([]);
        setFindings([]);
    }, []);

    return {
        events,
        findings,
        status,
        error,
        clearEvents,
    };
}
