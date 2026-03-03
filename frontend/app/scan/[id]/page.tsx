'use client';

import { useEffect, useState, useMemo } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { ActivityFeed } from '@/components/ActivityFeed';
import { SummaryCard } from '@/components/SummaryCard';
import { SubdomainTable } from '@/components/SubdomainTable';
import { AttackGraph } from '@/components/AttackGraph';
import { useWebSocket } from '@/lib/websocket';
import { getScan } from '@/lib/api';
import type { ScanWithFindings, ScanStats } from '@/lib/types';

export default function ScanPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanWithFindings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const { events, findings, status } = useWebSocket(scanId);

  // Merge findings from WebSocket with database findings
  const allFindings = useMemo(() => {
    const wsFindingIds = new Set(findings.map((f) => f.subdomain));
    const dbFindings = scan?.findings || [];
    const wsOnlyFindings = findings.filter((f) => !wsFindingIds.has(f.subdomain));
    return [...dbFindings, ...wsOnlyFindings];
  }, [findings, scan?.findings]);

  // Calculate stats
  const stats: ScanStats = useMemo(() => {
    const critical = allFindings.filter((f) => f.risk === 'critical').length;
    const warning = allFindings.filter((f) => f.risk === 'warning').length;
    const safe = allFindings.filter((f) => f.risk === 'safe').length;
    const openServices = allFindings.reduce(
      (acc, f) => acc + (f.open_ports?.length || 0),
      0
    );

    return {
      totalSubdomains: allFindings.length,
      critical,
      warning,
      safe,
      openServices,
    };
  }, [allFindings]);

  // Load scan from API (only once on mount)
  useEffect(() => {
    async function loadScan() {
      try {
        const data = await getScan(scanId);
        setScan(data);
      } catch (err) {
        console.error('Failed to load scan:', err);
        setError('Failed to load scan');
      } finally {
        setIsLoading(false);
      }
    }

    loadScan();
  }, [scanId]);

  const isComplete = scan?.status === 'complete' || status === 'disconnected';
  const domain = scan?.domain || 'Scanning...';

  // Check for complete event from WebSocket
  const summary = events.find((e) => e.event.type === 'complete')?.event.summary || scan?.summary;

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-purple-medium/30">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition-opacity">
              <span className="text-2xl">🛡️</span>
              <h1 className="text-xl font-semibold text-freeze">Attack Surface Monitor</h1>
            </Link>
          </div>
          <div className="flex items-center gap-4">
            <span className={`text-sm ${status === 'connected' ? 'text-ice' : 'text-purple-heavy'}`}>
              {status === 'connected' && '● Live'}
              {status === 'connecting' && '○ Connecting...'}
              {status === 'disconnected' && '● Offline'}
            </span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-8">
        {/* Error State */}
        {error && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="bg-[#ff4d4d]/10 border border-[#ff4d4d]/30 rounded-xl p-6 mb-6"
          >
            <h3 className="text-lg font-semibold text-[#ff4d4d] mb-2">Error</h3>
            <p className="text-freeze mb-4">{error}</p>
            <button
              onClick={() => router.push('/')}
              className="px-4 py-2 bg-purple-pain text-white rounded-lg hover:bg-purple-medium transition-colors"
            >
              Back to Home
            </button>
          </motion.div>
        )}

        {/* Main Content */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Left Panel - Activity Feed */}
          <div className="lg:col-span-1">
            <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6 h-[calc(100vh-200px)]">
              <ActivityFeed
                events={events}
                isLoading={status === 'connecting'}
              />
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="lg:col-span-2 space-y-6">
            {/* Summary Card */}
            <SummaryCard
              stats={stats}
              domain={domain}
              isLoading={isLoading && allFindings.length === 0}
            />

            {/* Attack Graph */}
            <AttackGraph
              findings={allFindings}
              domain={domain}
              isLoading={isLoading && allFindings.length === 0}
            />

            {/* Subdomain Table */}
            <SubdomainTable
              findings={allFindings}
              isLoading={isLoading && allFindings.length === 0}
            />

            {/* Summary Markdown */}
            {summary && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6"
              >
                <h3 className="text-lg font-semibold text-freeze mb-4">
                  📝 Attack Surface Summary
                </h3>
                <div className="prose prose-invert max-w-none">
                  <pre className="whitespace-pre-wrap text-sm text-purple-medium font-mono">
                    {summary}
                  </pre>
                </div>
              </motion.div>
            )}

            {/* Complete Status */}
            {isComplete && !summary && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-center py-8"
              >
                <div className="text-4xl mb-4">✅</div>
                <p className="text-purple-heavy">Scan completed</p>
              </motion.div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
