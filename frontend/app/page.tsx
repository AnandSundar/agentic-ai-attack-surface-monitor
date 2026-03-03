'use client';

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import Link from 'next/link';
import { DomainInput } from '@/components/DomainInput';
import { RiskBadge } from '@/components/RiskBadge';
import { getRecentScans } from '@/lib/api';
import type { RecentScan } from '@/lib/types';

export default function Home() {
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function loadRecentScans() {
      try {
        const scans = await getRecentScans(5);
        setRecentScans(scans);
      } catch (error) {
        console.error('Failed to load recent scans:', error);
      } finally {
        setIsLoading(false);
      }
    }

    loadRecentScans();
  }, []);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'complete':
        return 'text-ice';
      case 'running':
        return 'text-[#f5c542]';
      case 'error':
        return 'text-[#ff4d4d]';
      default:
        return 'text-purple-heavy';
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-purple-medium/30">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🛡️</span>
            <h1 className="text-xl font-semibold text-freeze">Attack Surface Monitor</h1>
          </div>
          <nav className="flex items-center gap-4">
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-purple-medium hover:text-ice transition-colors"
            >
              GitHub
            </a>
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <main className="max-w-7xl mx-auto px-4 py-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center mb-12"
        >
          <h2 className="text-5xl font-bold mb-4">
            <span className="bg-gradient-to-r from-ice to-purple-pain bg-clip-text text-transparent">
              AI-Powered
            </span>
            <br />
            Attack Surface Monitoring
          </h2>
          <p className="text-xl text-purple-heavy max-w-2xl mx-auto">
            Automatically discover, analyze, and visualize your organization's 
            external attack surface using advanced AI agents.
          </p>
        </motion.div>

        {/* Domain Input */}
        <div className="mb-16">
          <DomainInput />
        </div>

        {/* Recent Scans */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.3 }}
        >
          <h3 className="text-2xl font-semibold text-freeze mb-6">Recent Scans</h3>
          
          {isLoading ? (
            <div className="text-center py-8 text-purple-heavy animate-pulse">
              Loading recent scans...
            </div>
          ) : recentScans.length === 0 ? (
            <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-8 text-center">
              <div className="text-4xl mb-4">📡</div>
              <p className="text-purple-heavy">
                No scans yet. Enter a domain above to get started!
              </p>
            </div>
          ) : (
            <div className="grid gap-4">
              {recentScans.map((scan, index) => (
                <motion.div
                  key={scan.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: index * 0.1 }}
                >
                  <Link
                    href={`/scan/${scan.id}`}
                    className="block bg-freeze/5 border border-purple-medium/30 rounded-xl p-4 
                      hover:border-purple-pain/50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-mono text-freeze">{scan.domain}</span>
                        <span className={`ml-3 text-sm ${getStatusColor(scan.status)}`}>
                          {scan.status === 'running' && '⏳ '}
                          {scan.status}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-sm text-purple-heavy">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </span>
                        <span className="text-purple-medium">→</span>
                      </div>
                    </div>
                  </Link>
                </motion.div>
              ))}
            </div>
          )}
        </motion.section>

        {/* Features */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.5 }}
          className="mt-16"
        >
          <h3 className="text-2xl font-semibold text-freeze mb-8 text-center">Features</h3>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
              <div className="text-3xl mb-4">🔍</div>
              <h4 className="text-lg font-semibold text-freeze mb-2">Subdomain Enumeration</h4>
              <p className="text-purple-heavy">
                Automatically discover all subdomains using Certificate Transparency logs
              </p>
            </div>
            <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
              <div className="text-3xl mb-4">🤖</div>
              <h4 className="text-lg font-semibold text-freeze mb-2">AI-Powered Analysis</h4>
              <p className="text-purple-heavy">
                Smart technology detection and risk assessment using GPT-4
              </p>
            </div>
            <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
              <div className="text-3xl mb-4">📊</div>
              <h4 className="text-lg font-semibold text-freeze mb-2">Visual Mapping</h4>
              <p className="text-purple-heavy">
                Interactive attack surface visualization with real-time updates
              </p>
            </div>
          </div>
        </motion.section>
      </main>

      {/* Footer */}
      <footer className="border-t border-purple-medium/30 mt-16">
        <div className="max-w-7xl mx-auto px-4 py-8 text-center text-purple-heavy">
          <p>Built with Go, Next.js, and OpenAI</p>
        </div>
      </footer>
    </div>
  );
}
