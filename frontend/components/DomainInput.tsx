'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { motion } from 'framer-motion';
import { startScan } from '@/lib/api';

interface DomainInputProps {
  onScanStart?: (scanId: string) => void;
}

export function DomainInput({ onScanStart }: DomainInputProps) {
  const [domain, setDomain] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;

    setIsLoading(true);
    setError(null);

    try {
      const response = await startScan(domain.trim());
      if (onScanStart) {
        onScanStart(response.scan_id);
      } else {
        router.push(`/scan/${response.scan_id}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start scan');
      setIsLoading(false);
    }
  };

  const handleDemo = async () => {
    setDomain('tesla.com');
    setIsLoading(true);
    setError(null);

    try {
      const response = await startScan('tesla.com');
      if (onScanStart) {
        onScanStart(response.scan_id);
      } else {
        router.push(`/scan/${response.scan_id}`);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start demo scan');
      setIsLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="w-full max-w-2xl mx-auto"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter domain (e.g., tesla.com)"
            className="flex-1 px-4 py-3 bg-freeze/5 border border-purple-medium/30 rounded-lg 
              text-freeze placeholder:text-purple-heavy focus:outline-none focus:border-purple-pain 
              focus:ring-1 focus:ring-purple-pain transition-colors"
            disabled={isLoading}
          />
          <button
            type="submit"
            disabled={isLoading || !domain.trim()}
            className="px-6 py-3 bg-purple-pain text-white font-medium rounded-lg 
              hover:bg-purple-medium disabled:opacity-50 disabled:cursor-not-allowed 
              transition-colors whitespace-nowrap"
          >
            {isLoading ? 'Starting...' : 'Scan'}
          </button>
        </div>

        {error && (
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-[#ff4d4d] text-sm"
          >
            {error}
          </motion.p>
        )}

        <div className="text-center">
          <button
            type="button"
            onClick={handleDemo}
            disabled={isLoading}
            className="text-sm text-purple-medium hover:text-ice transition-colors 
              disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Try Demo with tesla.com
          </button>
        </div>
      </form>
    </motion.div>
  );
}
