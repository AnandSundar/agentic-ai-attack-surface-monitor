'use client';

import { motion } from 'framer-motion';
import type { ScanStats } from '@/lib/types';

interface SummaryCardProps {
  stats: ScanStats;
  domain: string;
  isLoading?: boolean;
}

export function SummaryCard({ stats, domain, isLoading }: SummaryCardProps) {
  const statCards = [
    {
      label: 'Total Subdomains',
      value: stats.totalSubdomains,
      color: 'text-ice',
      icon: '🌐',
    },
    {
      label: 'Critical',
      value: stats.critical,
      color: 'text-[#ff4d4d]',
      icon: '🚨',
    },
    {
      label: 'Warning',
      value: stats.warning,
      color: 'text-[#f5c542]',
      icon: '⚠️',
    },
    {
      label: 'Safe',
      value: stats.safe,
      color: 'text-ice',
      icon: '✅',
    },
    {
      label: 'Open Services',
      value: stats.openServices,
      color: 'text-purple-medium',
      icon: '🔓',
    },
  ];

  const getRiskScore = () => {
    if (stats.critical > 0) return { label: 'High Risk', color: 'text-[#ff4d4d]' };
    if (stats.warning > 0) return { label: 'Medium Risk', color: 'text-[#f5c542]' };
    if (stats.totalSubdomains > 0) return { label: 'Low Risk', color: 'text-ice' };
    return { label: 'Unknown', color: 'text-purple-heavy' };
  };

  const riskScore = getRiskScore();

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6"
    >
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-lg font-semibold text-freeze">{domain}</h3>
          <p className="text-sm text-purple-heavy">Attack Surface Summary</p>
        </div>
        <div className={`text-lg font-bold ${riskScore.color}`}>
          {riskScore.label}
        </div>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
        {statCards.map((stat, index) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3, delay: index * 0.1 }}
            className="bg-freeze/5 rounded-lg p-4 text-center"
          >
            <div className="text-2xl mb-1">{stat.icon}</div>
            <div className={`text-2xl font-bold ${stat.color}`}>
              {isLoading ? '-' : stat.value}
            </div>
            <div className="text-xs text-purple-heavy">{stat.label}</div>
          </motion.div>
        ))}
      </div>
    </motion.div>
  );
}
