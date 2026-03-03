'use client';

import { useMemo } from 'react';
import { ResponsiveNetwork } from '@nivo/network';
import type { Finding, GraphData, GraphNode } from '@/lib/types';

interface AttackGraphProps {
  findings: Finding[];
  domain: string;
  isLoading?: boolean;
}

export function AttackGraph({ findings, domain, isLoading }: AttackGraphProps) {
  const graphData: GraphData = useMemo(() => {
    const nodes: GraphNode[] = [];
    const links: { source: string; target: string }[] = [];

    // Ensure domain is valid
    const validDomain = domain && domain !== 'Scanning...' ? domain : 'root';

    // Add root domain node
    nodes.push({
      id: validDomain,
      label: validDomain,
      risk: 'root',
      type: 'root',
    });

    // Add subdomain nodes and links
    findings.forEach((finding) => {
      if (!finding?.subdomain) return;

      nodes.push({
        id: finding.subdomain,
        label: finding.subdomain,
        risk: finding.risk || 'safe',
        type: 'subdomain',
      });

      links.push({
        source: validDomain,
        target: finding.subdomain,
      });
    });

    return { nodes, links };
  }, [findings, domain]);

  const getNodeColor = (node: GraphNode) => {
    if (!node || !node.type) return '#a0d2eb'; // Default to ice color if node is undefined
    if (node.type === 'root') return '#8458B3'; // purple.pain
    switch (node.risk) {
      case 'critical':
        return '#ff4d4d';
      case 'warning':
        return '#f5c542';
      case 'safe':
        return '#a0d2eb'; // ice
      default:
        return '#a0d2eb';
    }
  };

  if (isLoading && findings.length === 0) {
    return (
      <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-freeze mb-4">Attack Surface Map</h3>
        <div className="h-80 flex items-center justify-center">
          <div className="text-purple-heavy animate-pulse">Loading graph...</div>
        </div>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
        <h3 className="text-lg font-semibold text-freeze mb-4">Attack Surface Map</h3>
        <div className="h-80 flex items-center justify-center">
          <div className="text-purple-heavy">No data to visualize</div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-freeze/5 border border-purple-medium/30 rounded-xl p-6">
      <h3 className="text-lg font-semibold text-freeze mb-4">
        Attack Surface Map ({findings.length} endpoints)
      </h3>
      <div className="h-96">
        <ResponsiveNetwork
          data={graphData}
          margin={{ top: 20, right: 20, bottom: 20, left: 20 }}
          linkDistance={100}
          centripetalForce={0.5}
          nodeSize={60}
          activeNodeSize={70}
          nodeColor={(node: any) => {
            const nodeData = node?.data;
            if (!nodeData) return '#a0d2eb';
            return getNodeColor(nodeData as GraphNode);
          }}
          nodeBorderWidth={2}
          nodeBorderColor={{
            from: 'color',
            modifiers: [['darker', 0.8]],
          }}
          linkWidth={1.5}
          linkColor={{
            from: 'source.color',
            modifiers: [['opacity', 0.4]],
          }}
          labelsTextColor="#e5eaf5"
          labelsBgColor={{ from: 'color', modifiers: [['opacity', 0.8]] }}
          motionConfig="gentle"
        />
      </div>
    </div>
  );
}
