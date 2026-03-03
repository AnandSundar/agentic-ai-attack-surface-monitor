'use client';

import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import type { ActivityItem, WSEvent } from '@/lib/types';
import { RiskBadge } from './RiskBadge';

interface ActivityFeedProps {
  events: ActivityItem[];
  isLoading?: boolean;
}

function EventItem({ item }: { item: ActivityItem }) {
  const { event } = item;

  const getEventStyles = () => {
    switch (event.type) {
      case 'agent_thought':
        return 'text-purple-heavy italic';
      case 'tool_call':
        return 'text-ice';
      case 'tool_result':
        return 'text-purple-medium';
      case 'finding':
        return '';
      case 'complete':
        return 'text-purple-pain font-bold';
      case 'error':
        return 'text-[#ff4d4d]';
      default:
        return 'text-freeze';
    }
  };

  const renderContent = () => {
    switch (event.type) {
      case 'agent_thought':
        return (
          <span className="text-purple-heavy italic">
            💭 {event.message}
          </span>
        );

      case 'tool_call':
        return (
          <div className="flex items-center gap-2">
            <span className="text-ice">⚡</span>
            <span className="text-ice font-mono text-sm">{event.tool}</span>
            {event.input && (
              <pre className="text-xs text-purple-heavy mt-1 ml-4">
                {JSON.stringify(event.input, null, 2)}
              </pre>
            )}
          </div>
        );

      case 'tool_result':
        return (
          <div className="text-purple-medium">
            <span>✓ {event.tool} result</span>
            {event.data && typeof event.data === 'object' && (
              <pre className="text-xs text-purple-heavy mt-1 ml-4 max-h-24 overflow-auto">
                {JSON.stringify(event.data, null, 2)}
              </pre>
            )}
          </div>
        );

      case 'finding':
        return (
          <div className="flex items-start gap-2">
            <span className="text-lg">
              {event.risk === 'critical' ? '🚨' : event.risk === 'warning' ? '⚠️' : '✅'}
            </span>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-freeze">{event.subdomain}</span>
                {event.risk && <RiskBadge risk={event.risk} />}
              </div>
              {event.details && (
                <div className="text-xs text-purple-heavy mt-1 ml-6">
                  {typeof event.details === 'object' && event.details !== null && 'tech' in event.details && 
                    (event.details as { tech?: string }).tech && (
                    <span>Tech: {(event.details as { tech: string }).tech}</span>
                  )}
                  {typeof event.details === 'object' && event.details !== null && 'open_ports' in event.details && 
                    Array.isArray((event.details as { open_ports: number[] }).open_ports) && 
                    (event.details as { open_ports: number[] }).open_ports.length > 0 && (
                    <span className="ml-2">
                      Ports: {((event.details as { open_ports: number[] }).open_ports as number[]).join(', ')}
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        );

      case 'complete':
        return (
          <span className="text-purple-pain font-bold">
            ✓ Scan complete!
          </span>
        );

      case 'error':
        return (
          <span className="text-[#ff4d4d]">
            ✗ Error: {event.message}
          </span>
        );

      default:
        return null;
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ duration: 0.3 }}
      className={`p-3 rounded-lg bg-freeze/5 border border-purple-medium/20 ${getEventStyles()}`}
    >
      <div className="text-xs text-purple-heavy/60 mb-1">
        {item.timestamp.toLocaleTimeString()}
      </div>
      {renderContent()}
    </motion.div>
  );
}

export function ActivityFeed({ events, isLoading }: ActivityFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="h-full flex flex-col">
      <h3 className="text-lg font-semibold text-freeze mb-4 flex items-center gap-2">
        <span>📡</span> Live Activity
      </h3>
      
      {isLoading && events.length === 0 && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-purple-heavy animate-pulse">
            Connecting to scan...
          </div>
        </div>
      )}

      {!isLoading && events.length === 0 && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-purple-heavy">
            No activity yet
          </div>
        </div>
      )}

      <div 
        ref={scrollRef}
        className="flex-1 overflow-y-auto space-y-2 pr-2"
      >
        <AnimatePresence>
          {events.map((item) => (
            <EventItem key={item.id} item={item} />
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}
