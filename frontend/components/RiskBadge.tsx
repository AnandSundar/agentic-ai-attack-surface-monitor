import { cn } from '@/lib/utils';

interface RiskBadgeProps {
  risk: 'safe' | 'warning' | 'critical';
  className?: string;
}

const riskConfig = {
  safe: {
    label: 'Safe',
    bgColor: 'bg-ice/20',
    textColor: 'text-ice',
    borderColor: 'border-ice/30',
  },
  warning: {
    label: 'Warning',
    bgColor: 'bg-[#f5c542]/20',
    textColor: 'text-[#f5c542]',
    borderColor: 'border-[#f5c542]/30',
  },
  critical: {
    label: 'Critical',
    bgColor: 'bg-[#ff4d4d]/20',
    textColor: 'text-[#ff4d4d]',
    borderColor: 'border-[#ff4d4d]/30',
  },
};

export function RiskBadge({ risk, className }: RiskBadgeProps) {
  const config = riskConfig[risk];

  return (
    <span
      className={cn(
        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
        config.bgColor,
        config.textColor,
        config.borderColor,
        className
      )}
    >
      {config.label}
    </span>
  );
}
