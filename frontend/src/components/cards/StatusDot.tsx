import React from 'react';
import clsx from 'clsx';

/**
 * Color tone for a status dot. `off` is the muted gray used for disabled /
 * inactive states; the rest map to the glow colors the card footers use.
 */
export type StatusTone =
  | 'green'
  | 'emerald'
  | 'orange'
  | 'red'
  | 'amber'
  | 'off';

const TONE_CLASSES: Record<StatusTone, string> = {
  green: 'bg-green-400 shadow-lg shadow-green-400/30',
  emerald: 'bg-emerald-400 shadow-lg shadow-emerald-400/30',
  orange: 'bg-orange-400 shadow-lg shadow-orange-400/30',
  red: 'bg-red-400 shadow-lg shadow-red-400/30',
  amber: 'bg-amber-400 shadow-lg shadow-amber-400/30',
  off: 'bg-gray-300 dark:bg-gray-600',
};

interface StatusDotProps {
  tone: StatusTone;
  label: string;
  title?: string;
  className?: string;
}

/**
 * A glowing status dot plus its label, used across every card footer for
 * enabled/disabled and health states. Render two side by side with a
 * StatusDivider between them to match the existing footer layout.
 */
const StatusDot: React.FC<StatusDotProps> = ({
  tone,
  label,
  title,
  className,
}) => {
  return (
    <div className={clsx('flex items-center gap-2', className)}>
      <div className={clsx('w-3 h-3 rounded-full', TONE_CLASSES[tone])} />
      <span
        className="text-sm font-medium text-gray-700 dark:text-gray-300"
        title={title}
      >
        {label}
      </span>
    </div>
  );
};

/** Thin vertical rule placed between two StatusDots in a footer. */
export const StatusDivider: React.FC = () => (
  <div className="w-px h-4 bg-gray-200 dark:bg-gray-600" />
);

export default StatusDot;
