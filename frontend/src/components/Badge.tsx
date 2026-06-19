import React from 'react';
import clsx from 'clsx';

/**
 * Color tone for a Badge. Each maps to the standard
 * `bg-<c>-100 text-<c>-700 dark:bg-<c>-900/30 dark:text-<c>-300` pill the app
 * repeats ~37 times for status/label pills (VIRTUAL, SKILL, OFFICIAL, BEARER
 * AUTH, ORPHANED, …). Centralizing the per-tone classes means a contrast or
 * color tweak is one edit here, not a sweep across call sites.
 *
 * Gradient/bespoke badges (ANTHROPIC, ASOR) and the domain badges that already
 * have their own components (StatusBadge, VersionBadge, ANSBadge, ProviderBadge)
 * stay as-is.
 */
export type BadgeTone =
  | 'gray'
  | 'blue'
  | 'cyan'
  | 'teal'
  | 'green'
  | 'emerald'
  | 'amber'
  | 'yellow'
  | 'red'
  | 'purple'
  | 'violet'
  | 'indigo';

const TONE_CLASSES: Record<BadgeTone, string> = {
  gray: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
  blue: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  cyan: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300',
  teal: 'bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-300',
  green: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  emerald:
    'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  amber: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  yellow:
    'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  red: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  purple:
    'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  violet:
    'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  indigo:
    'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
};

interface BadgeProps {
  tone?: BadgeTone;
  /** Pill (rounded-full) by default; `square` uses `rounded`. */
  shape?: 'pill' | 'square';
  /** Adds a subtle border in the tone color. */
  bordered?: boolean;
  className?: string;
  title?: string;
  children: React.ReactNode;
}

const BORDER_CLASSES: Record<BadgeTone, string> = {
  gray: 'border border-gray-200 dark:border-gray-600',
  blue: 'border border-blue-200 dark:border-blue-600',
  cyan: 'border border-cyan-200 dark:border-cyan-600',
  teal: 'border border-teal-200 dark:border-teal-600',
  green: 'border border-green-200 dark:border-green-700',
  emerald: 'border border-emerald-200 dark:border-emerald-600',
  amber: 'border border-amber-200 dark:border-amber-600',
  yellow: 'border border-yellow-200 dark:border-yellow-600',
  red: 'border border-red-200 dark:border-red-600',
  purple: 'border border-purple-200 dark:border-purple-600',
  violet: 'border border-violet-200 dark:border-violet-600',
  indigo: 'border border-indigo-200 dark:border-indigo-600',
};

/**
 * Small status/label pill. Use for ad-hoc colored badges; reach for the
 * dedicated StatusBadge/VersionBadge/ANSBadge/ProviderBadge for those domains.
 */
const Badge: React.FC<BadgeProps> = ({
  tone = 'gray',
  shape = 'pill',
  bordered = false,
  className,
  title,
  children,
}) => {
  return (
    <span
      title={title}
      className={clsx(
        'inline-flex items-center px-2 py-0.5 text-xs font-semibold flex-shrink-0',
        shape === 'pill' ? 'rounded-full' : 'rounded',
        TONE_CLASSES[tone],
        bordered && BORDER_CLASSES[tone],
        className,
      )}
    >
      {children}
    </span>
  );
};

export default Badge;
