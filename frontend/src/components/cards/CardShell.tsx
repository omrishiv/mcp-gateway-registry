import React from 'react';
import clsx from 'clsx';

/**
 * Visual accent applied to the card container. Each entity type picks an
 * accent so its cards are visually distinguishable while sharing one
 * skeleton. `neutral` is the default white/gray card; the others apply a
 * tinted gradient + colored border (matching the existing per-entity styling).
 *
 * In the theming phase these literal color families are routed through CSS
 * variables; until then they map to the Tailwind classes the cards use today.
 */
export type CardAccent =
  | 'neutral'
  | 'purple'
  | 'cyan'
  | 'amber'
  | 'teal';

const ACCENT_CLASSES: Record<CardAccent, string> = {
  neutral:
    'bg-white dark:bg-gray-800 border border-gray-100 dark:border-gray-700 hover:border-gray-200 dark:hover:border-gray-600',
  purple:
    'bg-gradient-to-br from-purple-50 to-indigo-50 dark:from-purple-900/20 dark:to-indigo-900/20 border-2 border-purple-200 dark:border-purple-700 hover:border-purple-300 dark:hover:border-purple-600',
  cyan:
    'bg-gradient-to-br from-cyan-50 to-blue-50 dark:from-cyan-900/20 dark:to-blue-900/20 border-2 border-cyan-200 dark:border-cyan-700 hover:border-cyan-300 dark:hover:border-cyan-600',
  amber:
    'bg-gradient-to-br from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20 border-2 border-amber-200 dark:border-amber-700 hover:border-amber-300 dark:hover:border-amber-600',
  teal:
    'bg-gradient-to-br from-teal-50 to-emerald-50 dark:from-teal-900/20 dark:to-emerald-900/20 border-2 border-teal-200 dark:border-teal-700 hover:border-teal-300 dark:hover:border-teal-600',
};

interface CardShellProps {
  accent?: CardAccent;
  className?: string;
  children: React.ReactNode;
}

/**
 * The outer container shared by every entity card: rounded corners, shadow,
 * hover elevation, full-height flex column so footers align across a grid row.
 *
 * Cards compose their own header / body / footer inside this shell. Keeping the
 * container in one place means the theming phase only has to touch ACCENT_CLASSES.
 */
const CardShell: React.FC<CardShellProps> = ({
  accent = 'neutral',
  className,
  children,
}) => {
  return (
    <div
      className={clsx(
        'group rounded-2xl shadow-sm hover:shadow-xl transition-all duration-300 h-full flex flex-col',
        ACCENT_CLASSES[accent],
        className,
      )}
    >
      {children}
    </div>
  );
};

export default CardShell;
