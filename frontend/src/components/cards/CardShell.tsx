import React from 'react';
import clsx from 'clsx';
import { ACCENTS, AccentToken } from '../../theme/accents';

interface CardShellProps {
  /** Accent token driving this card's identity color (see theme/accents.ts). */
  accent?: AccentToken;
  className?: string;
  children: React.ReactNode;
}

/**
 * The outer container shared by every entity card: rounded corners, shadow,
 * hover elevation, full-height flex column so footers align across a grid row.
 *
 * Cards compose their own header / body / footer inside this shell and pass the
 * same `accent` to those primitives so every shared feature (footer, divider,
 * toggle, tags) renders with one consistent color. The accent's color literals
 * live in theme/accents.ts — the single place the theming phase remaps.
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
        ACCENTS[accent].container,
        className,
      )}
    >
      {children}
    </div>
  );
};

export default CardShell;
