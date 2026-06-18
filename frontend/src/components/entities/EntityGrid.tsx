import React from 'react';
import clsx from 'clsx';

interface EntityGridProps {
  /**
   * Extra classes for the grid container (e.g. ``pb-12`` bottom padding the
   * top-level server grid uses).
   */
  className?: string;
  children: React.ReactNode;
}

/**
 * The responsive card grid used by every entity collection on the Dashboard.
 *
 * Replaces the auto-fit / minmax(380px) / clamp-gap inline style that was
 * copy-pasted at ~10 render sites. Pure layout — callers map their own cards
 * as children.
 */
const EntityGrid: React.FC<EntityGridProps> = ({ className, children }) => {
  return (
    <div
      className={clsx('grid', className)}
      style={{
        gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))',
        gap: 'clamp(1.5rem, 3vw, 2.5rem)',
      }}
    >
      {children}
    </div>
  );
};

export default EntityGrid;
