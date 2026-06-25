import React from 'react';
import clsx from 'clsx';

interface CardStatsRowProps {
  /** Number of equal-width columns. Servers use 3, virtual servers 2. */
  columns: 1 | 2 | 3;
  children: React.ReactNode;
  className?: string;
}

const COLUMN_CLASSES: Record<1 | 2 | 3, string> = {
  1: 'grid-cols-1',
  2: 'grid-cols-2',
  3: 'grid-cols-3',
};

/**
 * A fixed-column grid for card stats (star rating, tool count, version badge).
 * Each child is one cell; the card decides what goes in each.
 */
const CardStatsRow: React.FC<CardStatsRowProps> = ({
  columns,
  children,
  className,
}) => {
  return (
    <div className={clsx('px-5 pb-4', className)}>
      <div className={clsx('grid gap-4', COLUMN_CLASSES[columns])}>
        {children}
      </div>
    </div>
  );
};

export default CardStatsRow;
