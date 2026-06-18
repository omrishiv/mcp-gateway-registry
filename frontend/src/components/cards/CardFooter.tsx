import React from 'react';
import clsx from 'clsx';

interface CardFooterProps {
  /** Left-aligned content, typically one or more StatusDots + StatusDivider. */
  status: React.ReactNode;
  /** Right-aligned content: timestamp, refresh button, toggle switch, etc. */
  controls?: React.ReactNode;
  className?: string;
}

/**
 * The bordered footer bar shared by every entity card. Holds status indicators
 * on the left and controls on the right. The pinned-to-bottom behavior (mt-auto)
 * lets footers line up across a grid row regardless of body height.
 */
const CardFooter: React.FC<CardFooterProps> = ({
  status,
  controls,
  className,
}) => {
  return (
    <div
      className={clsx(
        'mt-auto px-5 py-4 border-t border-gray-100 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-900/30 rounded-b-2xl',
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">{status}</div>
        {controls && <div className="flex items-center gap-3">{controls}</div>}
      </div>
    </div>
  );
};

export default CardFooter;
