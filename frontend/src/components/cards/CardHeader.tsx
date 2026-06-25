import React from 'react';
import clsx from 'clsx';

interface CardHeaderProps {
  title: string;
  /** Optional monospace path/code line under the title. */
  path?: string;
  /** Badge slot rendered inline after the title (StatusBadge, custom pills). */
  badges?: React.ReactNode;
  /** Right-aligned action buttons (info, security scan, edit, delete). */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * Shared card header: a wrapping row of title + badges on the left and an
 * action-button cluster on the right, with an optional monospace path beneath.
 *
 * Cards pass their entity-specific badges and action buttons as slots; the
 * layout (flex, wrapping, truncation) is owned here so all cards align.
 */
const CardHeader: React.FC<CardHeaderProps> = ({
  title,
  path,
  badges,
  actions,
  className,
}) => {
  return (
    <div className={clsx('p-5 pb-4', className)}>
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white truncate min-w-[120px]">
              {title}
            </h3>
            {badges}
          </div>
          {path && (
            <code className="text-xs text-gray-500 dark:text-gray-400 font-mono break-all">
              {path}
            </code>
          )}
        </div>
        {actions && (
          <div className="flex items-center gap-1 flex-shrink-0">{actions}</div>
        )}
      </div>
    </div>
  );
};

export default CardHeader;
