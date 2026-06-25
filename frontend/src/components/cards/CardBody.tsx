import React from 'react';
import clsx from 'clsx';

interface CardBodyProps {
  /** Line-clamped description. Falls back to a muted placeholder when empty. */
  description?: string | null;
  /** Placeholder shown when description is empty. Pass null to render nothing. */
  emptyText?: string | null;
  /** Number of lines before truncation. */
  clamp?: 2 | 3;
  /** Extra content under the description (ANS bar, tags, target agents, etc.). */
  children?: React.ReactNode;
  className?: string;
}

/**
 * The card's main content region: a line-clamped description followed by an
 * arbitrary slot for entity-specific rows (tags, trust bars, attribute lists).
 *
 * Pads horizontally to align with the header/footer. Cards that need a stats
 * grid render <CardStatsRow> as a child or sibling.
 */
const CardBody: React.FC<CardBodyProps> = ({
  description,
  emptyText = 'No description available',
  clamp = 2,
  children,
  className,
}) => {
  const text = description || emptyText;

  return (
    <div className={clsx('px-5 pb-4', className)}>
      {text && (
        <p
          className={clsx(
            'text-gray-600 dark:text-gray-300 text-sm leading-relaxed mb-4',
            clamp === 2 ? 'line-clamp-2' : 'line-clamp-3',
          )}
        >
          {text}
        </p>
      )}
      {children}
    </div>
  );
};

export default CardBody;
