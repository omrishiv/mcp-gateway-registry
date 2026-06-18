import React from 'react';
import clsx from 'clsx';

interface TagListProps {
  tags: string[];
  /** Max tags to show before collapsing the rest into a "+N" pill. */
  max?: number;
  /** Prefix each tag (e.g. "#") — servers/agents use a hash, custom does not. */
  prefix?: string;
  /** Pill shape. Servers use square `rounded`; custom entities use `rounded-full`. */
  rounded?: 'rounded' | 'rounded-full';
  /** Optional per-tag class override (e.g. highlight security-pending tags). */
  tagClassName?: (tag: string) => string | undefined;
  className?: string;
}

const DEFAULT_TAG_CLASS =
  'bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300';

/**
 * Renders the first `max` tags as pills plus a "+N" overflow pill. Shared by
 * every card; styling knobs (prefix, shape, per-tag color) cover the small
 * differences between entity types without forking the layout.
 *
 * Returns null when there are no tags so callers don't need a guard.
 */
const TagList: React.FC<TagListProps> = ({
  tags,
  max = 3,
  prefix = '',
  rounded = 'rounded',
  tagClassName,
  className,
}) => {
  if (!tags || tags.length === 0) {
    return null;
  }

  const visible = tags.slice(0, max);
  const overflow = tags.length - visible.length;

  return (
    <div className={clsx('flex flex-wrap gap-1.5', className)}>
      {visible.map((tag) => (
        <span
          key={tag}
          className={clsx(
            'px-2 py-1 text-xs font-medium',
            rounded,
            tagClassName?.(tag) ?? DEFAULT_TAG_CLASS,
          )}
        >
          {prefix}
          {tag}
        </span>
      ))}
      {overflow > 0 && (
        <span
          className={clsx(
            'px-2 py-1 text-xs font-medium bg-gray-50 dark:bg-gray-800 text-gray-600 dark:text-gray-300',
            rounded,
          )}
        >
          +{overflow}
        </span>
      )}
    </div>
  );
};

export default TagList;
