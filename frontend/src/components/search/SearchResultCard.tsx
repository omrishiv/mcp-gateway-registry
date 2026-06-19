import React from 'react';
import clsx from 'clsx';

/**
 * Accent treatments for a semantic-search result card. These differ from the
 * dashboard entity-card accents (search cards are read-only match results with
 * a relevance badge, not editable entities), so they live here rather than
 * reusing theme/accents.
 */
export type SearchAccent = 'server' | 'tool' | 'agent' | 'skill' | 'virtual' | 'custom';

interface AccentStyle {
  container: string;
  /** Match-percentage badge. */
  matchBadge: string;
  /** Default tag pill. */
  tag: string;
}

const ACCENTS: Record<SearchAccent, AccentStyle> = {
  server: {
    container: 'border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800',
    matchBadge: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-200',
    tag: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200',
  },
  tool: {
    container: 'border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800',
    matchBadge: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-200',
    tag: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200',
  },
  agent: {
    container: 'border border-cyan-200 dark:border-cyan-900/40 bg-white dark:bg-gray-800',
    matchBadge: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-200',
    tag: 'bg-cyan-50 text-cyan-700 dark:bg-cyan-900/40 dark:text-cyan-200',
  },
  skill: {
    container:
      'border-2 border-amber-200 dark:border-amber-700 bg-gradient-to-br from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20',
    matchBadge: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-200',
    tag: 'bg-amber-50 text-amber-700 dark:bg-amber-900/40 dark:text-amber-200',
  },
  virtual: {
    container:
      'border-2 border-indigo-200 dark:border-indigo-700 bg-gradient-to-br from-indigo-50 to-purple-50 dark:from-indigo-900/20 dark:to-purple-900/20',
    matchBadge: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-200',
    tag: 'bg-indigo-50 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-200',
  },
  custom: {
    container:
      'border-2 border-teal-200 dark:border-teal-700 bg-gradient-to-br from-teal-50 to-emerald-50 dark:from-teal-900/20 dark:to-emerald-900/20',
    matchBadge: 'bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-200',
    tag: 'bg-teal-50 text-teal-700 dark:bg-teal-900/40 dark:text-teal-200',
  },
};

const formatPercent = (value: number) => `${Math.round(Math.min(value, 1) * 100)}%`;

interface SearchResultCardProps {
  accent: SearchAccent;
  title: string;
  /** Inline badges after the title (type badge, federated/orphaned pills). */
  badges?: React.ReactNode;
  /** Subtitle under the title (path or visibility). */
  subtitle?: React.ReactNode;
  /** Action buttons rendered before the match badge (info, config, etc.). */
  actions?: React.ReactNode;
  relevanceScore: number;
  description?: string | null;
  tags?: string[];
  /** Extra content under the tags (tools section, key skills, etc.). */
  children?: React.ReactNode;
  /** Footer row content. */
  footer?: React.ReactNode;
}

/**
 * Shared shell for a semantic-search result card. Replaces the five
 * near-identical inline card blocks (server/agent/skill/virtual/custom) that
 * each repeated the bordered container + title/badge/match-score header +
 * line-clamped description + tag row. Per-type specifics (tools list, key
 * skills, footer) go in `children`/`footer`.
 */
const SearchResultCard: React.FC<SearchResultCardProps> = ({
  accent,
  title,
  badges,
  subtitle,
  actions,
  relevanceScore,
  description,
  tags,
  children,
  footer,
}) => {
  const style = ACCENTS[accent];
  return (
    <div
      className={clsx('rounded-2xl p-5 shadow-sm hover:shadow-md transition-shadow', style.container)}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-base font-semibold text-gray-900 dark:text-white">{title}</p>
            {badges}
          </div>
          {subtitle && (
            <p className="text-sm text-gray-500 dark:text-gray-400">{subtitle}</p>
          )}
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {actions}
          <span
            className={clsx(
              'inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold',
              style.matchBadge,
            )}
          >
            {formatPercent(relevanceScore)} match
          </span>
        </div>
      </div>

      <p className="mt-3 text-sm text-gray-600 dark:text-gray-300 line-clamp-3">
        {description || 'No description available.'}
      </p>

      {tags && tags.length > 0 && (
        <div className="mt-4 flex flex-wrap gap-2">
          {tags.slice(0, 6).map((tag) => (
            <span
              key={tag}
              className={clsx('px-2.5 py-1 text-[11px] rounded-full', style.tag)}
            >
              {tag}
            </span>
          ))}
        </div>
      )}

      {children}

      {footer && (
        <div className="mt-4 flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
          {footer}
        </div>
      )}
    </div>
  );
};

export default SearchResultCard;
