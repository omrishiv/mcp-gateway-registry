/**
 * Shared filtering for the Dashboard entity collections.
 *
 * Every collection runs the same tag -> hashtag -> text-search pipeline; they
 * differ only in the leading filter (lifecycle state for internal entities vs
 * source tab for external ones), which fields hold the enabled/status flags,
 * and which fields are text-searched. This pure function captures the shared
 * pipeline so the seven near-identical filter blocks in Dashboard collapse to a
 * single config call each, while the surrounding useMemo (and its deps) stays
 * in the component so memoization is unchanged.
 */

export interface ParsedSearch {
  textQuery: string;
  hashTags: string[];
}

export interface EntityFilterConfig<T> {
  /** Active lifecycle filter: 'all' | 'enabled' | 'disabled' | 'unhealthy' | 'deprecated'. */
  activeFilter?: string;
  /** Field holding the enabled flag (e.g. 'enabled' or 'is_enabled'). */
  enabledField?: keyof T;
  /** Field holding the health status; enables the 'unhealthy' filter when set. */
  statusField?: keyof T;
  /** Field holding lifecycle status; enables hide-deprecated when set. */
  lifecycleField?: keyof T;
  /** External source tab to match (mutually exclusive with the lifecycle filter). */
  sourceTab?: string | null;
  /** Source matcher used when sourceTab is set. */
  matchesSource?: (tags: string[] | undefined, source: string) => boolean;
  /** Sidebar tag selection. */
  selectedTags: string[];
  /** Sidebar tag matcher (owns the selectedTags semantics). */
  matchesSelectedTags: (tags: string[] | undefined) => boolean;
  /** Parsed search box content (#tags + free text). */
  parsedSearch: ParsedSearch;
  /** Hashtag matcher (prefix match while typing). */
  matchesHashTags: (tags: string[] | undefined) => boolean;
  /** Returns the item's tags. */
  getTags: (item: T) => string[] | undefined;
  /** Returns the item's text-searchable field values. */
  getSearchText: (item: T) => (string | undefined)[];
}

/**
 * Apply the shared filter pipeline to a list of entities. Order matches the
 * original inline blocks: leading filter (lifecycle or source) -> sidebar tags
 * -> search hashtags -> free-text search.
 */
export function filterEntities<T>(items: T[], cfg: EntityFilterConfig<T>): T[] {
  let filtered = items;

  // Leading filter: external source tab OR internal lifecycle state.
  if (cfg.sourceTab && cfg.matchesSource) {
    const source = cfg.sourceTab;
    const match = cfg.matchesSource;
    filtered = filtered.filter((item) => match(cfg.getTags(item), source));
  } else if (cfg.activeFilter) {
    const { activeFilter, enabledField, statusField, lifecycleField } = cfg;
    if (activeFilter === 'enabled' && enabledField) {
      filtered = filtered.filter((item) => Boolean(item[enabledField]));
    } else if (activeFilter === 'disabled' && enabledField) {
      filtered = filtered.filter((item) => !item[enabledField]);
    } else if (activeFilter === 'unhealthy' && statusField) {
      filtered = filtered.filter((item) => item[statusField] === 'unhealthy');
    }

    // Hide deprecated unless the deprecated toggle is active.
    if (activeFilter !== 'deprecated' && lifecycleField) {
      filtered = filtered.filter((item) => item[lifecycleField] !== 'deprecated');
    }
  }

  // Sidebar tag filter.
  if (cfg.selectedTags.length > 0) {
    filtered = filtered.filter((item) => cfg.matchesSelectedTags(cfg.getTags(item)));
  }

  // Search box #tags.
  if (cfg.parsedSearch.hashTags.length > 0) {
    filtered = filtered.filter((item) => cfg.matchesHashTags(cfg.getTags(item)));
  }

  // Search box free text.
  if (cfg.parsedSearch.textQuery) {
    const query = cfg.parsedSearch.textQuery;
    filtered = filtered.filter((item) =>
      cfg.getSearchText(item).some((field) =>
        (field || '').toLowerCase().includes(query),
      ),
    );
  }

  return filtered;
}
