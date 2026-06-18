import { filterEntities, ParsedSearch } from '../entityFilters';

interface Item {
  name: string;
  description?: string;
  path: string;
  tags?: string[];
  enabled?: boolean;
  is_enabled?: boolean;
  status?: string;
  lifecycle_status?: string;
}

const EMPTY_SEARCH: ParsedSearch = { textQuery: '', hashTags: [] };

const base = {
  selectedTags: [] as string[],
  matchesSelectedTags: () => true,
  parsedSearch: EMPTY_SEARCH,
  matchesHashTags: () => true,
  getTags: (i: Item) => i.tags,
  getSearchText: (i: Item) => [i.name, i.description, i.path, ...(i.tags || [])],
};

const items: Item[] = [
  { name: 'Alpha', path: '/a', enabled: true, status: 'healthy', lifecycle_status: 'active', tags: ['db'] },
  { name: 'Beta', path: '/b', enabled: false, status: 'unhealthy', lifecycle_status: 'active', tags: ['web'] },
  { name: 'Gamma', path: '/c', enabled: true, status: 'healthy', lifecycle_status: 'deprecated', tags: [] },
];

describe('filterEntities', () => {
  it('hides deprecated items by default', () => {
    const out = filterEntities(items, {
      ...base,
      activeFilter: 'all',
      enabledField: 'enabled',
      statusField: 'status',
      lifecycleField: 'lifecycle_status',
    });
    expect(out.map((i) => i.name)).toEqual(['Alpha', 'Beta']);
  });

  it('shows deprecated items when the deprecated filter is active', () => {
    const out = filterEntities(items, {
      ...base,
      activeFilter: 'deprecated',
      enabledField: 'enabled',
      lifecycleField: 'lifecycle_status',
    });
    expect(out.map((i) => i.name)).toContain('Gamma');
  });

  it('filters by enabled state', () => {
    const out = filterEntities(items, {
      ...base,
      activeFilter: 'enabled',
      enabledField: 'enabled',
      lifecycleField: 'lifecycle_status',
    });
    // Gamma is enabled but deprecated (hidden), so only Alpha remains.
    expect(out.map((i) => i.name)).toEqual(['Alpha']);
  });

  it('filters unhealthy by the status field', () => {
    const out = filterEntities(items, {
      ...base,
      activeFilter: 'unhealthy',
      enabledField: 'enabled',
      statusField: 'status',
      lifecycleField: 'lifecycle_status',
    });
    expect(out.map((i) => i.name)).toEqual(['Beta']);
  });

  it('matches free-text search against name, path, and tags', () => {
    const out = filterEntities(items, {
      ...base,
      activeFilter: 'all',
      enabledField: 'enabled',
      lifecycleField: 'lifecycle_status',
      parsedSearch: { textQuery: 'web', hashTags: [] },
    });
    expect(out.map((i) => i.name)).toEqual(['Beta']);
  });

  it('applies the source filter for external entities (no lifecycle)', () => {
    const matchesSource = (tags: string[] | undefined, source: string) =>
      (tags || []).includes(source);
    const out = filterEntities(items, {
      ...base,
      sourceTab: 'db',
      matchesSource,
    });
    expect(out.map((i) => i.name)).toEqual(['Alpha']);
  });

  it('honors the sidebar tag matcher', () => {
    const out = filterEntities(items, {
      ...base,
      activeFilter: 'all',
      enabledField: 'enabled',
      lifecycleField: 'lifecycle_status',
      selectedTags: ['web'],
      matchesSelectedTags: (tags) => (tags || []).includes('web'),
    });
    expect(out.map((i) => i.name)).toEqual(['Beta']);
  });
});
