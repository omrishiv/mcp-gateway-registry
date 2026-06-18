import { slugify, pathFromName } from '../slug';

describe('slugify', () => {
  it('lowercases and hyphenates', () => {
    expect(slugify('My Cool Server')).toBe('my-cool-server');
  });
  it('collapses non-alphanumeric runs and trims hyphens', () => {
    expect(slugify('  Foo / Bar!! ')).toBe('foo-bar');
  });
});

describe('pathFromName', () => {
  it('returns empty for an empty name', () => {
    expect(pathFromName('')).toBe('');
  });
  it('builds a root path without a prefix', () => {
    expect(pathFromName('My Server')).toBe('/my-server');
  });
  it('builds a prefixed path', () => {
    expect(pathFromName('My Server', 'virtual')).toBe('/virtual/my-server');
  });
});
