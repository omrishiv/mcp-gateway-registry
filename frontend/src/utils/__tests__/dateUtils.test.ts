import { formatTimeSince } from '../dateUtils';

describe('formatTimeSince', () => {
  const NOW = new Date('2026-06-18T12:00:00.000Z');

  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(NOW);
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('returns null for missing input', () => {
    expect(formatTimeSince(null)).toBeNull();
    expect(formatTimeSince(undefined)).toBeNull();
    expect(formatTimeSince('')).toBeNull();
  });

  it('returns null for an invalid timestamp', () => {
    expect(formatTimeSince('not-a-date')).toBeNull();
  });

  it('formats seconds ago', () => {
    expect(formatTimeSince('2026-06-18T11:59:30.000Z')).toBe('30s ago');
  });

  it('formats minutes ago', () => {
    expect(formatTimeSince('2026-06-18T11:45:00.000Z')).toBe('15m ago');
  });

  it('formats hours ago', () => {
    expect(formatTimeSince('2026-06-18T09:00:00.000Z')).toBe('3h ago');
  });

  it('formats days ago', () => {
    expect(formatTimeSince('2026-06-16T12:00:00.000Z')).toBe('2d ago');
  });

  it('treats future timestamps as "just now"', () => {
    expect(formatTimeSince('2026-06-18T12:05:00.000Z')).toBe('just now');
  });
});
