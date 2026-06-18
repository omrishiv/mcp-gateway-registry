import React from 'react';
import { renderHook, act } from '@testing-library/react';
import { ThemeProvider, useTheme, AVAILABLE_THEMES } from '../ThemeContext';

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <ThemeProvider>{children}</ThemeProvider>
);

describe('ThemeContext', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.className = '';
  });

  it('defaults to dark mode and the default palette', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    expect(result.current.theme).toBe('dark');
    expect(result.current.themeName).toBe('default');
    expect(document.documentElement.classList.contains('dark')).toBe(true);
  });

  it('toggles light/dark mode and persists it', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.toggleTheme());
    expect(result.current.theme).toBe('light');
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem('theme')).toBe('light');
  });

  it('applies a named palette theme class and persists it', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.setThemeName('high-contrast'));
    expect(result.current.themeName).toBe('high-contrast');
    expect(document.documentElement.classList.contains('high-contrast')).toBe(true);
    expect(localStorage.getItem('themeName')).toBe('high-contrast');
  });

  it('clears the previous theme class when switching back to default', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.setThemeName('high-contrast'));
    expect(document.documentElement.classList.contains('high-contrast')).toBe(true);
    act(() => result.current.setThemeName('default'));
    expect(document.documentElement.classList.contains('high-contrast')).toBe(false);
  });

  it('keeps dark mode independent of the palette theme', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.setThemeName('high-contrast'));
    // dark class is unaffected by the palette theme.
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(document.documentElement.classList.contains('high-contrast')).toBe(true);
  });

  it('ignores unknown theme names', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    act(() => result.current.setThemeName('bogus' as any));
    expect(result.current.themeName).toBe('default');
  });

  it('exposes the available theme list', () => {
    const { result } = renderHook(() => useTheme(), { wrapper });
    expect(result.current.availableThemes).toEqual(AVAILABLE_THEMES);
  });
});
