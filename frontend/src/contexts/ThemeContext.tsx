import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';

/**
 * Light/dark mode. Drives Tailwind's `dark:` variants via the `dark` class on
 * <html>. Kept as a distinct axis from the named palette theme so the existing
 * dark-mode styling continues to work unchanged.
 */
type Mode = 'light' | 'dark';

/**
 * Named palette theme. `default` uses the base token values; other names map to
 * an `html.<name>` block in index.css that remaps the CSS color variables at
 * runtime. Add a theme by defining that block and listing the name here.
 */
export type ThemeName = 'default' | 'high-contrast';

export const AVAILABLE_THEMES: ThemeName[] = ['default', 'high-contrast'];

interface ThemeContextType {
  /** Light/dark mode (Tailwind `dark:` variants). */
  theme: Mode;
  toggleTheme: () => void;
  /** Active palette theme name. */
  themeName: ThemeName;
  setThemeName: (name: ThemeName) => void;
  availableThemes: ThemeName[];
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

interface ThemeProviderProps {
  children: ReactNode;
}

const THEME_CLASSES: ThemeName[] = AVAILABLE_THEMES.filter((t) => t !== 'default');

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  const [theme, setTheme] = useState<Mode>('dark');
  const [themeName, setThemeNameState] = useState<ThemeName>('default');

  useEffect(() => {
    // Restore light/dark mode (defaults to dark).
    const savedTheme = localStorage.getItem('theme') as Mode | null;
    setTheme(savedTheme || 'dark');

    // Restore palette theme (defaults to default).
    const savedName = localStorage.getItem('themeName') as ThemeName | null;
    if (savedName && AVAILABLE_THEMES.includes(savedName)) {
      setThemeNameState(savedName);
    }
  }, []);

  useEffect(() => {
    // Toggle the Tailwind dark-mode class.
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    // Apply the active palette theme class, clearing any other theme class so
    // switching themes never leaves a stale class behind.
    const root = window.document.documentElement;
    THEME_CLASSES.forEach((name) => root.classList.remove(name));
    if (themeName !== 'default') {
      root.classList.add(themeName);
    }
    localStorage.setItem('themeName', themeName);
  }, [themeName]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  const setThemeName = (name: ThemeName) => {
    if (AVAILABLE_THEMES.includes(name)) {
      setThemeNameState(name);
    }
  };

  const value: ThemeContextType = {
    theme,
    toggleTheme,
    themeName,
    setThemeName,
    availableThemes: AVAILABLE_THEMES,
  };

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};
