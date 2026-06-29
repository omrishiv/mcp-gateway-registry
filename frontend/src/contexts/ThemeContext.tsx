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

const SYSTEM_DARK_QUERY = '(prefers-color-scheme: dark)';


/** Read the OS-level light/dark preference, defaulting to dark when unknown. */
function _systemMode(): Mode {
  if (typeof window === 'undefined' || !window.matchMedia) {
    return 'dark';
  }
  return window.matchMedia(SYSTEM_DARK_QUERY).matches ? 'dark' : 'light';
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ children }) => {
  // Until the user explicitly picks a mode, follow the OS preference (and keep
  // following live changes to it). An explicit choice is persisted and wins.
  const [userChoseMode, setUserChoseMode] = useState(false);
  const [theme, setTheme] = useState<Mode>(_systemMode);
  const [themeName, setThemeNameState] = useState<ThemeName>('default');

  useEffect(() => {
    // Restore an explicit light/dark choice; otherwise keep the OS preference
    // used to seed the initial state above.
    const savedTheme = localStorage.getItem('theme') as Mode | null;
    if (savedTheme === 'light' || savedTheme === 'dark') {
      setUserChoseMode(true);
      setTheme(savedTheme);
    }

    // Restore palette theme (defaults to default).
    const savedName = localStorage.getItem('themeName') as ThemeName | null;
    if (savedName && AVAILABLE_THEMES.includes(savedName)) {
      setThemeNameState(savedName);
    }
  }, []);

  useEffect(() => {
    // While the user hasn't made an explicit choice, mirror live OS changes.
    if (userChoseMode || typeof window === 'undefined' || !window.matchMedia) {
      return;
    }
    const media = window.matchMedia(SYSTEM_DARK_QUERY);
    const handleChange = (event: MediaQueryListEvent) => {
      setTheme(event.matches ? 'dark' : 'light');
    };
    media.addEventListener('change', handleChange);
    return () => media.removeEventListener('change', handleChange);
  }, [userChoseMode]);

  useEffect(() => {
    // Toggle the Tailwind dark-mode class. Persistence is intentionally NOT done
    // here — that happens only on an explicit choice in toggleTheme(), so a
    // system-default session never masquerades as a saved preference.
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
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
    setTheme((prev) => {
      const next = prev === 'light' ? 'dark' : 'light';
      // An explicit choice: stop following the OS and persist it.
      setUserChoseMode(true);
      localStorage.setItem('theme', next);
      return next;
    });
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
