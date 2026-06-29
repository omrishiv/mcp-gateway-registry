import React from 'react';
import { SunIcon, MoonIcon } from '@heroicons/react/24/outline';
import { useTheme } from '../contexts/ThemeContext';

/**
 * Header control that flips light/dark mode.
 *
 * Drives the `theme` axis of ThemeContext (the Tailwind `dark:` class on
 * <html>), which is independent from the named palette theme. Shows a moon in
 * light mode (click to go dark) and a sun in dark mode (click to go light),
 * matching the common convention where the icon previews the target mode.
 */
const ThemeToggle: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      className="p-2 text-gray-400 hover:text-gray-500 dark:text-gray-300 dark:hover:text-gray-100 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-purple-500"
      title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
    >
      {isDark ? (
        <SunIcon className="h-5 w-5" />
      ) : (
        <MoonIcon className="h-5 w-5" />
      )}
    </button>
  );
};

export default ThemeToggle;
