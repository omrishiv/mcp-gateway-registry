import React from 'react';
import clsx from 'clsx';

interface ToggleSwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  ariaLabel: string;
  disabled?: boolean;
}

/**
 * The enable/disable toggle shared by every entity card.
 *
 * Extracted verbatim from the per-card inline markup so all five cards render
 * an identical switch. The active color stays blue today; the theming phase
 * swaps it for an accent token.
 */
const ToggleSwitch: React.FC<ToggleSwitchProps> = ({
  checked,
  onChange,
  ariaLabel,
  disabled = false,
}) => {
  return (
    <label className="relative inline-flex items-center cursor-pointer">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        disabled={disabled}
        className="sr-only peer"
        aria-label={ariaLabel}
      />
      <div
        className={clsx(
          'relative w-12 h-6 rounded-full transition-colors duration-200 ease-in-out',
          checked ? 'bg-blue-600' : 'bg-gray-300 dark:bg-gray-600',
        )}
      >
        <div
          className={clsx(
            'absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform duration-200 ease-in-out',
            checked ? 'translate-x-6' : 'translate-x-0',
          )}
        />
      </div>
    </label>
  );
};

export default ToggleSwitch;
