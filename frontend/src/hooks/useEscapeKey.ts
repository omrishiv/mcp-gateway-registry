import { useEffect } from 'react';

/**
 * Calls the provided callback when the Escape key is pressed,
 * but only while `isActive` is true.
 */
const useEscapeKey = (onEscape: () => void, isActive: boolean) => {
  useEffect(() => {
    if (!isActive) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onEscape();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [onEscape, isActive]);
};

export default useEscapeKey;
