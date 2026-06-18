import { useCallback } from 'react';

type ToastFn = (message: string, type: 'success' | 'error') => void;

interface UseEntityToggleOptions<T> {
  /** State setter for the entity list (optimistic update + revert run through it). */
  setItems: React.Dispatch<React.SetStateAction<T[]>>;
  /** Field on each item that holds the enabled flag (e.g. 'enabled' or 'is_enabled'). */
  enabledField: keyof T;
  /** Performs the toggle API call. Receives the item's path and the new state. */
  apiCall: (path: string, enabled: boolean) => Promise<void>;
  /** Human label used in toast/error messages (e.g. 'Server', 'Agent', 'Skill'). */
  label: string;
  showToast: ToastFn;
}

/**
 * The optimistic enable/disable toggle shared by the server, agent, and skill
 * collections. Flips the entity's enabled flag immediately, calls the API, and
 * reverts (with an error toast) on failure — the pattern that was triplicated
 * in Dashboard. Items are matched by their `path` field.
 *
 * Only the API call shape differs per entity (FormData vs query param vs JSON),
 * so callers pass that as `apiCall`; everything else is shared here.
 */
export function useEntityToggle<T extends { path: string }>(
  options: UseEntityToggleOptions<T>,
): (path: string, enabled: boolean) => Promise<void> {
  const { setItems, enabledField, apiCall, label, showToast } = options;

  return useCallback(
    async (path: string, enabled: boolean) => {
      const apply = (value: boolean) =>
        setItems((prev) =>
          prev.map((item) =>
            item.path === path ? { ...item, [enabledField]: value } : item,
          ),
        );

      // Optimistically update, then revert if the call fails.
      apply(enabled);
      try {
        await apiCall(path, enabled);
        showToast(
          `${label} ${enabled ? 'enabled' : 'disabled'} successfully!`,
          'success',
        );
      } catch (error: any) {
        console.error(`Failed to toggle ${label.toLowerCase()}:`, error);
        apply(!enabled);
        showToast(
          error.response?.data?.detail || `Failed to toggle ${label.toLowerCase()}`,
          'error',
        );
      }
    },
    [setItems, enabledField, apiCall, label, showToast],
  );
}
