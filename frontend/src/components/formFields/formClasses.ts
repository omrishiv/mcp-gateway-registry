/**
 * Shared Tailwind class strings for form controls.
 *
 * These were redefined (with minor drift) in 8+ form components —
 * RegisterPage, the entity edit/register modals, CustomEntityForm,
 * VirtualServerForm, AddRegistryEntryModal, LocalRuntimeFormPanel, etc. This is
 * the single source of truth; forms import these instead of declaring their own.
 *
 * The default focus accent is purple (the registry's primary). Forms that need
 * a different accent (e.g. teal for virtual/custom) can compose FIELD_BASE with
 * an accent class, or pass a className override to FormField's input.
 */

/** Base input/select/textarea classes WITHOUT a focus accent. */
export const FIELD_BASE =
  'block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md ' +
  'bg-white dark:bg-gray-700 text-gray-900 dark:text-white';

/** Focus-ring accents, keyed by color, to append to FIELD_BASE. */
export const FIELD_FOCUS: Record<string, string> = {
  purple: 'focus:ring-purple-500 focus:border-purple-500',
  cyan: 'focus:ring-cyan-500 focus:border-cyan-500',
  amber: 'focus:ring-amber-500 focus:border-amber-500',
  teal: 'focus:ring-teal-500 focus:border-teal-500',
};

/** Default field classes (purple focus accent). */
export const FIELD = `${FIELD_BASE} ${FIELD_FOCUS.purple}`;

/** Standard field label. */
export const LABEL = 'block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1';

/** Inline validation-error text shown under a field. */
export const FIELD_ERROR = 'mt-1 text-sm text-red-600 dark:text-red-400';

/** Border applied to a field when it has a validation error. */
export const FIELD_ERROR_BORDER = 'border-red-500 dark:border-red-400';

/**
 * Build field classes for a given focus accent (defaults to purple), optionally
 * flagging an error state.
 */
export function fieldClass(
  accent: keyof typeof FIELD_FOCUS = 'purple',
  hasError = false,
): string {
  return [FIELD_BASE, FIELD_FOCUS[accent], hasError ? FIELD_ERROR_BORDER : '']
    .filter(Boolean)
    .join(' ');
}
