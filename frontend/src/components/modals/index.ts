/**
 * Composable modal primitives shared by every entity detail modal.
 *
 * EntityModal is the shell (backdrop, escape, loading/error, header-actions
 * slot, padded/flush layouts). CopyButton, CollapsibleSection, and
 * FieldReferenceGrid are the reusable pieces the detail modals compose.
 */
export { default as EntityModal } from './EntityModal';
export type { ModalMaxWidth } from './EntityModal';
export { default as CopyButton } from './CopyButton';
export { default as CollapsibleSection } from './CollapsibleSection';
export { default as FieldReferenceGrid } from './FieldReferenceGrid';
export type { FieldRef } from './FieldReferenceGrid';
