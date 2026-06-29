/**
 * Shared building blocks for the Dashboard's entity collections (servers,
 * agents, skills, virtual servers, custom resources). These replace the
 * grid/empty-state markup that was repeated across the per-entity render
 * blocks in Dashboard.tsx.
 */
export { default as EntityGrid } from './EntityGrid';
export { default as EmptyState } from './EmptyState';
export type { EmptyStateTone } from './EmptyState';
