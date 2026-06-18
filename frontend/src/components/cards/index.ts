/**
 * Composable, presentational card primitives shared by every entity card
 * (servers, agents, skills, virtual servers, custom resources).
 *
 * These hold no entity knowledge — each card composes them and supplies its
 * own badges, stats, actions, and behavior. Colors live in CardShell's accent
 * map and the per-primitive Tailwind classes so the upcoming theming work can
 * route them through CSS variables in one place.
 */
export { default as CardShell } from './CardShell';
export type { CardAccent } from './CardShell';
export { default as CardHeader } from './CardHeader';
export { default as CardBody } from './CardBody';
export { default as CardStatsRow } from './CardStatsRow';
export { default as CardFooter } from './CardFooter';
export { default as StatusDot, StatusDivider } from './StatusDot';
export type { StatusTone } from './StatusDot';
export { default as TagList } from './TagList';
export { default as ToggleSwitch } from './ToggleSwitch';
export { default as InlineDeleteConfirm } from './InlineDeleteConfirm';
