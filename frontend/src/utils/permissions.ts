/**
 * Access control utilities mirroring backend authorization checks.
 *
 * All Settings categories (Audit, Federation, IAM) require admin access.
 * The backend enforces this on every endpoint. The frontend mirrors it
 * as a UX convenience layer.
 *
 * The ui_permissions from scopes.yml control server/agent access
 * (e.g., list_service, toggle_service, list_agents, publish_agent)
 */

interface SettingsUser {
  is_admin?: boolean;
}

/**
 * Check if a user can access the Settings page.
 * Returns true only when is_admin === true.
 */
export function canAccessSettings(user: SettingsUser | null): boolean {
  if (!user) return false;
  return user.is_admin === true;
}


/**
 * Federation sync markers the server mutation gates read. Declared structurally
 * (like SettingsUser above) so this module stays dependency-free — every
 * SyncMetadata / Server interface in the app satisfies it by shape.
 *
 * local_overrides is stored either as a bool (POST /api/peers/local-override)
 * or as a dict of the locally customized fields.
 */
interface SyncGateSyncMetadata {
  is_federated?: boolean;
  is_read_only?: boolean;
  local_overrides?: boolean | Record<string, unknown>;
}

interface SyncGateServer {
  sync_metadata?: SyncGateSyncMetadata;
  registered_by?: string | null;
}

/**
 * Whether an operator has detached a synced row so local edits stick.
 *
 * Mirrors Python truthiness, which the backend guard relies on: an EMPTY
 * override dict still means "attached", while in JS `{}` is truthy.
 */
function _isLocallyDetached(
  overrides: boolean | Record<string, unknown> | undefined,
): boolean {
  if (!overrides) return false;
  if (typeof overrides === 'boolean') return overrides;
  return Object.keys(overrides).length > 0;
}

/**
 * Whether the record is owned by a peer registry, i.e. every local write to it
 * is refused. Frontend twin of the backend's peer_owned_source(): a synced row
 * is re-$set field by field on every sync cycle, so a local write is silently
 * reverted — the routes answer 403 instead, regardless of who asks, admins
 * included. Detaching the row (local_overrides) makes local writes durable and
 * therefore lifts the block.
 */
function _isPeerOwned(server: SyncGateServer): boolean {
  if (_isLocallyDetached(server.sync_metadata?.local_overrides)) return false;
  return (
    server.sync_metadata?.is_federated === true ||
    server.sync_metadata?.is_read_only === true
  );
}

/**
 * Caller identity for the server mutation gates. Every field is optional so a
 * partially populated /auth/me payload fails closed rather than throwing.
 */
interface ServerMutationUser {
  username?: string;
  is_admin?: boolean;
  can_modify_servers?: boolean;
}

/**
 * Check if a user may edit a registry server.
 *
 * Mirrors the backend guard on POST /api/edit/{path} and
 * PUT|PATCH /api/servers/{path}, which answers 403 when the row is synced
 * from a peer registry or when a non-admin caller does not own it. Without
 * this the UI renders a pencil that always 403s.
 *
 * Fails closed: missing server, missing user, or a blank stored owner denies
 * a non-admin. registered_by is a LOCAL authorization key, so an empty value
 * must never match an empty username.
 */
export function canEditServer(
  server: SyncGateServer | null | undefined,
  user: ServerMutationUser | null | undefined,
): boolean {
  if (!server || !user) return false;
  if (!user.can_modify_servers && !user.is_admin) return false;
  // Peer-synced rows belong to the source registry: the local registry refuses
  // the write regardless of who asks, admins included.
  if (_isPeerOwned(server)) return false;
  if (user.is_admin === true) return true;
  const owner = server.registered_by;
  return !!owner && !!user.username && owner === user.username;
}

/**
 * Check if a user may enable/disable a registry server.
 *
 * Mirrors the backend guard on POST /api/toggle/{path} and
 * POST /api/servers/toggle, which reject a peer-synced row: its is_enabled is
 * re-$set on every sync, so a local flip is silently reverted while it tears
 * down (or stands up) the nginx route in the meantime. Without this the UI
 * renders a switch that always 403s.
 *
 * Deliberately NOT an ownership check, unlike canEditServer: the backend gates
 * toggling on the toggle_service permission only, which the caller resolves
 * per server (hasUiPermission) and passes as its own capability flag. `user` is
 * consulted only so an unknown identity fails closed, like every gate here.
 */
export function canToggleServer(
  server: SyncGateServer | null | undefined,
  user: ServerMutationUser | null | undefined,
): boolean {
  if (!server || !user) return false;
  return !_isPeerOwned(server);
}
