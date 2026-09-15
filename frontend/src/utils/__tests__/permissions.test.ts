import { canEditServer, canToggleServer } from '../permissions';

/**
 * canEditServer mirrors the backend guard on POST /api/edit/{path} and
 * PUT|PATCH /api/servers/{path}. These cases pin the fail-closed behavior:
 * a peer-synced row is never editable locally, and a non-admin may only edit
 * a row whose stored registered_by is non-empty and matches their username.
 */
describe('canEditServer', () => {
  const owner = { username: 'alice', can_modify_servers: true };
  const admin = { username: 'root', can_modify_servers: true, is_admin: true };
  const ownedServer = { registered_by: 'alice' };

  it('allows the owner of a local server', () => {
    expect(canEditServer(ownedServer, owner)).toBe(true);
  });

  it('allows an admin who does not own the server', () => {
    expect(canEditServer(ownedServer, admin)).toBe(true);
  });

  it('denies a non-admin who does not own the server', () => {
    expect(canEditServer({ registered_by: 'bob' }, owner)).toBe(false);
  });

  it('denies a non-admin when registered_by is missing or blank', () => {
    expect(canEditServer({}, owner)).toBe(false);
    expect(canEditServer({ registered_by: null }, owner)).toBe(false);
    expect(canEditServer({ registered_by: '' }, owner)).toBe(false);
  });

  it('denies a non-admin whose own username is blank', () => {
    expect(canEditServer({ registered_by: '' }, { username: '', can_modify_servers: true })).toBe(false);
  });

  it('denies a federated server for every caller, admin included', () => {
    const federated = { registered_by: 'alice', sync_metadata: { is_federated: true } };
    expect(canEditServer(federated, owner)).toBe(false);
    expect(canEditServer(federated, admin)).toBe(false);
  });

  it('denies a read-only server for every caller, admin included', () => {
    const readOnly = { registered_by: 'alice', sync_metadata: { is_read_only: true } };
    expect(canEditServer(readOnly, owner)).toBe(false);
    expect(canEditServer(readOnly, admin)).toBe(false);
  });

  it('allows a server whose sync metadata carries no peer markers', () => {
    expect(
      canEditServer({ registered_by: 'alice', sync_metadata: {} }, owner),
    ).toBe(true);
  });

  it('allows an admin to edit a synced row an operator has detached', () => {
    // The backend skips overridden rows during sync, so local edits are durable
    // and _synced_source_peer() returns None for them.
    expect(
      canEditServer(
        { registered_by: '', sync_metadata: { is_federated: true, local_overrides: true } },
        admin,
      ),
    ).toBe(true);
    expect(
      canEditServer(
        { registered_by: '', sync_metadata: { is_read_only: true, local_overrides: { tags: ['local'] } } },
        admin,
      ),
    ).toBe(true);
  });

  it('still denies a synced row whose override marker is empty', () => {
    // An empty dict is falsy in Python, so the backend treats it as attached;
    // in JS `{}` is truthy and must not be mistaken for a detached row.
    expect(
      canEditServer(
        { registered_by: 'alice', sync_metadata: { is_federated: true, local_overrides: {} } },
        admin,
      ),
    ).toBe(false);
    expect(
      canEditServer(
        { registered_by: 'alice', sync_metadata: { is_federated: true, local_overrides: false } },
        admin,
      ),
    ).toBe(false);
  });

  it('denies a user without the can_modify_servers capability', () => {
    expect(canEditServer(ownedServer, { username: 'alice' })).toBe(false);
    expect(canEditServer(ownedServer, { username: 'alice', can_modify_servers: false })).toBe(false);
  });

  it('denies when the server or the user is missing', () => {
    expect(canEditServer(null, owner)).toBe(false);
    expect(canEditServer(undefined, owner)).toBe(false);
    expect(canEditServer(ownedServer, null)).toBe(false);
    expect(canEditServer(ownedServer, undefined)).toBe(false);
  });
});

/**
 * canToggleServer mirrors the backend guard on POST /api/toggle/{path} and
 * POST /api/servers/toggle. Those reject a peer-synced row -- its is_enabled is
 * re-$set on every sync, so a local flip is reverted after it has already torn
 * down the nginx route. Unlike editing, toggling carries NO ownership
 * requirement: toggle_service alone authorizes it, and the caller resolves that
 * permission per server, so these cases must not depend on registered_by.
 */
describe('canToggleServer', () => {
  const nonOwner = { username: 'bob' };
  const admin = { username: 'root', is_admin: true };

  it('allows any caller for a local server, owner or not', () => {
    expect(canToggleServer({ registered_by: 'alice' }, nonOwner)).toBe(true);
    expect(canToggleServer({ registered_by: 'alice' }, admin)).toBe(true);
  });

  it('allows a local server with no stored owner', () => {
    // Ownership is irrelevant here, so a blank registered_by must not deny --
    // that is the one place this gate differs from canEditServer.
    expect(canToggleServer({}, nonOwner)).toBe(true);
    expect(canToggleServer({ registered_by: '' }, nonOwner)).toBe(true);
  });

  it('denies a federated server for every caller, admin included', () => {
    const federated = { registered_by: 'alice', sync_metadata: { is_federated: true } };
    expect(canToggleServer(federated, nonOwner)).toBe(false);
    expect(canToggleServer(federated, admin)).toBe(false);
  });

  it('denies a read-only server for every caller, admin included', () => {
    const readOnly = { registered_by: 'alice', sync_metadata: { is_read_only: true } };
    expect(canToggleServer(readOnly, nonOwner)).toBe(false);
    expect(canToggleServer(readOnly, admin)).toBe(false);
  });

  it('allows a server whose sync metadata carries no peer markers', () => {
    expect(canToggleServer({ registered_by: 'alice', sync_metadata: {} }, nonOwner)).toBe(true);
  });

  it('allows a synced row an operator has detached', () => {
    expect(
      canToggleServer(
        { sync_metadata: { is_federated: true, local_overrides: true } },
        nonOwner,
      ),
    ).toBe(true);
    expect(
      canToggleServer(
        { sync_metadata: { is_read_only: true, local_overrides: { tags: ['local'] } } },
        nonOwner,
      ),
    ).toBe(true);
  });

  it('still denies a synced row whose override marker is empty', () => {
    // Python truthiness: an empty dict means "attached", though `{}` is truthy
    // in JS. Same trap the edit gate guards against.
    expect(
      canToggleServer({ sync_metadata: { is_federated: true, local_overrides: {} } }, admin),
    ).toBe(false);
    expect(
      canToggleServer({ sync_metadata: { is_federated: true, local_overrides: false } }, admin),
    ).toBe(false);
  });

  it('denies when the server or the user is missing', () => {
    expect(canToggleServer(null, nonOwner)).toBe(false);
    expect(canToggleServer(undefined, nonOwner)).toBe(false);
    expect(canToggleServer({ registered_by: 'alice' }, null)).toBe(false);
    expect(canToggleServer({ registered_by: 'alice' }, undefined)).toBe(false);
  });
});
