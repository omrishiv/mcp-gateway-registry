import React from 'react';
import { render, screen } from '@testing-library/react';

import ServerCard, { Server } from '../ServerCard';

// react-markdown / remark-gfm are ESM-only; mock them (matches cardSnapshots.test).
jest.mock('react-markdown', () => {
  return { __esModule: true, default: ({ children }: { children?: React.ReactNode }) => <>{children}</> };
});
jest.mock('remark-gfm', () => ({ __esModule: true, default: () => {} }));

let authUser: Record<string, unknown> | null = null;
jest.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: authUser }),
}));

// Stub the heavy children so only the card's own header actions render.
jest.mock('axios');
jest.mock('../ServerConfigModal', () => () => null);
jest.mock('../SecurityScanModal', () => () => null);
// The version modal is stubbed, but its canModify prop is the gate for
// "Set as default" (PUT /versions/default), so capture it.
let mockVersionModalProps: Record<string, unknown> | null = null;
jest.mock('../VersionSelectorModal', () => (props: Record<string, unknown>) => {
  mockVersionModalProps = props;
  return null;
});
jest.mock('../ServerDetailsModal', () => () => null);
jest.mock('../StarRatingWidget', () => () => <div data-testid="stars" />);

const noop = () => {};

const baseServer = {
  name: 'Owned Server',
  path: '/owned-server',
  description: 'A server for edit-gate tests',
  proxy_pass_url: 'http://localhost:9000',
  enabled: true,
  tags: [],
  num_tools: 1,
  rating_details: [],
  registered_by: 'alice',
} as unknown as Server;

function renderCard(overrides: Partial<Server> = {}) {
  return render(
    <ServerCard
      server={{ ...baseServer, ...overrides } as Server}
      onToggle={noop}
      onEdit={noop}
      canModify
    />,
  );
}

/**
 * The pencil must mirror the backend guard on POST /api/edit/{path}: a
 * peer-synced row or another user's row always answers 403, so offering the
 * affordance is a dead end.
 */
describe('ServerCard edit affordance', () => {
  it('renders for the owner', () => {
    authUser = { username: 'alice', can_modify_servers: true };
    renderCard();
    expect(screen.getByTitle('Edit server')).toBeInTheDocument();
  });

  it('renders for an admin who does not own the server', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard();
    expect(screen.getByTitle('Edit server')).toBeInTheDocument();
  });

  it('is hidden for a non-owner without admin', () => {
    authUser = { username: 'bob', can_modify_servers: true };
    renderCard();
    expect(screen.queryByTitle('Edit server')).not.toBeInTheDocument();
  });

  it('is hidden when the stored owner is missing', () => {
    authUser = { username: 'alice', can_modify_servers: true };
    renderCard({ registered_by: null });
    expect(screen.queryByTitle('Edit server')).not.toBeInTheDocument();
  });

  it('is hidden for a federated server, even for an admin', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard({ sync_metadata: { is_federated: true, source_peer_id: 'peer-registry-lob1' } });
    expect(screen.queryByTitle('Edit server')).not.toBeInTheDocument();
  });

  it('is hidden for a read-only server, even for an admin', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard({ sync_metadata: { is_read_only: true } });
    expect(screen.queryByTitle('Edit server')).not.toBeInTheDocument();
  });
});

/**
 * The switch must mirror the backend guard on POST /api/toggle/{path}: a
 * peer-synced row's is_enabled is re-$set on every sync, so the route 403s
 * rather than let a local flip churn the nginx route and then revert. Toggling
 * needs no ownership, so a non-owner must keep the switch.
 */
describe('ServerCard toggle affordance', () => {
  const toggleLabel = { name: `Enable ${baseServer.name}` };

  it('renders for a caller who does not own the server', () => {
    authUser = { username: 'bob', can_modify_servers: true };
    renderCard();
    expect(screen.getByRole('checkbox', toggleLabel)).toBeInTheDocument();
  });

  it('renders for a local server with no stored owner', () => {
    authUser = { username: 'alice', can_modify_servers: true };
    renderCard({ registered_by: null });
    expect(screen.getByRole('checkbox', toggleLabel)).toBeInTheDocument();
  });

  it('is hidden for a federated server, even for an admin', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard({ sync_metadata: { is_federated: true, source_peer_id: 'peer-registry-lob1' } });
    expect(screen.queryByRole('checkbox', toggleLabel)).not.toBeInTheDocument();
  });

  it('is hidden for a read-only server, even for an admin', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard({ sync_metadata: { is_read_only: true } });
    expect(screen.queryByRole('checkbox', toggleLabel)).not.toBeInTheDocument();
  });

  it('renders for a synced row an operator has detached', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard({
      sync_metadata: {
        is_federated: true,
        source_peer_id: 'peer-registry-lob1',
        local_overrides: { tags: ['local'] },
      },
    });
    expect(screen.getByRole('checkbox', toggleLabel)).toBeInTheDocument();
  });

  it('is hidden when there is no authenticated user', () => {
    authUser = null;
    renderCard();
    expect(screen.queryByRole('checkbox', toggleLabel)).not.toBeInTheDocument();
  });
});

/**
 * "Set as default" issues PUT /api/servers/{path}/versions/default, which runs
 * the full mutation gate (federation reject, then owner-or-admin) — the same
 * rule as the pencil. The card must hand the version modal that verdict, not
 * the bare can_modify_servers capability.
 */
describe('ServerCard set-default-version affordance', () => {
  it('is offered to the owner of a local server', () => {
    authUser = { username: 'alice', can_modify_servers: true };
    renderCard();
    expect(mockVersionModalProps?.canModify).toBe(true);
  });

  it('is withheld for a federated server, even for an admin', () => {
    authUser = { username: 'root', can_modify_servers: true, is_admin: true };
    renderCard({ sync_metadata: { is_federated: true, source_peer_id: 'peer-registry-lob1' } });
    expect(mockVersionModalProps?.canModify).toBe(false);
  });

  it('is withheld from a non-owner without admin', () => {
    authUser = { username: 'bob', can_modify_servers: true };
    renderCard();
    expect(mockVersionModalProps?.canModify).toBe(false);
  });
});
