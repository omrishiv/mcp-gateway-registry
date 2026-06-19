import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';

import ConnectedAccountsPage from '../ConnectedAccountsPage';
import * as egressAuth from '../../utils/egressAuth';

jest.mock('../../utils/egressAuth');
const mocked = egressAuth as jest.Mocked<typeof egressAuth>;

describe('ConnectedAccountsPage', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('lists existing connections', async () => {
    mocked.listConnections.mockResolvedValue([
      {
        provider: 'github',
        server_path: '/github-mcp',
        scopes: ['repo'],
        expires_at: null,
        status: 'active',
        last_refreshed_at: null,
      },
    ]);

    render(<ConnectedAccountsPage />);

    expect(await screen.findByText('github')).toBeInTheDocument();
    expect(screen.getByText('/github-mcp')).toBeInTheDocument();
    expect(screen.getByText('repo')).toBeInTheDocument();
  });

  it('shows empty state when no connections', async () => {
    mocked.listConnections.mockResolvedValue([]);
    render(<ConnectedAccountsPage />);
    expect(await screen.findByText('No connected accounts yet.')).toBeInTheDocument();
  });

  it('opens the authorize URL on Connect', async () => {
    mocked.listConnections.mockResolvedValue([]);
    mocked.initiateConsent.mockResolvedValue('https://github.com/login/oauth/authorize?x=1');
    const openSpy = jest.spyOn(window, 'open').mockImplementation(() => null);

    render(<ConnectedAccountsPage />);
    await screen.findByText('No connected accounts yet.');

    fireEvent.change(screen.getByLabelText('Server path'), {
      target: { value: '/github-mcp' },
    });
    fireEvent.click(screen.getByRole('button', { name: /connect/i }));

    await waitFor(() => expect(mocked.initiateConsent).toHaveBeenCalledWith('/github-mcp'));
    expect(openSpy).toHaveBeenCalledWith(
      'https://github.com/login/oauth/authorize?x=1',
      '_blank',
      'noopener,noreferrer'
    );
    openSpy.mockRestore();
  });

  it('disconnects and refreshes', async () => {
    mocked.listConnections
      .mockResolvedValueOnce([
        {
          provider: 'github',
          server_path: '/github-mcp',
          scopes: [],
          expires_at: null,
          status: 'active',
          last_refreshed_at: null,
        },
      ])
      .mockResolvedValueOnce([]);
    mocked.disconnect.mockResolvedValue();

    render(<ConnectedAccountsPage />);
    fireEvent.click(await screen.findByRole('button', { name: /disconnect github/i }));

    await waitFor(() =>
      expect(mocked.disconnect).toHaveBeenCalledWith('github', '/github-mcp')
    );
    expect(await screen.findByText('No connected accounts yet.')).toBeInTheDocument();
  });

  it('surfaces a load error', async () => {
    mocked.listConnections.mockRejectedValue(new Error('boom'));
    render(<ConnectedAccountsPage />);
    expect(await screen.findByText('Could not load connections.')).toBeInTheDocument();
  });
});
