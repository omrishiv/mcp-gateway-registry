import React, { useCallback, useEffect, useState } from 'react';
import {
  LinkIcon,
  TrashIcon,
  ExclamationTriangleIcon,
  ArrowTopRightOnSquareIcon,
} from '@heroicons/react/24/outline';

import {
  listConnections,
  initiateConsent,
  disconnect,
  type EgressConnection,
} from '../utils/egressAuth';

/**
 * Connected Accounts: the end-user surface for the per-user egress credential
 * vault. Lists linked third-party accounts and lets the user connect a new one
 * (opens the provider consent in a new tab) or disconnect. Discoverable BEFORE
 * the first-use tool-call error so users can self-serve.
 */
const ConnectedAccountsPage: React.FC = () => {
  const [connections, setConnections] = useState<EgressConnection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [serverPath, setServerPath] = useState('');
  const [connecting, setConnecting] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setConnections(await listConnections());
    } catch {
      setError('Could not load connections.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    const path = serverPath.trim();
    if (!path) return;
    setConnecting(true);
    setError('');
    try {
      const authorizeUrl = await initiateConsent(path);
      // Open the provider consent in a new tab; the callback stores the token.
      window.open(authorizeUrl, '_blank', 'noopener,noreferrer');
    } catch {
      setError(`Could not start a connection for "${path}". Check the server path.`);
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async (conn: EgressConnection) => {
    setError('');
    try {
      await disconnect(conn.provider, conn.server_path);
      await refresh();
    } catch {
      setError(`Could not disconnect ${conn.provider} for ${conn.server_path}.`);
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-6">
      <div className="flex items-center space-x-3 mb-2">
        <LinkIcon className="h-6 w-6 text-purple-600 dark:text-purple-400" />
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Connected Accounts</h1>
      </div>
      <p className="text-sm text-gray-600 dark:text-gray-300 mb-6">
        Link your third-party accounts (GitHub, Slack, Google, …) so MCP servers can act on your
        behalf. Connect an account here before using a server that requires it.
      </p>

      {error && (
        <div className="flex items-center space-x-2 mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300">
          <ExclamationTriangleIcon className="h-5 w-5 flex-shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Connect a new account */}
      <form
        onSubmit={handleConnect}
        className="flex items-end gap-3 mb-8 p-4 rounded-lg bg-gray-50 dark:bg-gray-800"
      >
        <div className="flex-1">
          <label
            htmlFor="server-path"
            className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
          >
            Server path
          </label>
          <input
            id="server-path"
            type="text"
            value={serverPath}
            onChange={e => setServerPath(e.target.value)}
            placeholder="/github-mcp"
            className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-purple-500"
          />
        </div>
        <button
          type="submit"
          disabled={connecting || !serverPath.trim()}
          className="flex items-center space-x-2 px-4 py-2 rounded-md bg-purple-600 text-white text-sm font-medium hover:bg-purple-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-purple-500"
        >
          <ArrowTopRightOnSquareIcon className="h-4 w-4" />
          <span>{connecting ? 'Opening…' : 'Connect'}</span>
        </button>
      </form>

      {/* Existing connections */}
      {loading ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">Loading…</p>
      ) : connections.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">No connected accounts yet.</p>
      ) : (
        <ul className="divide-y divide-gray-200 dark:divide-gray-700 rounded-lg border border-gray-200 dark:border-gray-700">
          {connections.map(conn => (
            <li
              key={`${conn.provider}:${conn.server_path}`}
              className="flex items-center justify-between p-4"
            >
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-medium text-gray-900 dark:text-white capitalize">
                    {conn.provider}
                  </span>
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    {conn.server_path}
                  </span>
                  {conn.status !== 'active' && (
                    <span className="text-xs px-2 py-0.5 rounded-full bg-yellow-100 dark:bg-yellow-900/40 text-yellow-800 dark:text-yellow-300">
                      {conn.status}
                    </span>
                  )}
                </div>
                {conn.scopes.length > 0 && (
                  <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                    {conn.scopes.join(', ')}
                  </div>
                )}
              </div>
              <button
                onClick={() => handleDisconnect(conn)}
                className="flex items-center space-x-1 px-3 py-1.5 rounded-md text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 focus:outline-none focus:ring-2 focus:ring-red-500"
                aria-label={`Disconnect ${conn.provider} for ${conn.server_path}`}
              >
                <TrashIcon className="h-4 w-4" />
                <span>Disconnect</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
};

export default ConnectedAccountsPage;
