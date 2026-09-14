import React from 'react';
import FormField from './FormField';
import { fieldClass, FIELD_FOCUS } from './formClasses';

export type AuthScheme = 'none' | 'bearer' | 'api_key' | 'oauth' | 'oauth2_1';

interface AuthSchemeFieldsProps {
  scheme: AuthScheme;
  credential: string;
  headerName: string;
  /** Called with the new scheme; the parent applies the reset cascade. */
  onSchemeChange: (scheme: AuthScheme) => void;
  onCredentialChange: (value: string) => void;
  onHeaderNameChange: (value: string) => void;
  /** When true, the credential placeholder reflects "keep existing" (edit mode). */
  editing?: boolean;
  accent?: keyof typeof FIELD_FOCUS;
  /**
   * True when this server uses On-Behalf-Of egress (egress_auth_mode ===
   * 'obo_exchange'). Backend discovery for such a server has no per-server
   * credential -- it is derived (a gateway machine token). When set and the
   * scheme is 'none', an informational panel explains the derived behavior and
   * the Entra prerequisite.
   */
  oboDiscoveryActive?: boolean;
  /** The obo target audience, shown in the derived-discovery panel. */
  oboTargetAudience?: string;
}

/**
 * The backend-authentication cascade (scheme select -> credential -> header
 * name) shared by the server form's "Backend Authentication" block. The
 * credential field shows for bearer/api_key; the header-name field shows only
 * for api_key. The parent owns the reset semantics (clearing the credential
 * when switching to none, etc.) via onSchemeChange.
 *
 * The skill form's auth has an extra 'global_credentials' option and inline
 * re-parse buttons, so it keeps its own richer controls.
 */
const AuthSchemeFields: React.FC<AuthSchemeFieldsProps> = ({
  scheme,
  credential,
  headerName,
  onSchemeChange,
  onCredentialChange,
  onHeaderNameChange,
  editing = false,
  accent = 'purple',
  oboDiscoveryActive = false,
  oboTargetAudience = '',
}) => {
  return (
    <div className="border-t border-gray-200 dark:border-gray-700 pt-4 mt-4">
      <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-1">
        Backend Authentication
      </h4>
      <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
        The credential the registry uses itself to reach this server for health
        checks and tool discovery. Per-user egress reuses this header definition.
      </p>

      <div className="space-y-4">
        <FormField label="Authentication Scheme">
          <select
            value={scheme}
            onChange={(e) => onSchemeChange(e.target.value as AuthScheme)}
            className={fieldClass(accent)}
          >
            <option value="none">None</option>
            <option value="bearer">Bearer Token</option>
            <option value="api_key">API Key</option>
            <option value="oauth">OAuth 2.0 (client credentials)</option>
            <option value="oauth2_1">OAuth 2.1 (delegated / discovery)</option>
          </select>
        </FormField>

        {(scheme === 'bearer' || scheme === 'api_key') && (
          <FormField
            label={scheme === 'bearer' ? 'Bearer Token' : 'API Key'}
            hint="Leave blank to keep the existing credential unchanged."
          >
            <input
              type="password"
              value={credential}
              onChange={(e) => onCredentialChange(e.target.value)}
              className={fieldClass(accent)}
              placeholder={
                editing ? 'Leave blank to keep current credential' : ''
              }
            />
          </FormField>
        )}

        {scheme === 'api_key' && (
          <FormField label="Header Name">
            <input
              type="text"
              value={headerName}
              onChange={(e) => onHeaderNameChange(e.target.value)}
              className={fieldClass(accent)}
              placeholder="X-API-Key"
            />
          </FormField>
        )}

        {oboDiscoveryActive && scheme === 'none' && (
          <div className="rounded-md border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20 p-3 text-xs text-blue-800 dark:text-blue-300">
            <p className="font-semibold mb-1">
              On-Behalf-Of server — discovery uses a gateway machine token
            </p>
            <p>
              Health checks and tool discovery authenticate as the gateway&apos;s
              own IdP app (client_credentials) audienced to{' '}
              <code className="font-mono break-all">
                {oboTargetAudience || 'this server\u2019s target audience'}
              </code>
              . No per-server credential is needed here.
            </p>
            <p className="mt-1">
              On Entra: grant the gateway app an application permission (app role)
              on the target server&apos;s app and admin-consent it; the internal
              server must accept app-only tokens for discovery. Selecting a scheme
              above overrides discovery with an explicit credential.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};

export default AuthSchemeFields;
