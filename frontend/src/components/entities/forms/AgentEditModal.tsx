import React from 'react';

/**
 * Shape of the agent edit form state, owned by the Dashboard. This modal is a
 * controlled, presentational view over it.
 */
export interface AgentEditForm {
  name: string;
  path: string;
  url: string;
  description: string;
  version: string;
  visibility: 'public' | 'private' | 'group-restricted';
  allowed_groups: string;
  trust_level: 'community' | 'verified' | 'trusted' | 'unverified';
  supported_protocol: 'a2a' | 'other';
  tags: string[];
  skillsJson: string;
  metadata: string;
  status: 'active' | 'draft' | 'deprecated' | 'beta';
}

interface AgentEditModalProps {
  agentName: string;
  form: AgentEditForm;
  setForm: React.Dispatch<React.SetStateAction<AgentEditForm>>;
  loading: boolean;
  /** Validation message for the skills JSON textarea (null when valid). */
  skillsJsonError: string | null;
  /** Clears the skills JSON error (called as the field is edited). */
  onSkillsJsonChange: () => void;
  onSave: () => Promise<void> | void;
  onClose: () => void;
}

const FIELD =
  'block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-cyan-500 focus:border-cyan-500';
const LABEL = 'block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1';

/**
 * Edit form for an A2A agent. Controlled by the Dashboard's editAgentForm state.
 * Agents are created via AgentCore import, so there is no create mode here.
 */
const AgentEditModal: React.FC<AgentEditModalProps> = ({
  agentName,
  form,
  setForm,
  loading,
  skillsJsonError,
  onSkillsJsonChange,
  onSave,
  onClose,
}) => {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Edit Agent: {agentName}
        </h3>

        <form
          onSubmit={async (e) => {
            e.preventDefault();
            await onSave();
          }}
          className="space-y-4"
        >
          <div>
            <label className={LABEL}>Agent Name *</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((prev) => ({ ...prev, name: e.target.value }))}
              className={FIELD}
              required
            />
          </div>

          <div>
            <label className={LABEL}>Description</label>
            <textarea
              value={form.description}
              onChange={(e) => setForm((prev) => ({ ...prev, description: e.target.value }))}
              className={FIELD}
              rows={3}
              placeholder="Brief description of the agent"
            />
          </div>

          <div>
            <label className={LABEL}>Lifecycle Status</label>
            <select
              value={form.status}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  status: e.target.value as 'active' | 'draft' | 'deprecated' | 'beta',
                }))
              }
              className={FIELD}
            >
              <option value="active">Active</option>
              <option value="draft">Draft</option>
              <option value="beta">Beta</option>
              <option value="deprecated">Deprecated</option>
            </select>
          </div>

          <div>
            <label className={LABEL}>Version</label>
            <input
              type="text"
              value={form.version}
              onChange={(e) => setForm((prev) => ({ ...prev, version: e.target.value }))}
              className={FIELD}
              placeholder="1.0.0"
            />
          </div>

          <div>
            <label className={LABEL}>Visibility</label>
            <select
              value={form.visibility}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  visibility: e.target.value as 'public' | 'private' | 'group-restricted',
                }))
              }
              className={FIELD}
            >
              <option value="private">Private</option>
              <option value="public">Public</option>
              <option value="group-restricted">Group Restricted</option>
            </select>
          </div>

          {form.visibility === 'group-restricted' && (
            <div>
              <label className={LABEL}>Allowed Groups</label>
              <input
                type="text"
                value={form.allowed_groups}
                onChange={(e) => setForm((prev) => ({ ...prev, allowed_groups: e.target.value }))}
                className={FIELD}
                placeholder="e.g. finance-team, engineering"
              />
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Comma-separated list of groups that can access this agent
              </p>
              {form.allowed_groups.trim() === '' && (
                <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">
                  At least one group is required for group-restricted visibility
                </p>
              )}
            </div>
          )}

          <div>
            <label className={LABEL}>Trust Level</label>
            <select
              value={form.trust_level}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  trust_level: e.target.value as
                    | 'community'
                    | 'verified'
                    | 'trusted'
                    | 'unverified',
                }))
              }
              className={FIELD}
            >
              <option value="unverified">Unverified</option>
              <option value="community">Community</option>
              <option value="verified">Verified</option>
              <option value="trusted">Trusted</option>
            </select>
          </div>

          <div>
            <label className={LABEL}>Supported Protocol</label>
            <select
              value={form.supported_protocol}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  supported_protocol: e.target.value as 'a2a' | 'other',
                }))
              }
              className={FIELD}
            >
              <option value="a2a">A2A</option>
              <option value="other">Other</option>
            </select>
          </div>

          <div>
            <label className={LABEL}>Tags</label>
            <input
              type="text"
              value={form.tags.join(',')}
              onChange={(e) =>
                setForm((prev) => ({
                  ...prev,
                  tags: e.target.value.split(',').map((t) => t.trim()).filter((t) => t),
                }))
              }
              className={FIELD}
              placeholder="tag1,tag2,tag3"
            />
          </div>

          <div>
            <label className={LABEL}>Custom Metadata (JSON, optional)</label>
            <textarea
              value={form.metadata}
              onChange={(e) => setForm((prev) => ({ ...prev, metadata: e.target.value }))}
              rows={4}
              className={`${FIELD} font-mono text-sm`}
              placeholder='{"team": "platform", "owner": "alice@example.com", "cost_center": "CC-1001"}'
            />
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              Custom key-value pairs for organization, compliance, or integration purposes
            </p>
          </div>

          <div>
            <label className={LABEL}>Skills (JSON array)</label>
            <textarea
              value={form.skillsJson}
              onChange={(e) => {
                setForm((prev) => ({ ...prev, skillsJson: e.target.value }));
                onSkillsJsonChange();
              }}
              className={`block w-full px-3 py-2 border rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-xs focus:ring-cyan-500 focus:border-cyan-500 ${
                skillsJsonError
                  ? 'border-red-500 dark:border-red-400'
                  : 'border-gray-300 dark:border-gray-600'
              }`}
              rows={8}
              placeholder='[{"id": "skill-1", "name": "My Skill", "description": "What this skill does"}]'
            />
            {skillsJsonError && (
              <p className="mt-1 text-xs text-red-600 dark:text-red-400">{skillsJsonError}</p>
            )}
            <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
              Each skill needs at least: id, name, description. Saving triggers a security rescan.
            </p>
          </div>

          <div>
            <label className={LABEL}>Path (read-only)</label>
            <input
              type="text"
              value={form.path}
              className="block w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-300"
              disabled
            />
          </div>

          <div className="flex space-x-3 pt-4">
            <button
              type="submit"
              disabled={loading}
              className="flex-1 px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 rounded-md transition-colors"
            >
              {loading ? 'Saving...' : 'Save Changes'}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded-md transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AgentEditModal;
