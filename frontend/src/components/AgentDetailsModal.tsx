import React from 'react';
import DetailsModal from './DetailsModal';
import ResourceBoundTokenButton from './ResourceBoundTokenButton';
import { CopyButton, FieldReferenceGrid, FieldRef } from './modals';

const CORE_FIELDS: FieldRef[] = [
  { name: 'protocol_version', description: 'A2A protocol version' },
  { name: 'name', description: 'Agent display name' },
  { name: 'description', description: 'Agent purpose' },
  { name: 'url', description: 'Agent endpoint URL' },
  { name: 'path', description: 'Registry path' },
];

const METADATA_FIELDS: FieldRef[] = [
  { name: 'skills', description: 'Agent capabilities' },
  { name: 'security_schemes', description: 'Auth methods' },
  { name: 'tags', description: 'Categorization' },
  { name: 'trust_level', description: 'Verification status' },
  { name: 'status', description: 'Lifecycle status' },
];

interface AgentLike {
  name: string;
  path: string;
  description?: string;
  version?: string;
  visibility?: string;
  trust_level?: string;
  enabled: boolean;
  tags?: string[];
}

interface AgentDetailsModalProps {
  agent: AgentLike & { [key: string]: any };
  isOpen: boolean;
  onClose: () => void;
  loading: boolean;
  fullDetails?: any;
  onCopy?: (data: any) => Promise<void> | void;
}

/**
 * AgentDetailsModal displays the complete agent JSON schema.
 *
 * Features:
 * - Uses shared DetailsModal component
 * - Copy to clipboard functionality
 * - Field reference documentation
 * - Loading states handled by parent DetailsModal
 */
const getAgentCardUrl = (agentUrl: string): string | null => {
  try {
    const origin = new URL(agentUrl).origin;
    return `${origin}/.well-known/agent-card.json`;
  } catch {
    return null;
  }
};

const AgentDetailsModal: React.FC<AgentDetailsModalProps> = ({
  agent,
  isOpen,
  onClose,
  loading,
  fullDetails,
  onCopy,
}) => {
  const dataToCopy = fullDetails || agent;

  return (
    <DetailsModal
      title={`${agent.name} - Full Details (JSON)`}
      isOpen={isOpen}
      onClose={onClose}
      loading={loading}
      maxWidth="4xl"
    >
      <div className="space-y-4">
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
          <h4 className="font-medium text-blue-900 dark:text-blue-100 mb-2">Complete Agent Schema</h4>
          <p className="text-sm text-blue-800 dark:text-blue-200">
            This is the complete A2A agent definition stored in the registry. It includes all metadata, skills,
            security schemes, and configuration details.
          </p>
        </div>

        {agent?.path && (
          <ResourceBoundTokenButton
            resourceType="agent"
            resourceId={agent.path}
            resourceName={agent.name}
          />
        )}

        {/* A2A Agent Card URL for A2A agents */}
        {fullDetails?.supported_protocol === 'a2a' && fullDetails?.url && (() => {
          const cardUrl = getAgentCardUrl(fullDetails.url);
          return cardUrl ? (
            <div className="bg-cyan-50 dark:bg-cyan-900/20 border border-cyan-200 dark:border-cyan-800 rounded-lg p-3 mt-2">
              <p className="text-sm text-cyan-800 dark:text-cyan-200">
                <span className="font-medium">A2A Agent Card:</span>{' '}
                <a
                  href={cardUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-600 dark:text-cyan-400 hover:underline break-all"
                >
                  {cardUrl}
                </a>
              </p>
            </div>
          ) : null;
        })()}

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <h4 className="font-medium text-gray-900 dark:text-white">Agent JSON Schema:</h4>
            <CopyButton
              getText={() => JSON.stringify(dataToCopy, null, 2)}
              onCopy={onCopy ? () => onCopy(dataToCopy) : undefined}
            />
          </div>

          <pre className="p-4 bg-gray-50 dark:bg-gray-900 border dark:border-gray-700 rounded-lg overflow-x-auto text-xs text-gray-900 dark:text-gray-100 max-h-[30vh] overflow-y-auto">
            {JSON.stringify(dataToCopy, null, 2)}
          </pre>
        </div>

        <FieldReferenceGrid
          columns={[
            { heading: 'Core Fields', fields: CORE_FIELDS },
            { heading: 'Metadata Fields', fields: METADATA_FIELDS },
          ]}
        />
      </div>
    </DetailsModal>
  );
};

export default AgentDetailsModal;
