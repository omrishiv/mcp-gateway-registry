import React, { useState, useCallback } from 'react';
import axios from 'axios';
import {
  PencilIcon,
  TrashIcon,
  LinkIcon,
  WrenchScrewdriverIcon,
  XMarkIcon,
  ChevronDownIcon,
  ChevronRightIcon,
} from '@heroicons/react/24/outline';
import { VirtualServerInfo, ResolvedTool } from '../types/virtualServer';
import ServerConfigModal from './ServerConfigModal';
import StarRatingWidget from './StarRatingWidget';
import useEscapeKey from '../hooks/useEscapeKey';
import {
  CardShell,
  CardHeader,
  CardBody,
  CardStatsRow,
  CardFooter,
  StatusDot,
  TagList,
  ToggleSwitch,
  ACCENTS,
  ENTITY_ACCENTS,
} from './cards';
import Badge from './Badge';


/**
 * Props for the VirtualServerCard component.
 */
interface VirtualServerCardProps {
  virtualServer: VirtualServerInfo;
  canModify: boolean;
  onToggle: (path: string, enabled: boolean) => void;
  onEdit: (server: VirtualServerInfo) => void;
  onDelete: (path: string) => void;
  onShowToast?: (message: string, type: 'success' | 'error' | 'info') => void;
  onServerUpdate?: (path: string, updates: Partial<VirtualServerInfo>) => void;
  authToken?: string | null;
}


const ACCENT = ENTITY_ACCENTS.virtualServer;


/**
 * VirtualServerCard renders a dashboard card for a virtual MCP server.
 *
 * Composes the shared card primitives (CardShell/Header/Body/Stats/Footer) and
 * uses the teal accent so every shared feature — container, footer, divider,
 * toggle, tags — follows the same rule as the other entity cards. The tools
 * modal (backend-grouped, collapsible) is the entity-specific behavior kept
 * inline here.
 */
const VirtualServerCard: React.FC<VirtualServerCardProps> = ({
  virtualServer: server,
  canModify,
  onToggle,
  onEdit,
  onDelete,
  onShowToast,
  onServerUpdate,
  authToken,
}) => {
  const [showTools, setShowTools] = useState(false);
  const [tools, setTools] = useState<ResolvedTool[]>([]);
  const [loadingTools, setLoadingTools] = useState(false);
  const [expandedBackends, setExpandedBackends] = useState<Record<string, boolean>>({});
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});
  const [showConfig, setShowConfig] = useState(false);

  useEscapeKey(() => setShowTools(false), showTools);

  const handleViewTools = useCallback(async () => {
    if (loadingTools) return;

    setShowTools(true);
    setLoadingTools(true);

    try {
      // Fetch resolved tools with full details (description, schema)
      const response = await axios.get<{ tools: ResolvedTool[] }>(
        `/api/virtual-servers${server.path}/tools`
      );
      const resolvedTools = response.data.tools || [];
      setTools(resolvedTools);

      // Group tools by backend to determine collapse state
      const toolsByBackend: Record<string, ResolvedTool[]> = {};
      for (const tool of resolvedTools) {
        const backend = tool.backend_server_path;
        if (!toolsByBackend[backend]) {
          toolsByBackend[backend] = [];
        }
        toolsByBackend[backend].push(tool);
      }

      // Auto-expand first backend, collapse tools if more than 3 in any backend
      const backends = Object.keys(toolsByBackend);
      if (backends.length > 0) {
        setExpandedBackends({ [backends[0]]: true });
      }

      // If any backend has more than 3 tools, collapse all tools by default
      // Otherwise expand all tools
      const hasLargeBackend = Object.values(toolsByBackend).some(t => t.length > 3);
      if (!hasLargeBackend) {
        // Expand all tools if small number of tools
        const allToolsExpanded: Record<string, boolean> = {};
        for (const tool of resolvedTools) {
          allToolsExpanded[tool.name] = true;
        }
        setExpandedTools(allToolsExpanded);
      } else {
        setExpandedTools({});
      }
    } catch (error) {
      console.error('Failed to fetch tools:', error);
      onShowToast?.('Failed to load tools', 'error');
      setTools([]);
    } finally {
      setLoadingTools(false);
    }
  }, [server.path, loadingTools, onShowToast]);

  const toggleBackend = (backend: string) => {
    setExpandedBackends(prev => ({
      ...prev,
      [backend]: !prev[backend]
    }));
  };

  const toggleTool = (toolName: string) => {
    setExpandedTools(prev => ({
      ...prev,
      [toolName]: !prev[toolName]
    }));
  };

  // Group tools by backend server
  const toolsByBackend = tools.reduce<Record<string, ResolvedTool[]>>((acc, tool) => {
    const backend = tool.backend_server_path;
    if (!acc[backend]) {
      acc[backend] = [];
    }
    acc[backend].push(tool);
    return acc;
  }, {});

  const backendPaths = Object.keys(toolsByBackend);

  // Create a Server-like object for ServerConfigModal
  const serverForConfig = {
    name: server.server_name,
    path: server.path,
    description: server.description,
    enabled: server.is_enabled,
    tags: server.tags,
  };

  return (
    <>
      <CardShell accent={ACCENT}>
        <CardHeader
          title={server.server_name}
          path={server.path}
          badges={
            <Badge tone="teal" bordered>
              VIRTUAL
            </Badge>
          }
          actions={
            <>
              {canModify && (
                <button
                  className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-all duration-200"
                  onClick={() => onEdit(server)}
                  title="Edit virtual server"
                >
                  <PencilIcon className="h-4 w-4" />
                </button>
              )}

              {/* Connect Button */}
              <button
                onClick={() => setShowConfig(true)}
                className="flex items-center gap-1 px-2 py-1.5 text-xs font-medium text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-700/50 rounded-lg transition-all duration-200 flex-shrink-0 border border-green-200 dark:border-green-700"
                title="Get connection details and mcp.json configuration"
                aria-label={`Connect to ${server.server_name}`}
              >
                <LinkIcon className="h-3.5 w-3.5" />
                Connect
              </button>

              {canModify && (
                <button
                  onClick={() => onDelete(server.path)}
                  className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-700/50 rounded-lg transition-all duration-200"
                  title="Delete virtual server"
                >
                  <TrashIcon className="h-4 w-4" />
                </button>
              )}
            </>
          }
        />

        <CardBody description={server.description}>
          <TagList tags={server.tags || []} accent={ACCENT} prefix="#" />
        </CardBody>

        {/* Stats - 2-column layout */}
        <CardStatsRow columns={2}>
          <StarRatingWidget
            resourceType="virtual-servers"
            path={server.path}
            initialRating={server.num_stars || 0}
            initialCount={server.rating_details?.length || 0}
            ratingDetails={server.rating_details}
            authToken={authToken}
            onShowToast={onShowToast}
            onRatingUpdate={(newRating) => {
              onServerUpdate?.(server.path, { num_stars: newRating });
            }}
          />

          {/* Tools - clickable */}
          <div className="flex items-center gap-2">
            {server.tool_count > 0 ? (
              <button
                onClick={handleViewTools}
                disabled={loadingTools}
                className={`flex items-center gap-2 disabled:opacity-50 px-2 py-1 -mx-2 -my-1 rounded transition-all ${ACCENTS[ACCENT].interactive}`}
                title="View tools"
              >
                <div className={`p-1.5 rounded ${ACCENTS[ACCENT].iconChip}`}>
                  <WrenchScrewdriverIcon className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-sm font-semibold">{server.tool_count}</div>
                  <div className="text-xs">Tools</div>
                </div>
              </button>
            ) : (
              <div className="flex items-center gap-2 text-gray-400 dark:text-gray-500">
                <div className="p-1.5 bg-gray-50 dark:bg-gray-800 rounded">
                  <WrenchScrewdriverIcon className="h-4 w-4" />
                </div>
                <div>
                  <div className="text-sm font-semibold">0</div>
                  <div className="text-xs">Tools</div>
                </div>
              </div>
            )}
          </div>
        </CardStatsRow>

        <CardFooter
          accent={ACCENT}
          status={
            <StatusDot
              tone={server.is_enabled ? 'green' : 'off'}
              label={server.is_enabled ? 'Enabled' : 'Disabled'}
            />
          }
          controls={
            canModify && (
              <ToggleSwitch
                checked={server.is_enabled}
                onChange={(checked) => onToggle(server.path, checked)}
                ariaLabel={`Enable ${server.server_name}`}
                accent={ACCENT}
              />
            )
          }
        />
      </CardShell>

      {/* Tools Modal */}
      {showTools && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-2xl w-full mx-4 max-h-[80vh] overflow-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                Tools for {server.server_name}
              </h3>
              <button
                onClick={() => setShowTools(false)}
                className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                <XMarkIcon className="h-5 w-5" />
              </button>
            </div>

            {loadingTools ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-600"></div>
                <span className="ml-3 text-gray-500">Loading tools...</span>
              </div>
            ) : tools.length > 0 ? (
              <div className="space-y-3">
                {backendPaths.map((backend) => {
                  const backendTools = toolsByBackend[backend];
                  const isBackendExpanded = expandedBackends[backend];

                  return (
                    <div key={backend} className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                      <button
                        onClick={() => toggleBackend(backend)}
                        className="w-full flex items-center justify-between px-4 py-3 bg-gray-50 dark:bg-gray-900/50 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-left"
                      >
                        <div className="flex items-center gap-2">
                          {isBackendExpanded ? (
                            <ChevronDownIcon className="h-4 w-4 text-gray-500" />
                          ) : (
                            <ChevronRightIcon className="h-4 w-4 text-gray-500" />
                          )}
                          <span className="text-sm font-mono text-gray-700 dark:text-gray-200">
                            {backend}
                          </span>
                        </div>
                        <span className="px-2 py-0.5 text-xs bg-teal-100 dark:bg-teal-900/40 text-teal-700 dark:text-teal-300 rounded-full">
                          {backendTools.length} tool{backendTools.length !== 1 ? 's' : ''}
                        </span>
                      </button>

                      {isBackendExpanded && (
                        <ul className="border-t border-gray-200 dark:border-gray-700 divide-y divide-gray-100 dark:divide-gray-800">
                          {backendTools.map((tool) => {
                            const isToolExpanded = expandedTools[tool.name];
                            const hasDetails = tool.description || (tool.input_schema && Object.keys(tool.input_schema).length > 0);

                            return (
                              <li
                                key={tool.name}
                                className="bg-white dark:bg-gray-800"
                              >
                                {/* Tool header - clickable to expand */}
                                <button
                                  onClick={() => hasDetails && toggleTool(tool.name)}
                                  className={`w-full px-4 py-3 text-left ${hasDetails ? 'cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700' : 'cursor-default'}`}
                                  disabled={!hasDetails}
                                >
                                  <div className="flex items-start justify-between gap-2">
                                    <div className="flex items-center gap-2 flex-1 min-w-0">
                                      {hasDetails && (
                                        isToolExpanded ? (
                                          <ChevronDownIcon className="h-3 w-3 text-gray-400 flex-shrink-0" />
                                        ) : (
                                          <ChevronRightIcon className="h-3 w-3 text-gray-400 flex-shrink-0" />
                                        )
                                      )}
                                      {!hasDetails && <div className="w-3" />}
                                      <span className="font-medium text-sm text-gray-900 dark:text-white">
                                        {tool.name}
                                      </span>
                                      {tool.original_name && tool.name !== tool.original_name && (
                                        <span className="text-xs text-gray-400 dark:text-gray-500">
                                          (original: {tool.original_name})
                                        </span>
                                      )}
                                    </div>
                                    {tool.backend_version && (
                                      <span className="px-1.5 py-0.5 text-[10px] bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 rounded font-mono flex-shrink-0">
                                        v{tool.backend_version}
                                      </span>
                                    )}
                                  </div>
                                </button>

                                {/* Expanded tool details */}
                                {isToolExpanded && hasDetails && (
                                  <div className="px-4 pb-3 pt-0 space-y-3">
                                    {/* Description */}
                                    {tool.description && (
                                      <div className="ml-5">
                                        <p className="text-xs text-gray-600 dark:text-gray-400 leading-relaxed whitespace-pre-wrap">
                                          {tool.description}
                                        </p>
                                      </div>
                                    )}

                                    {/* Schema */}
                                    {tool.input_schema && Object.keys(tool.input_schema).length > 0 && (
                                      <div className="ml-5">
                                        <details className="text-xs">
                                          <summary className="cursor-pointer text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 font-medium">
                                            View Schema
                                          </summary>
                                          <pre className="mt-2 p-3 bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded overflow-x-auto text-gray-800 dark:text-gray-200">
                                            {JSON.stringify(tool.input_schema, null, 2)}
                                          </pre>
                                        </details>
                                      </div>
                                    )}

                                    {/* Required scopes */}
                                    {tool.required_scopes && tool.required_scopes.length > 0 && (
                                      <div className="ml-5 flex flex-wrap gap-1">
                                        {tool.required_scopes.map((scope) => (
                                          <span
                                            key={scope}
                                            className="px-1.5 py-0.5 text-[10px] bg-amber-50 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 rounded font-mono"
                                          >
                                            {scope}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                )}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-gray-500 dark:text-gray-300 text-center py-8">
                No tools available for this virtual server.
              </p>
            )}
          </div>
        </div>
      )}

      {/* ServerConfigModal - reusing exact same component as ServerCard */}
      <ServerConfigModal
        server={serverForConfig as any}
        isOpen={showConfig}
        onClose={() => setShowConfig(false)}
        onShowToast={onShowToast}
        resourceType="virtual_server"
      />
    </>
  );
};

export default VirtualServerCard;
