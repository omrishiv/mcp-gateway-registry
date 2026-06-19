import React, { useState, useCallback, useEffect } from 'react';
import axios from 'axios';
import {
  ArrowPathIcon,
  PencilIcon,
  ClockIcon,
  CheckCircleIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  GlobeAltIcon,
  LockClosedIcon,
  InformationCircleIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import AgentDetailsModal from './AgentDetailsModal';
import SecurityScanModal from './SecurityScanModal';
import StarRatingWidget from './StarRatingWidget';
import StatusBadge from './StatusBadge';
import { ANSBadge } from './ANSBadge';
import { formatRelativeTime, formatTimeSince } from '../utils/dateUtils';
import { normalizeHealthStatus } from '../utils/healthStatus';
import { toScanSummary } from '../utils/securityScan';
import {
  CardShell,
  CardHeader,
  CardBody,
  CardStatsRow,
  CardFooter,
  StatusDot,
  StatusDivider,
  TagList,
  ToggleSwitch,
  InlineDeleteConfirm,
  ENTITY_ACCENTS,
  type StatusTone,
} from './cards';

interface SyncMetadata {
  is_federated?: boolean;
  source_peer_id?: string;
  upstream_path?: string;
  last_synced_at?: string;
  is_read_only?: boolean;
  is_orphaned?: boolean;
  orphaned_at?: string;
}

/**
 * Agent interface representing an A2A agent.
 */
export interface Agent {
  name: string;
  path: string;
  url?: string;
  description?: string;
  version?: string;
  visibility?: 'public' | 'private' | 'group-restricted';
  trust_level?: 'community' | 'verified' | 'trusted' | 'unverified';
  enabled: boolean;
  tags?: string[];
  last_checked_time?: string;
  usersCount?: number;
  rating?: number;
  rating_details?: Array<{ user: string; rating: number }>;
  // Lightweight scan summary from the list payload, used to colour the shield
  // icon without a per-card /security-scan fetch. Undefined if not yet scanned.
  security_scan?: {
    scan_failed?: boolean;
    critical_issues?: number;
    high_severity?: number;
    medium_severity?: number;
    low_severity?: number;
  } | null;
  status?: 'healthy' | 'healthy-auth-expired' | 'unhealthy' | 'unknown';
  // Federation sync metadata
  sync_metadata?: SyncMetadata;
  // ANS verification metadata
  ans_metadata?: {
    ans_agent_id: string;
    status: 'verified' | 'expired' | 'revoked' | 'not_found' | 'pending';
    domain?: string;
    organization?: string;
    certificate?: {
      not_after?: string;
      subject_dn?: string;
      issuer_dn?: string;
    };
    last_verified?: string;
  };
  // Lifecycle status
  lifecycle_status?: 'active' | 'deprecated' | 'draft' | 'beta';
  source_created_at?: string;
  source_updated_at?: string;
  // Supported protocol (e.g., 'a2a', 'mcp')
  supported_protocol?: string | null;
}

/**
 * Props for the AgentCard component.
 */
interface AgentCardProps {
  agent: Agent & { [key: string]: any };  // Allow additional fields from full agent JSON
  onToggle: (path: string, enabled: boolean) => void;
  onEdit?: (agent: Agent) => void;
  canModify?: boolean;
  canHealthCheck?: boolean;  // Whether user can run health check on this agent
  canToggle?: boolean;       // Whether user can enable/disable this agent
  canDelete?: boolean;       // Whether user can delete this agent
  onDelete?: (path: string) => Promise<void>;  // Callback to delete the agent
  onRefreshSuccess?: () => void;
  onShowToast?: (message: string, type: 'success' | 'error') => void;
  onAgentUpdate?: (path: string, updates: Partial<Agent>) => void;
  authToken?: string | null;
}

const ACCENT = ENTITY_ACCENTS.agent;

/** Map an agent health status to a StatusDot tone + label. */
function healthDot(status: Agent['status']): { tone: StatusTone; label: string } {
  switch (status) {
    case 'healthy':
      return { tone: 'emerald', label: 'Healthy' };
    case 'healthy-auth-expired':
      return { tone: 'orange', label: 'Healthy (Auth Expired)' };
    case 'unhealthy':
      return { tone: 'red', label: 'Unhealthy' };
    default:
      return { tone: 'amber', label: 'Unknown' };
  }
}

/**
 * AgentCard component for displaying A2A agents.
 *
 * Composes the shared card primitives with the cyan accent; the entity-specific
 * behavior (trust/ANS badges, health refresh, security scan, details modal) is
 * kept inline here.
 */
const AgentCard: React.FC<AgentCardProps> = React.memo(({
  agent,
  onToggle,
  onEdit,
  canModify,
  canHealthCheck = true,
  canToggle = true,
  canDelete,
  onDelete,
  onRefreshSuccess,
  onShowToast,
  onAgentUpdate,
  authToken
}) => {
  const [showDetails, setShowDetails] = useState(false);
  const [loadingRefresh, setLoadingRefresh] = useState(false);
  const [fullAgentDetails, setFullAgentDetails] = useState<any>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [showSecurityScan, setShowSecurityScan] = useState(false);
  // Seed from the list payload's lightweight scan summary so the shield icon
  // colours correctly with no per-card fetch. The on-click handler upgrades this
  // to the full scan document for the modal.
  const [securityScanResult, setSecurityScanResult] = useState<any>(agent.security_scan ?? null);
  const [loadingSecurityScan, setLoadingSecurityScan] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Check if this is a federated agent from a peer registry using sync_metadata
  const isFederatedAgent = agent.sync_metadata?.is_federated === true;
  const peerRegistryId = isFederatedAgent && agent.sync_metadata?.source_peer_id
    ? agent.sync_metadata.source_peer_id
    : null;

  // Check if this agent is orphaned (no longer exists on peer registry)
  const isOrphanedAgent = agent.sync_metadata?.is_orphaned === true;

  // Keep the icon in sync with the list payload's scan summary. No fetch: the
  // summary (scan_failed + severity counts) arrives inline on /api/agents, so a
  // page of cards costs zero extra requests instead of one /security-scan each.
  // Skip when the user has already opened the full detail (a richer object).
  //
  // Invariant: handleRescan MUST update the parent (onAgentUpdate) synchronously
  // so agent.security_scan is fresh by the time the modal closes and this effect
  // re-syncs. React 18 batches the rescan's state updates, so the prop is current
  // on the next render; wrapping the modal close in setTimeout would break this.
  useEffect(() => {
    if (!showSecurityScan) {
      setSecurityScanResult(agent.security_scan ?? null);
    }
  }, [agent.security_scan, showSecurityScan]);

  const getTrustLevelColor = () => {
    switch (agent.trust_level) {
      case 'trusted':
        return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 border border-green-200 dark:border-green-700';
      case 'verified':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 border border-blue-200 dark:border-blue-700';
      case 'community':
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600';
    }
  };

  const getTrustLevelIcon = () => {
    switch (agent.trust_level) {
      case 'trusted':
        return <ShieldCheckIcon className="h-3 w-3" />;
      case 'verified':
        return <CheckCircleIcon className="h-3 w-3" />;
      default:
        return null;
    }
  };

  const getVisibilityIcon = () => {
    return agent.visibility === 'public' ? (
      <GlobeAltIcon className="h-3 w-3" />
    ) : (
      <LockClosedIcon className="h-3 w-3" />
    );
  };

  const handleRefreshHealth = useCallback(async () => {
    if (loadingRefresh) return;

    setLoadingRefresh(true);
    try {
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
      const response = await axios.post(
        `/api/agents${agent.path}/health`,
        undefined,
        headers ? { headers } : undefined
      );

      // Update just this agent instead of triggering global refresh
      if (onAgentUpdate && response.data) {
        const updates: Partial<Agent> = {
          status: normalizeHealthStatus(response.data.status) as Agent['status'],
          last_checked_time: response.data.last_checked_iso
        };

        onAgentUpdate(agent.path, updates);
      } else if (onRefreshSuccess) {
        // Fallback to global refresh if onAgentUpdate is not provided
        onRefreshSuccess();
      }

      if (onShowToast) {
        onShowToast('Agent health status refreshed successfully', 'success');
      }
    } catch (error: any) {
      console.error('Failed to refresh agent health:', error);
      if (onShowToast) {
        onShowToast(error.response?.data?.detail || 'Failed to refresh agent health status', 'error');
      }
    } finally {
      setLoadingRefresh(false);
    }
  }, [agent.path, authToken, loadingRefresh, onRefreshSuccess, onShowToast, onAgentUpdate]);

  const handleCopyDetails = useCallback(
    async (data: any) => {
      try {
        await navigator.clipboard.writeText(JSON.stringify(data, null, 2));
        onShowToast?.('Full agent JSON copied to clipboard!', 'success');
      } catch (error) {
        console.error('Failed to copy JSON:', error);
        onShowToast?.('Failed to copy JSON', 'error');
      }
    },
    [onShowToast]
  );

  const handleViewSecurityScan = useCallback(async () => {
    if (loadingSecurityScan) return;

    setShowSecurityScan(true);
    setLoadingSecurityScan(true);
    try {
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
      const response = await axios.get(
        `/api/agents${agent.path}/security-scan`,
        headers ? { headers } : undefined
      );
      setSecurityScanResult(response.data);
    } catch (error: any) {
      if (error.response?.status !== 404) {
        console.error('Failed to fetch security scan:', error);
        if (onShowToast) {
          onShowToast('Failed to load security scan results', 'error');
        }
      }
      setSecurityScanResult(null);
    } finally {
      setLoadingSecurityScan(false);
    }
  }, [agent.path, authToken, loadingSecurityScan, onShowToast]);

  const handleRescan = useCallback(async () => {
    const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
    const response = await axios.post(
      `/api/agents${agent.path}/rescan`,
      undefined,
      headers ? { headers } : undefined
    );
    // Show the full result in the open modal, and push the lightweight summary
    // up so agent.security_scan (the list entry) reflects the new scan. Without
    // this the prop-sync effect would revert the badge to the stale list value
    // when the modal closes.
    setSecurityScanResult(response.data);
    onAgentUpdate?.(agent.path, { security_scan: toScanSummary(response.data) });
  }, [agent.path, authToken, onAgentUpdate]);

  const getSecurityIconState = () => {
    // Gray: no scan result yet
    if (!securityScanResult) {
      return { Icon: ShieldCheckIcon, color: 'text-gray-400 dark:text-gray-500', title: 'View security scan results' };
    }
    // Red: scan failed or any vulnerabilities found
    if (securityScanResult.scan_failed) {
      return { Icon: ShieldExclamationIcon, color: 'text-red-500 dark:text-red-400', title: 'Security scan failed' };
    }
    const hasVulnerabilities = securityScanResult.critical_issues > 0 ||
      securityScanResult.high_severity > 0 ||
      securityScanResult.medium_severity > 0 ||
      securityScanResult.low_severity > 0;
    if (hasVulnerabilities) {
      return { Icon: ShieldExclamationIcon, color: 'text-red-500 dark:text-red-400', title: 'Security issues found' };
    }
    // Green: scan passed with no vulnerabilities
    return { Icon: ShieldCheckIcon, color: 'text-green-500 dark:text-green-400', title: 'Security scan passed' };
  };

  const health = healthDot(agent.status);

  return (
    <>
      <CardShell accent={ACCENT}>
        {showDeleteConfirm ? (
          <InlineDeleteConfirm
            entityType="agent"
            entityName={agent.name || agent.path.replace(/^\//, '')}
            entityPath={agent.path}
            onConfirm={onDelete!}
            onCancel={() => setShowDeleteConfirm(false)}
          />
        ) : (
          <>
            <CardHeader
              title={agent.name}
              badges={
                <>
                  {agent.lifecycle_status && agent.lifecycle_status !== 'active' && (
                    <StatusBadge status={agent.lifecycle_status} />
                  )}
                  {/* Check if this is an ASOR agent */}
                  {(agent.tags?.includes('asor') || (agent as any).provider === 'ASOR') && (
                    <span className="px-2 py-0.5 text-xs font-semibold bg-gradient-to-r from-orange-100 to-red-100 text-orange-700 dark:from-orange-900/30 dark:to-red-900/30 dark:text-orange-300 rounded-full flex-shrink-0 border border-orange-200 dark:border-orange-600">
                      ASOR
                    </span>
                  )}
                  {/* A2A tag badge (for AgentCore imported agents) */}
                  {agent.tags?.includes('a2a') && (
                    <span className="px-2 py-0.5 text-xs font-semibold bg-gradient-to-r from-emerald-100 to-teal-100 text-emerald-700 dark:from-emerald-900/30 dark:to-teal-900/30 dark:text-emerald-300 rounded-full flex-shrink-0 border border-emerald-200 dark:border-emerald-600">
                      A2A
                    </span>
                  )}
                  {/* Supported Protocol Badge */}
                  {agent.supported_protocol === 'a2a' && !agent.tags?.includes('a2a') && (
                    <span className="inline-flex items-center px-2 py-0.5 text-xs font-medium bg-cyan-50 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300 rounded border border-cyan-200 dark:border-cyan-700">
                      A2A Protocol
                    </span>
                  )}
                  {agent.trust_level && (
                    <span className={`px-2 py-0.5 text-xs font-semibold rounded-full flex-shrink-0 flex items-center gap-1 ${getTrustLevelColor()}`}>
                      {getTrustLevelIcon()}
                      {agent.trust_level.toUpperCase()}
                    </span>
                  )}
                  {agent.visibility && (
                    <span className={`px-2 py-0.5 text-xs font-semibold rounded-full flex-shrink-0 flex items-center gap-1 ${
                      agent.visibility === 'public'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 border border-blue-200 dark:border-blue-700'
                        : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600'
                    }`}>
                      {getVisibilityIcon()}
                      {agent.visibility.toUpperCase()}
                    </span>
                  )}
                  {/* Registry source badge - only show for federated (peer registry) items */}
                  {isFederatedAgent && (
                    <span className="px-2 py-0.5 text-xs font-semibold bg-gradient-to-r from-violet-100 to-purple-100 text-violet-700 dark:from-violet-900/30 dark:to-purple-900/30 dark:text-violet-300 rounded-full flex-shrink-0 border border-violet-200 dark:border-violet-600" title={`Synced from ${peerRegistryId}`}>
                      {peerRegistryId?.toUpperCase().replace('PEER-REGISTRY-', '').replace('PEER-', '')}
                    </span>
                  )}
                  {/* Orphaned badge - agent no longer exists on peer registry */}
                  {isOrphanedAgent && (
                    <span className="px-2 py-0.5 text-xs font-semibold bg-gradient-to-r from-red-100 to-rose-100 text-red-700 dark:from-red-900/30 dark:to-rose-900/30 dark:text-red-300 rounded-full flex-shrink-0 border border-red-200 dark:border-red-600" title="No longer exists on peer registry">
                      ORPHANED
                    </span>
                  )}
                </>
              }
              actions={
                <>
                  {canModify && (
                    <button
                      className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-all duration-200 flex-shrink-0"
                      onClick={() => onEdit?.(agent)}
                      title="Edit agent"
                    >
                      <PencilIcon className="h-4 w-4" />
                    </button>
                  )}

                  {/* Security Scan Button */}
                  <button
                    onClick={handleViewSecurityScan}
                    className={`p-2 hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-all duration-200 flex-shrink-0 ${getSecurityIconState().color}`}
                    title={getSecurityIconState().title}
                    aria-label="View security scan results"
                  >
                    {React.createElement(getSecurityIconState().Icon, { className: "h-4 w-4" })}
                  </button>

                  {/* Full Details Button */}
                  <button
                    onClick={async () => {
                      setShowDetails(true);
                      setLoadingDetails(true);
                      try {
                        const response = await axios.get(`/api/agents${agent.path}`);
                        setFullAgentDetails(response.data);
                      } catch (error) {
                        console.error('Failed to fetch agent details:', error);
                        if (onShowToast) {
                          onShowToast('Failed to load full agent details', 'error');
                        }
                      } finally {
                        setLoadingDetails(false);
                      }
                    }}
                    className="p-2 text-gray-400 hover:text-blue-600 dark:hover:text-blue-300 hover:bg-blue-50 dark:hover:bg-blue-700/50 rounded-lg transition-all duration-200 flex-shrink-0"
                    title="View full agent details (JSON)"
                  >
                    <InformationCircleIcon className="h-4 w-4" />
                  </button>

                  {/* Delete Button */}
                  {canDelete && (
                    <button
                      onClick={() => setShowDeleteConfirm(true)}
                      className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-700/50 rounded-lg transition-all duration-200 flex-shrink-0"
                      title="Delete agent"
                      aria-label={`Delete ${agent.name}`}
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  )}
                </>
              }
            />

            {/* ANS badge + path/version/url live just under the header row */}
            <div className="px-5 -mt-2 pb-2 space-y-1">
              {agent.ans_metadata && (
                <div>
                  <ANSBadge ansMetadata={agent.ans_metadata} compact />
                </div>
              )}
              <div>
                <code className="text-xs text-gray-600 dark:text-gray-300 bg-gray-50 dark:bg-gray-800/50 px-2 py-1 rounded font-mono">
                  {agent.path}
                </code>
                {agent.version && (
                  <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                    v{agent.version}
                  </span>
                )}
              </div>
              {agent.url && (
                <a
                  href={agent.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-cyan-700 dark:text-cyan-300 break-all hover:underline"
                >
                  <span className="font-mono">{agent.url}</span>
                </a>
              )}
            </div>

            <CardBody description={agent.description}>
              <TagList tags={agent.tags || []} accent={ACCENT} prefix="#" />
            </CardBody>

            <CardStatsRow columns={1}>
              <StarRatingWidget
                resourceType="agents"
                path={agent.path}
                initialRating={agent.rating || 0}
                initialCount={agent.rating_details?.length || 0}
                ratingDetails={agent.rating_details}
                authToken={authToken}
                onShowToast={onShowToast}
                onRatingUpdate={(newRating) => {
                  // Update local agent rating when user submits rating
                  if (onAgentUpdate) {
                    onAgentUpdate(agent.path, { rating: newRating });
                  }
                }}
              />
            </CardStatsRow>

            <CardFooter
              accent={ACCENT}
              status={
                <>
                  <StatusDot
                    tone={agent.enabled ? 'green' : 'off'}
                    label={agent.enabled ? 'Enabled' : 'Disabled'}
                  />
                  <StatusDivider accent={ACCENT} />
                  <StatusDot tone={health.tone} label={health.label} />
                </>
              }
              controls={
                <>
                  {/* Last Updated (source timestamp) */}
                  {agent.source_updated_at && (
                    <div className="text-xs text-gray-500 dark:text-gray-300 flex items-center gap-1.5">
                      <ClockIcon className="h-3.5 w-3.5" />
                      <span title={new Date(agent.source_updated_at).toLocaleString()}>
                        {formatRelativeTime(agent.source_updated_at)}
                      </span>
                    </div>
                  )}

                  {/* Last Checked */}
                  {(() => {
                    const timeText = formatTimeSince(agent.last_checked_time);
                    return agent.last_checked_time && timeText && !agent.source_updated_at ? (
                      <div className="text-xs text-gray-500 dark:text-gray-300 flex items-center gap-1.5">
                        <ClockIcon className="h-3.5 w-3.5" />
                        <span>{timeText}</span>
                      </div>
                    ) : null;
                  })()}

                  {/* Refresh Button - only show if user has health_check_agent permission */}
                  {canHealthCheck && (
                    <button
                      onClick={handleRefreshHealth}
                      disabled={loadingRefresh}
                      className="p-2.5 text-gray-500 hover:text-cyan-600 dark:hover:text-cyan-400 hover:bg-cyan-50 dark:hover:bg-cyan-900/20 rounded-lg transition-all duration-200 disabled:opacity-50"
                      title="Refresh agent health status"
                    >
                      <ArrowPathIcon className={`h-4 w-4 ${loadingRefresh ? 'animate-spin' : ''}`} />
                    </button>
                  )}

                  {/* Toggle Switch - only show if user has toggle_agent permission */}
                  {canToggle && (
                    <ToggleSwitch
                      checked={agent.enabled}
                      onChange={(checked) => onToggle(agent.path, checked)}
                      ariaLabel={`Enable ${agent.name}`}
                      accent={ACCENT}
                    />
                  )}
                </>
              }
            />
          </>
        )}
      </CardShell>

      <AgentDetailsModal
        agent={agent}
        isOpen={showDetails}
        onClose={() => setShowDetails(false)}
        loading={loadingDetails}
        fullDetails={fullAgentDetails}
        onCopy={handleCopyDetails}
      />

      <SecurityScanModal
        resourceName={agent.name}
        resourceType="agent"
        isOpen={showSecurityScan}
        onClose={() => setShowSecurityScan(false)}
        loading={loadingSecurityScan}
        scanResult={securityScanResult}
        onRescan={canModify ? handleRescan : undefined}
        canRescan={canModify}
        onShowToast={onShowToast}
      />

    </>
  );
});

AgentCard.displayName = 'AgentCard';

export default AgentCard;
