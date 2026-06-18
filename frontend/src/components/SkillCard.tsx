import React, { useState, useCallback, useEffect } from 'react';
import axios from 'axios';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  SparklesIcon,
  PencilIcon,
  TrashIcon,
  GlobeAltIcon,
  LockClosedIcon,
  UserGroupIcon,
  InformationCircleIcon,
  ArrowTopRightOnSquareIcon,
  WrenchScrewdriverIcon,
  CheckCircleIcon,
  XCircleIcon,
  ArrowPathIcon,
  ClockIcon,
  ClipboardIcon,
  ArrowDownTrayIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
} from '@heroicons/react/24/outline';
import { Skill, SkillResourceManifest } from '../types/skill';
import StatusBadge from './StatusBadge';
import StarRatingWidget from './StarRatingWidget';
import SecurityScanModal from './SecurityScanModal';
import ResourceBoundTokenButton from './ResourceBoundTokenButton';
import SkillResources from './SkillResources';
import { formatTimeSince } from '../utils/dateUtils';
import { toScanSummary } from '../utils/securityScan';
import {
  CardShell,
  CardHeader,
  CardBody,
  CardFooter,
  StatusDot,
  StatusDivider,
  TagList,
  ToggleSwitch,
  ENTITY_ACCENTS,
  type StatusTone,
} from './cards';
import { EntityModal } from './modals';

const ACCENT = ENTITY_ACCENTS.skill;

/**
 * Props for the SkillCard component.
 */
interface SkillCardProps {
  skill: Skill & { [key: string]: any };
  onToggle: (path: string, enabled: boolean) => void;
  onEdit?: (skill: Skill) => void;
  onDelete?: (path: string) => void;
  canModify?: boolean;
  canToggle?: boolean;
  canHealthCheck?: boolean;
  onRefreshSuccess?: () => void;
  onShowToast?: (message: string, type: 'success' | 'error') => void;
  onSkillUpdate?: (path: string, updates: Partial<Skill>) => void;
  authToken?: string | null;
}

// Helper function to parse YAML frontmatter from markdown
const parseYamlFrontmatter = (content: string): { frontmatter: Record<string, string> | null; body: string } => {
  // Check if content starts with --- (YAML frontmatter delimiter)
  const frontmatterRegex = /^---\s*\n([\s\S]*?)\n---\s*\n([\s\S]*)$/;
  const match = content.match(frontmatterRegex);

  if (match) {
    const yamlContent = match[1];
    const body = match[2];

    // Simple YAML parsing for key: value pairs
    const frontmatter: Record<string, string> = {};
    const lines = yamlContent.split('\n');
    for (const line of lines) {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim();
        const value = line.substring(colonIndex + 1).trim();
        if (key && value) {
          frontmatter[key] = value;
        }
      }
    }

    return { frontmatter: Object.keys(frontmatter).length > 0 ? frontmatter : null, body };
  }

  return { frontmatter: null, body: content };
};


/** Map a skill health status to a StatusDot tone + label. */
function healthDot(
  status: 'healthy' | 'unhealthy' | 'unknown',
): { tone: StatusTone; label: string } {
  switch (status) {
    case 'healthy':
      return { tone: 'emerald', label: 'Healthy' };
    case 'unhealthy':
      return { tone: 'red', label: 'Unhealthy' };
    default:
      return { tone: 'amber', label: 'Unknown' };
  }
}

/**
 * SkillCard component for displaying Agent Skills.
 *
 * Composes the shared card primitives with the amber accent. The SKILL.md
 * viewer (YAML frontmatter + markdown + resources) and the tool-availability /
 * security-scan flows are the skill-specific behavior kept inline here.
 */
const SkillCard: React.FC<SkillCardProps> = React.memo(({
  skill,
  onToggle,
  onEdit,
  onDelete,
  canModify,
  canToggle = true,
  canHealthCheck = true,
  onShowToast,
  onSkillUpdate,
  authToken
}) => {
  const [showDetails, setShowDetails] = useState(false);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [skillMdContent, setSkillMdContent] = useState<string | null>(null);
  // resource_manifest is exposed by /content but NOT by the listing schema
  // (SkillInfo). Capture it from the same /content fetch the modal already
  // makes so the Resources section can render against the modal-scoped data.
  const [resourceManifest, setResourceManifest] = useState<SkillResourceManifest | null>(null);

  const [loadingToolCheck, setLoadingToolCheck] = useState(false);
  const [toolCheckResult, setToolCheckResult] = useState<any>(null);
  const [loadingHealthCheck, setLoadingHealthCheck] = useState(false);
  const toSkillHealth = (raw: string | undefined): 'healthy' | 'unhealthy' | 'unknown' => {
    if (raw === 'healthy' || raw === 'unhealthy' || raw === 'unknown') return raw;
    return 'unknown';
  };
  const [healthStatus, setHealthStatus] = useState<'healthy' | 'unhealthy' | 'unknown'>(
    toSkillHealth(skill.health_status)
  );
  const [lastCheckedTime, setLastCheckedTime] = useState<string | null>(
    skill.last_checked_time || null
  );
  const [showSecurityScan, setShowSecurityScan] = useState(false);
  // Seed from the list payload's lightweight scan summary so the shield icon
  // colours correctly with no per-card fetch. The on-click handler upgrades this
  // to the full scan document for the modal.
  const [securityScanResult, setSecurityScanResult] = useState<any>(skill.security_scan ?? null);
  const [loadingSecurityScan, setLoadingSecurityScan] = useState(false);

  // Sync health status from props when skill changes
  useEffect(() => {
    setHealthStatus(toSkillHealth(skill.health_status));
    setLastCheckedTime(skill.last_checked_time || null);
  }, [skill.health_status, skill.last_checked_time]);

  // Extract skill name from path for API calls
  // skill.path is like "/skills/doc-coauthoring", API routes already have /skills prefix
  // so we need just "/doc-coauthoring" for the path parameter
  const getSkillApiPath = (path: string) => {
    if (path.startsWith('/skills/')) {
      return path.replace('/skills/', '/');
    }
    return path;
  };
  const skillApiPath = getSkillApiPath(skill.path);

  // Keep the icon in sync with the list payload's scan summary. No fetch: the
  // summary (scan_failed + severity counts) arrives inline on /api/skills, so a
  // page of cards costs zero extra requests instead of one /security-scan each.
  // Skip when the user has already opened the full detail (a richer object).
  //
  // Invariant: handleRescan MUST update the parent (onSkillUpdate) synchronously
  // so skill.security_scan is fresh by the time the modal closes and this effect
  // re-syncs. React 18 batches the rescan's state updates, so the prop is current
  // on the next render; wrapping the modal close in setTimeout would break this.
  useEffect(() => {
    if (!showSecurityScan) {
      setSecurityScanResult(skill.security_scan ?? null);
    }
  }, [skill.security_scan, showSecurityScan]);

  const getVisibilityIcon = () => {
    switch (skill.visibility) {
      case 'public':
        return <GlobeAltIcon className="h-3 w-3" />;
      case 'group':
        return <UserGroupIcon className="h-3 w-3" />;
      default:
        return <LockClosedIcon className="h-3 w-3" />;
    }
  };

  const getVisibilityColor = () => {
    switch (skill.visibility) {
      case 'public':
        return 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 border border-green-200 dark:border-green-700';
      case 'group':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400 border border-blue-200 dark:border-blue-700';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300 border border-gray-200 dark:border-gray-600';
    }
  };

  const handleViewDetails = useCallback(async () => {
    setShowDetails(true);
    setLoadingDetails(true);
    setSkillMdContent(null);
    setResourceManifest(null);

    try {
      // Fetch SKILL.md content via backend proxy to avoid CORS issues
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
      const response = await axios.get(
        `/api/skills${skillApiPath}/content`,
        headers ? { headers } : undefined
      );
      setSkillMdContent(response.data.content);
      setResourceManifest(response.data.resource_manifest ?? null);
    } catch (error: any) {
      console.error('Failed to fetch SKILL.md content:', error);
      const detail = error.response?.data?.detail;
      if (error.response?.status === 409 && detail) {
        setSkillMdContent(`> **Content Drift Detected**\n>\n> ${detail}\n>\n> Re-register this skill to update the integrity baseline and re-enable it.`);
      } else if (onShowToast) {
        onShowToast(detail || 'Failed to load SKILL.md content', 'error');
      }
    } finally {
      setLoadingDetails(false);
    }
  }, [skillApiPath, authToken, onShowToast]);

  const handleCheckTools = useCallback(async () => {
    if (loadingToolCheck) return;

    setLoadingToolCheck(true);
    try {
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
      const response = await axios.get(
        `/api/skills${skillApiPath}/tools`,
        headers ? { headers } : undefined
      );
      setToolCheckResult(response.data);
      if (onShowToast) {
        const result = response.data;
        if (result.all_available) {
          onShowToast('All required tools are available', 'success');
        } else {
          onShowToast(`Missing tools: ${result.missing_tools?.join(', ') || 'Unknown'}`, 'error');
        }
      }
    } catch (error: any) {
      console.error('Failed to check tool availability:', error);
      if (onShowToast) {
        onShowToast('Failed to check tool availability', 'error');
      }
    } finally {
      setLoadingToolCheck(false);
    }
  }, [skill.path, authToken, loadingToolCheck, onShowToast]);

  const handleRefreshHealth = useCallback(async () => {
    if (loadingHealthCheck) return;

    setLoadingHealthCheck(true);
    try {
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
      const response = await axios.get(
        `/api/skills${skillApiPath}/health`,
        headers ? { headers } : undefined
      );

      const newStatus = response.data.healthy ? 'healthy' : 'unhealthy';
      setHealthStatus(newStatus);
      setLastCheckedTime(new Date().toISOString());

      // Update parent if callback provided
      if (onSkillUpdate) {
        onSkillUpdate(skill.path, {
          health_status: newStatus,
          last_checked_time: new Date().toISOString()
        } as any);
      }

      if (onShowToast) {
        onShowToast(
          response.data.healthy
            ? 'SKILL.md is accessible'
            : `SKILL.md check failed: ${response.data.error || 'Unknown error'}`,
          response.data.healthy ? 'success' : 'error'
        );
      }
    } catch (error: any) {
      console.error('Failed to check skill health:', error);
      setHealthStatus('unhealthy');
      if (onShowToast) {
        onShowToast('Failed to check skill health', 'error');
      }
    } finally {
      setLoadingHealthCheck(false);
    }
  }, [skill.path, authToken, loadingHealthCheck, onShowToast, onSkillUpdate]);

  const handleViewSecurityScan = useCallback(async () => {
    if (loadingSecurityScan) return;

    setShowSecurityScan(true);
    setLoadingSecurityScan(true);
    try {
      const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
      const response = await axios.get(
        `/api/skills${skillApiPath}/security-scan`,
        headers ? { headers } : undefined
      );
      setSecurityScanResult(response.data);
    } catch (error: any) {
      if (error.response?.status !== 404) {
        if (onShowToast) {
          onShowToast('Failed to load security scan results', 'error');
        }
      }
      setSecurityScanResult(null);
    } finally {
      setLoadingSecurityScan(false);
    }
  }, [skillApiPath, authToken, loadingSecurityScan, onShowToast]);

  const handleRescan = useCallback(async () => {
    const headers = authToken ? { Authorization: `Bearer ${authToken}` } : undefined;
    const response = await axios.post(
      `/api/skills${skillApiPath}/rescan`,
      undefined,
      headers ? { headers } : undefined
    );
    // Show the full result in the open modal, and push the lightweight summary
    // up so skill.security_scan (the list entry) reflects the new scan. Without
    // this the prop-sync effect would revert the badge to the stale list value
    // when the modal closes.
    setSecurityScanResult(response.data);
    onSkillUpdate?.(skill.path, { security_scan: toScanSummary(response.data) });
  }, [skillApiPath, skill.path, authToken, onSkillUpdate]);

  const getSecurityIconState = () => {
    if (!securityScanResult) {
      return { Icon: ShieldCheckIcon, color: 'text-gray-400 dark:text-gray-500', title: 'View security scan results' };
    }
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
    return { Icon: ShieldCheckIcon, color: 'text-green-500 dark:text-green-400', title: 'Security scan passed' };
  };

  const health = healthDot(healthStatus);

  return (
    <>
      <CardShell accent={ACCENT}>
        <CardHeader
          title={skill.name}
          path={skill.path}
          badges={
            <>
              <span className="px-2 py-0.5 text-xs font-semibold bg-gradient-to-r from-amber-100 to-orange-100 text-amber-700 dark:from-amber-900/30 dark:to-orange-900/30 dark:text-amber-300 rounded-full flex-shrink-0 border border-amber-200 dark:border-amber-600">
                SKILL
              </span>
              <span className={`px-2 py-0.5 text-xs font-semibold rounded-full flex-shrink-0 flex items-center gap-1 ${getVisibilityColor()}`}>
                {getVisibilityIcon()}
                {skill.visibility.toUpperCase()}
              </span>
              {skill.status && skill.status !== 'active' && (
                <StatusBadge status={skill.status} />
              )}
            </>
          }
          actions={
            <>
              {canModify && (
                <>
                  <button
                    className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700/50 rounded-lg transition-all duration-200 flex-shrink-0"
                    onClick={() => onEdit?.(skill)}
                    title="Edit skill"
                  >
                    <PencilIcon className="h-4 w-4" />
                  </button>
                  <button
                    className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30 rounded-lg transition-all duration-200 flex-shrink-0"
                    onClick={() => onDelete?.(skillApiPath)}
                    title="Delete skill"
                  >
                    <TrashIcon className="h-4 w-4" />
                  </button>
                </>
              )}

              {/* Tool Check Button */}
              {skill.allowed_tools && skill.allowed_tools.length > 0 && (
                <button
                  onClick={handleCheckTools}
                  disabled={loadingToolCheck}
                  className={`p-2 hover:bg-gray-50 dark:hover:bg-gray-700/50 rounded-lg transition-all duration-200 flex-shrink-0 ${
                    toolCheckResult?.all_available === true
                      ? 'text-green-500 dark:text-green-400'
                      : toolCheckResult?.all_available === false
                      ? 'text-red-500 dark:text-red-400'
                      : 'text-gray-400 dark:text-gray-500'
                  }`}
                  title="Check tool availability"
                >
                  <WrenchScrewdriverIcon className={`h-4 w-4 ${loadingToolCheck ? 'animate-spin' : ''}`} />
                </button>
              )}

              {/* Security Scan Button */}
              <button
                onClick={handleViewSecurityScan}
                className={`p-2 hover:bg-gray-50 dark:hover:bg-gray-700/50 rounded-lg transition-all duration-200 flex-shrink-0 ${getSecurityIconState().color}`}
                title={getSecurityIconState().title}
                aria-label={getSecurityIconState().title}
              >
                {React.createElement(getSecurityIconState().Icon, { className: `h-4 w-4 ${loadingSecurityScan ? 'animate-pulse' : ''}` })}
              </button>

              {/* Details Button */}
              <button
                onClick={handleViewDetails}
                className="p-2 text-gray-400 hover:text-amber-600 dark:hover:text-amber-300 hover:bg-amber-50 dark:hover:bg-amber-700/50 rounded-lg transition-all duration-200 flex-shrink-0"
                title="View SKILL.md content"
              >
                <InformationCircleIcon className="h-4 w-4" />
              </button>
            </>
          }
        />

        {/* version + author live just under the header path */}
        {(skill.version || skill.author) && (
          <div className="px-5 -mt-2 pb-2 text-xs text-gray-500 dark:text-gray-400">
            {skill.version && <span>v{skill.version}</span>}
            {skill.author && <span className="ml-2">by {skill.author}</span>}
          </div>
        )}

        <CardBody description={skill.description}>
          <TagList
            tags={skill.tags || []}
            accent={ACCENT}
            prefix="#"
            tagClassName={(tag) =>
              tag === 'security-pending' || tag === 'content-drifted'
                ? 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-700'
                : undefined
            }
          />

          {/* Target Agents */}
          {skill.target_agents && skill.target_agents.length > 0 && (
            <div className="mt-4">
              <span className="text-xs text-gray-500 dark:text-gray-400">Target agents: </span>
              <span className="text-xs text-amber-700 dark:text-amber-300">
                {skill.target_agents.join(', ')}
              </span>
            </div>
          )}

          {/* Tools Count */}
          {skill.allowed_tools && skill.allowed_tools.length > 0 && (
            <div className="flex items-center gap-2 mt-4">
              <WrenchScrewdriverIcon className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              <span className="text-xs text-gray-600 dark:text-gray-300">
                {skill.allowed_tools.length} tool{skill.allowed_tools.length !== 1 ? 's' : ''} required
              </span>
              {toolCheckResult && (
                toolCheckResult.all_available ? (
                  <CheckCircleIcon className="h-4 w-4 text-green-500" title="All tools available" />
                ) : (
                  <XCircleIcon className="h-4 w-4 text-red-500" title="Some tools missing" />
                )
              )}
            </div>
          )}
        </CardBody>

        {/* Stats - skill-specific flex row (registry + rating + SKILL.md link) */}
        <div className="px-5 pb-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="p-1.5 bg-amber-50 dark:bg-amber-900/30 rounded">
                <SparklesIcon className="h-4 w-4 text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <div className="text-xs text-gray-500 dark:text-gray-400">Registry</div>
                <div className="text-sm font-semibold text-gray-900 dark:text-white">
                  {skill.registry_name || 'local'}
                </div>
              </div>
            </div>

            {/* Rating Widget */}
            <StarRatingWidget
              resourceType="skills"
              path={skillApiPath}
              initialRating={skill.num_stars || 0}
              initialCount={skill.rating_details?.length || 0}
              ratingDetails={skill.rating_details}
              authToken={authToken}
              onShowToast={onShowToast}
            />

            {/* SKILL.md Link */}
            {skill.skill_md_url && (
              <a
                href={skill.skill_md_url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-amber-700 dark:text-amber-300 hover:underline"
              >
                <ArrowTopRightOnSquareIcon className="h-3 w-3" />
                SKILL.md
              </a>
            )}
          </div>
        </div>

        <CardFooter
          accent={ACCENT}
          status={
            <>
              <div className="flex items-center gap-2">
                <StatusDot
                  tone={skill.is_enabled ? 'green' : 'off'}
                  label={skill.is_enabled ? 'Enabled' : 'Disabled'}
                />
                {!skill.is_enabled && skill.tags?.includes('content-drifted') && (
                  <span className="text-xs text-red-600 dark:text-red-400 font-medium" title="Skill content changed since registration. Re-register to update the baseline.">
                    — content drifted
                  </span>
                )}
                {!skill.is_enabled && skill.tags?.includes('security-pending') && !skill.tags?.includes('content-drifted') && (
                  <span className="text-xs text-red-600 dark:text-red-400 font-medium">
                    — security review pending
                  </span>
                )}
              </div>

              <StatusDivider accent={ACCENT} />

              <StatusDot tone={health.tone} label={health.label} />
            </>
          }
          controls={
            <>
              {/* Last Checked */}
              {(() => {
                const timeText = formatTimeSince(lastCheckedTime);
                return lastCheckedTime && timeText ? (
                  <div className="text-xs text-gray-500 dark:text-gray-300 flex items-center gap-1.5">
                    <ClockIcon className="h-3.5 w-3.5" />
                    <span>{timeText}</span>
                  </div>
                ) : null;
              })()}

              {/* Refresh Health Button */}
              {canHealthCheck && (
                <button
                  onClick={handleRefreshHealth}
                  disabled={loadingHealthCheck}
                  className="p-2.5 text-gray-500 hover:text-amber-600 dark:hover:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/20 rounded-lg transition-all duration-200 disabled:opacity-50"
                  title="Check SKILL.md accessibility"
                  aria-label={`Check health for ${skill.name}`}
                >
                  <ArrowPathIcon className={`h-4 w-4 ${loadingHealthCheck ? 'animate-spin' : ''}`} />
                </button>
              )}

              {/* Toggle Switch */}
              {canToggle && (
                <ToggleSwitch
                  checked={skill.is_enabled}
                  onChange={(checked) => onToggle(skill.path, checked)}
                  ariaLabel={`Enable ${skill.name}`}
                  accent={ACCENT}
                />
              )}
            </>
          }
        />
      </CardShell>

      {/* Skill Details Modal (SKILL.md viewer) */}
      <EntityModal
        isOpen={showDetails}
        onClose={() => setShowDetails(false)}
        loading={loadingDetails}
        maxWidth="4xl"
        title={skill.name}
      >
        <div>
            {skill.path && (
              <div className="mb-4">
                <ResourceBoundTokenButton
                  resourceType="skill"
                  resourceId={skill.path}
                  resourceName={skill.name}
                />
              </div>
            )}

            {/* Action buttons */}
            <div className="flex items-center gap-4 mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
              {skill.skill_md_url && (
                <a
                  href={skill.skill_md_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-sm text-amber-700 dark:text-amber-300 hover:underline"
                >
                  <ArrowTopRightOnSquareIcon className="h-4 w-4" />
                  View Skill
                </a>
              )}
              {skill.repository_url && (
                <a
                  href={skill.repository_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-sm text-amber-700 dark:text-amber-300 hover:underline"
                >
                  <ArrowTopRightOnSquareIcon className="h-4 w-4" />
                  View Repo
                </a>
              )}
              {skillMdContent && (
                <>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(skillMdContent);
                      if (onShowToast) {
                        onShowToast('SKILL.md copied to clipboard', 'success');
                      }
                    }}
                    className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-400 hover:text-amber-700 dark:hover:text-amber-300 transition-colors"
                    title="Copy to clipboard"
                  >
                    <ClipboardIcon className="h-4 w-4" />
                    Copy
                  </button>
                  <button
                    onClick={() => {
                      const blob = new Blob([skillMdContent], { type: 'text/markdown' });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = `${skill.name || 'skill'}.md`;
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      URL.revokeObjectURL(url);
                    }}
                    className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-400 hover:text-amber-700 dark:hover:text-amber-300 transition-colors"
                    title="Download SKILL.md"
                  >
                    <ArrowDownTrayIcon className="h-4 w-4" />
                    Download
                  </button>
                </>
              )}
            </div>

            {skillMdContent ? (
              (() => {
                const { frontmatter, body } = parseYamlFrontmatter(skillMdContent);
                return (
                  <>
                    {/* YAML Frontmatter Table */}
                    {frontmatter && (
                      <div className="mb-6 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
                        <table className="w-full text-sm">
                          <tbody>
                            {Object.entries(frontmatter).map(([key, value]) => (
                              <tr key={key} className="border-b border-gray-200 dark:border-gray-700 last:border-b-0">
                                <td className="px-4 py-2 bg-gray-50 dark:bg-gray-900/50 font-medium text-gray-700 dark:text-gray-300 w-1/4">
                                  {key}
                                </td>
                                <td className="px-4 py-2 text-gray-900 dark:text-white">
                                  {value}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                    {/* Resources section (self-gated: hidden for federated skills,
                        empty manifests, and skills without manifests).

                        The manifest is sourced from the /content fetch above
                        because the listing schema (SkillInfo) intentionally
                        omits resource_manifest to keep the listing payload
                        small; only the full SkillCard exposes it. */}
                    <SkillResources
                      skill={skill}
                      skillApiPath={skillApiPath}
                      authToken={authToken}
                      skillMdContent={skillMdContent}
                      resourceManifest={resourceManifest}
                    />
                    {/* Markdown Body */}
                    <div className="prose prose-sm dark:prose-invert max-w-none prose-headings:text-amber-800 dark:prose-headings:text-amber-200 prose-a:text-amber-600 dark:prose-a:text-amber-400 prose-code:bg-gray-100 dark:prose-code:bg-gray-900 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-pre:bg-gray-100 dark:prose-pre:bg-gray-900">
                      <ReactMarkdown remarkPlugins={[remarkGfm]}>{body}</ReactMarkdown>
                    </div>
                  </>
                );
              })()
            ) : (
              <div className="text-center py-12 text-gray-500">
                <p>Could not load SKILL.md content.</p>
                <p className="mt-2 text-sm">
                  Try visiting the{' '}
                  <a
                    href={skill.skill_md_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-amber-600 hover:underline"
                  >
                    source URL
                  </a>{' '}
                  directly.
                </p>
              </div>
            )}
        </div>
      </EntityModal>
      {/* Security Scan Modal */}
      <SecurityScanModal
        resourceName={skill.name}
        resourceType="skill"
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

SkillCard.displayName = 'SkillCard';

export default SkillCard;
