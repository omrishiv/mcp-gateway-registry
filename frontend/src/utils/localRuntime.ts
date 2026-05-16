/**
 * Shared types and helpers for the local-runtime form UI.
 *
 * Used by RegisterPage (new local server) and Dashboard's edit modal.
 * Keeps the JSON-string serialization in one place — both endpoints accept
 * `local_runtime` as a JSON-encoded form field, so the form-state →
 * JSON-string conversion must match exactly between the two callers.
 */

export type LocalRuntimeFormType = 'npx' | 'docker' | 'uvx' | 'command';


export interface LocalRuntimeEnvRow {
  key: string;
  value: string;
  required: boolean;
}


export interface LocalRuntimeFormData {
  type: LocalRuntimeFormType;
  package: string;
  version: string;
  image_digest: string;
  /** Argv-style list — never comma-split (args may contain commas). */
  argList: string[];
  envRows: LocalRuntimeEnvRow[];
}


export const initialLocalRuntime: LocalRuntimeFormData = {
  type: 'npx',
  package: '',
  version: '',
  image_digest: '',
  argList: [],
  envRows: [],
};


/**
 * Convert a LocalRuntimeFormData to the JSON string the backend expects in
 * the `local_runtime` form field.
 *
 * - envRows split into `env` (literal values) and `required_env` (key names
 *   the user supplies at connect time)
 * - argList is filtered for empty entries
 * - image_digest only included for docker
 * - version only included for npx/uvx
 */
export function buildLocalRuntimeJson(rt: LocalRuntimeFormData): string {
  const env: Record<string, string> = {};
  const required_env: string[] = [];
  for (const row of rt.envRows) {
    if (!row.key.trim()) continue;
    if (row.required) {
      required_env.push(row.key.trim());
    } else {
      env[row.key.trim()] = row.value;
    }
  }

  const local_runtime: Record<string, unknown> = {
    type: rt.type,
    package: rt.package.trim(),
    args: rt.argList.filter(a => a.length > 0),
    env,
    required_env,
  };
  if (rt.type === 'docker' && rt.image_digest) {
    local_runtime.image_digest = rt.image_digest;
  }
  if ((rt.type === 'npx' || rt.type === 'uvx') && rt.version) {
    local_runtime.version = rt.version;
  }
  return JSON.stringify(local_runtime);
}


/**
 * Build a LocalRuntimeFormData from a stored local_runtime dict (e.g. when
 * populating the edit modal from an existing server). Returns fresh defaults
 * when `rt` is undefined/empty.
 */
export function buildLocalRuntimeForm(rt: unknown): LocalRuntimeFormData {
  const r = (rt ?? {}) as {
    type?: LocalRuntimeFormType;
    package?: string;
    version?: string;
    image_digest?: string;
    args?: unknown;
    env?: Record<string, string>;
    required_env?: string[];
  };
  const env = r.env ?? {};
  const requiredEnv = r.required_env ?? [];
  const envRows: LocalRuntimeEnvRow[] = [];
  for (const k of requiredEnv) {
    envRows.push({ key: k, value: '', required: true });
  }
  for (const [k, v] of Object.entries(env)) {
    envRows.push({ key: k, value: v, required: false });
  }
  return {
    type: r.type ?? 'npx',
    package: r.package ?? '',
    version: r.version ?? '',
    image_digest: r.image_digest ?? '',
    argList: Array.isArray(r.args) ? [...r.args as string[]] : [],
    envRows,
  };
}
