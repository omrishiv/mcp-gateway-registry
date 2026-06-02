import { useState, useEffect, useCallback, useMemo } from 'react';
import axios from 'axios';
import {
  CustomEntityCreate,
  CustomEntityRecord,
  CustomEntityUpdate,
  CustomTypeDescriptor,
} from '../types/customEntity';
import { useServerStats } from './useServerStats';

interface UseCustomEntitiesReturn {
  /** The full type descriptor (fetched once per tab). Null until loaded. */
  descriptor: CustomTypeDescriptor | null;
  /** Records the caller may see, sorted by name client-side. */
  records: CustomEntityRecord[];
  loading: boolean;
  /** Set when the type no longer exists (stale tab) — drives the empty state. */
  notFound: boolean;
  error: string | null;
  refreshData: () => Promise<void>;
  createRecord: (body: CustomEntityCreate) => Promise<CustomEntityRecord>;
  updateRecord: (uuid: string, body: CustomEntityUpdate) => Promise<CustomEntityRecord>;
  deleteRecord: (uuid: string) => Promise<void>;
}

// Descriptors are immutable in v1 (no PUT — rename/restructure is delete+recreate),
// so cache them per type across tab mounts. Without this, switching back into a
// custom-entity tab refetches GET /api/custom-types/{name} every time, since the
// tab unmounts when inactive and remounts fresh.
const _descriptorCache = new Map<string, CustomTypeDescriptor>();

function _uuidOf(path: string): string {
  // Synthetic path is /{type}/{uuid}; the uuid is the last segment.
  return path.split('/').pop() ?? '';
}

function _sortByName(records: CustomEntityRecord[]): CustomEntityRecord[] {
  return [...records].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Loads one custom type's descriptor (once) and exposes its visible records.
 *
 * Records are sourced from the shared `ServerStatsContext` — the SAME single
 * fetch that backs the sidebar counts and Discover summary — so switching
 * between tabs does not re-read the record list (matching the built-in
 * server/agent tabs). Only the immutable descriptor is fetched per tab mount.
 * Mutations hit the API then refresh the shared context.
 */
export const useCustomEntities = (typeName: string): UseCustomEntitiesReturn => {
  const { customRecordsByType, loading: recordsLoading, refreshData: refreshStats } =
    useServerStats();
  const [descriptor, setDescriptor] = useState<CustomTypeDescriptor | null>(null);
  const [descriptorLoading, setDescriptorLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const records = useMemo(() => {
    const forType = customRecordsByType.find((t) => t.name === typeName);
    return _sortByName((forType?.records ?? []) as CustomEntityRecord[]);
  }, [customRecordsByType, typeName]);

  // Resolve the immutable descriptor. Served from the module cache on a hit so
  // re-entering a tab doesn't refetch; only a cache miss hits the network.
  useEffect(() => {
    const cached = _descriptorCache.get(typeName);
    if (cached) {
      setDescriptor(cached);
      setDescriptorLoading(false);
      setError(null);
      setNotFound(false);
      return;
    }

    let cancelled = false;
    setDescriptorLoading(true);
    setError(null);
    setNotFound(false);
    axios
      .get<CustomTypeDescriptor>(`/api/custom-types/${typeName}`)
      .then((res) => {
        _descriptorCache.set(typeName, res.data);
        if (!cancelled) setDescriptor(res.data);
      })
      .catch((err: any) => {
        if (cancelled) return;
        if (err.response?.status === 404) {
          setNotFound(true);
        } else {
          console.error(`Failed to load custom type ${typeName}:`, err);
          setError(err.response?.data?.detail || 'Failed to load type');
        }
      })
      .finally(() => {
        if (!cancelled) setDescriptorLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [typeName]);

  const createRecord = useCallback(
    async (body: CustomEntityCreate): Promise<CustomEntityRecord> => {
      const res = await axios.post<CustomEntityRecord>(`/api/custom/${typeName}`, body);
      await refreshStats();
      return res.data;
    },
    [typeName, refreshStats],
  );

  const updateRecord = useCallback(
    async (uuid: string, body: CustomEntityUpdate): Promise<CustomEntityRecord> => {
      const res = await axios.put<CustomEntityRecord>(
        `/api/custom/${typeName}/${uuid}`,
        body,
      );
      await refreshStats();
      return res.data;
    },
    [typeName, refreshStats],
  );

  const deleteRecord = useCallback(
    async (uuid: string): Promise<void> => {
      await axios.delete(`/api/custom/${typeName}/${uuid}`);
      await refreshStats();
    },
    [typeName, refreshStats],
  );

  return {
    descriptor,
    records,
    loading: descriptorLoading || recordsLoading,
    notFound,
    error,
    refreshData: refreshStats,
    createRecord,
    updateRecord,
    deleteRecord,
  };
};

export { _uuidOf as uuidFromPath };
