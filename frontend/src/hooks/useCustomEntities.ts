import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import {
  CustomEntityCreate,
  CustomEntityRecord,
  CustomEntityUpdate,
  CustomTypeDescriptor,
} from '../types/customEntity';

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

function _uuidOf(path: string): string {
  // Synthetic path is /{type}/{uuid}; the uuid is the last segment.
  return path.split('/').pop() ?? '';
}

function _sortByName(records: CustomEntityRecord[]): CustomEntityRecord[] {
  // Presentational sort of the fetched page only (server paginates by _id).
  return [...records].sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * Loads one custom type's descriptor (once) and its visible records.
 *
 * The descriptor is fetched a single time per tab mount because types are
 * immutable in v1; a deleted type surfaces as a 404 and flips `notFound`.
 */
export const useCustomEntities = (typeName: string): UseCustomEntitiesReturn => {
  const [descriptor, setDescriptor] = useState<CustomTypeDescriptor | null>(null);
  const [records, setRecords] = useState<CustomEntityRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchRecords = useCallback(async () => {
    const res = await axios.get(`/api/custom/${typeName}?limit=1000`);
    const list: CustomEntityRecord[] = res.data?.records ?? [];
    setRecords(_sortByName(list));
  }, [typeName]);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setNotFound(false);

      // Fetch the descriptor only once per tab; refresh just re-pulls records.
      if (!descriptor) {
        const descRes = await axios.get<CustomTypeDescriptor>(
          `/api/custom-types/${typeName}`,
        );
        setDescriptor(descRes.data);
      }
      await fetchRecords();
    } catch (err: any) {
      if (err.response?.status === 404) {
        setNotFound(true);
        setRecords([]);
      } else {
        console.error(`Failed to load custom type ${typeName}:`, err);
        setError(err.response?.data?.detail || 'Failed to load records');
      }
    } finally {
      setLoading(false);
    }
  }, [typeName, descriptor, fetchRecords]);

  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeName]);

  const createRecord = useCallback(
    async (body: CustomEntityCreate): Promise<CustomEntityRecord> => {
      const res = await axios.post<CustomEntityRecord>(`/api/custom/${typeName}`, body);
      await fetchRecords();
      return res.data;
    },
    [typeName, fetchRecords],
  );

  const updateRecord = useCallback(
    async (uuid: string, body: CustomEntityUpdate): Promise<CustomEntityRecord> => {
      const res = await axios.put<CustomEntityRecord>(
        `/api/custom/${typeName}/${uuid}`,
        body,
      );
      await fetchRecords();
      return res.data;
    },
    [typeName, fetchRecords],
  );

  const deleteRecord = useCallback(
    async (uuid: string): Promise<void> => {
      await axios.delete(`/api/custom/${typeName}/${uuid}`);
      await fetchRecords();
    },
    [typeName, fetchRecords],
  );

  return {
    descriptor,
    records,
    loading,
    notFound,
    error,
    refreshData: fetchData,
    createRecord,
    updateRecord,
    deleteRecord,
  };
};

export { _uuidOf as uuidFromPath };
