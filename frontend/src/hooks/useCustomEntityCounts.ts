import { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { CustomEntityRecord } from '../types/customEntity';
import { CustomTypeTab } from './useRegistryConfig';

/** Records for one custom type, used by the Discover summary to count them. */
export interface CustomTypeRecords {
  name: string;
  displayName: string;
  records: CustomEntityRecord[];
}

interface UseCustomEntityCountsReturn {
  byType: CustomTypeRecords[];
  loading: boolean;
  refresh: () => Promise<void>;
}

/**
 * Aggregate fetch of records across ALL custom types, for the Discover summary.
 *
 * The per-type tabs fetch lazily on click; the Discover homepage needs counts
 * up front, so this pulls each type's records in parallel. Returns the raw
 * records (not just counts) so the caller can apply the same tag/enabled
 * filtering it uses for the built-in categories.
 */
export const useCustomEntityCounts = (
  customTypes: CustomTypeTab[],
): UseCustomEntityCountsReturn => {
  const [byType, setByType] = useState<CustomTypeRecords[]>([]);
  const [loading, setLoading] = useState(false);

  // Stable key so the effect refetches only when the set of types changes.
  const typesKey = customTypes.map((t) => t.name).join(',');

  const fetchData = useCallback(async () => {
    if (customTypes.length === 0) {
      setByType([]);
      return;
    }
    setLoading(true);
    try {
      const results = await Promise.all(
        customTypes.map(async (t) => {
          try {
            const res = await axios.get(`/api/custom/${t.name}?limit=1000`);
            const records: CustomEntityRecord[] = res.data?.records ?? [];
            return { name: t.name, displayName: t.display_name, records };
          } catch {
            // A type deleted mid-session 404s; treat as zero records.
            return { name: t.name, displayName: t.display_name, records: [] };
          }
        }),
      );
      setByType(results);
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typesKey]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { byType, loading, refresh: fetchData };
};
