import { useState, useEffect, useCallback } from 'react';

/**
 * Generic fetch-list hook for the IAM resources. The IAM components each had a
 * structurally identical hook (state + loading + error + fetch-in-useEffect +
 * refetch) differing only in the endpoint and how the list is unwrapped from
 * the response. This factory captures that shared shape.
 *
 * @param fetcher  Performs the request and returns the resource array.
 * @param errorMessage  Fallback message when the request fails.
 * @param depKey  Optional stable string; refetches when it changes (e.g. search).
 */
export function useIAMResource<T>(
  fetcher: () => Promise<T[]>,
  errorMessage: string,
  depKey?: string,
) {
  const [data, setData] = useState<T[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      setData(await fetcher());
    } catch (err: any) {
      setError(err.response?.data?.detail || errorMessage);
    } finally {
      setIsLoading(false);
    }
    // fetcher is recreated per render by callers; depKey is the stable trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [depKey]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  return { data, isLoading, error, refetch };
}
