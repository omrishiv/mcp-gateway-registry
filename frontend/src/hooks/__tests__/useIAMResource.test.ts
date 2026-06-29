import { renderHook, waitFor, act } from '@testing-library/react';
import { useIAMResource } from '../useIAMResource';

describe('useIAMResource', () => {
  it('fetches on mount and exposes the data', async () => {
    const fetcher = jest.fn().mockResolvedValue([{ id: 1 }, { id: 2 }]);
    const { result } = renderHook(() =>
      useIAMResource(fetcher, 'failed'),
    );

    expect(result.current.isLoading).toBe(true);
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.data).toEqual([{ id: 1 }, { id: 2 }]);
    expect(result.current.error).toBeNull();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('surfaces the API detail message on failure', async () => {
    const fetcher = jest
      .fn()
      .mockRejectedValue({ response: { data: { detail: 'nope' } } });
    const { result } = renderHook(() => useIAMResource(fetcher, 'fallback'));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.error).toBe('nope');
    expect(result.current.data).toEqual([]);
  });

  it('falls back to the provided message when no detail', async () => {
    const fetcher = jest.fn().mockRejectedValue(new Error('boom'));
    const { result } = renderHook(() => useIAMResource(fetcher, 'fallback'));
    await waitFor(() => expect(result.current.error).toBe('fallback'));
  });

  it('refetches on demand', async () => {
    const fetcher = jest.fn().mockResolvedValue([]);
    const { result } = renderHook(() => useIAMResource(fetcher, 'failed'));
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await act(async () => {
      await result.current.refetch();
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('refetches when depKey changes', async () => {
    const fetcher = jest.fn().mockResolvedValue([]);
    const { rerender } = renderHook(
      ({ key }) => useIAMResource(fetcher, 'failed', key),
      { initialProps: { key: 'a' } },
    );
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
    rerender({ key: 'b' });
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
  });
});
