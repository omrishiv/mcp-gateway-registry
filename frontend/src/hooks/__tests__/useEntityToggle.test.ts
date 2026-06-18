import { renderHook, act } from '@testing-library/react';
import { useEntityToggle } from '../useEntityToggle';

interface Item {
  path: string;
  enabled: boolean;
}

describe('useEntityToggle', () => {
  const makeSetItems = () => {
    const items: Item[] = [
      { path: '/a', enabled: false },
      { path: '/b', enabled: true },
    ];
    const calls: Item[][] = [];
    const setItems = ((updater: any) => {
      const next = typeof updater === 'function' ? updater(items.slice()) : updater;
      calls.push(next);
    }) as React.Dispatch<React.SetStateAction<Item[]>>;
    return { setItems, calls };
  };

  it('optimistically flips the enabled flag then calls the API', async () => {
    const { setItems, calls } = makeSetItems();
    const apiCall = jest.fn().mockResolvedValue(undefined);
    const showToast = jest.fn();

    const { result } = renderHook(() =>
      useEntityToggle<Item>({
        setItems,
        enabledField: 'enabled',
        apiCall,
        label: 'Server',
        showToast,
      }),
    );

    await act(async () => {
      await result.current('/a', true);
    });

    // First setItems call is the optimistic update flipping /a to enabled.
    expect(calls[0].find((i) => i.path === '/a')?.enabled).toBe(true);
    expect(apiCall).toHaveBeenCalledWith('/a', true);
    expect(showToast).toHaveBeenCalledWith('Server enabled successfully!', 'success');
  });

  it('reverts and shows an error toast when the API call fails', async () => {
    const { setItems, calls } = makeSetItems();
    const apiCall = jest
      .fn()
      .mockRejectedValue({ response: { data: { detail: 'nope' } } });
    const showToast = jest.fn();

    const { result } = renderHook(() =>
      useEntityToggle<Item>({
        setItems,
        enabledField: 'enabled',
        apiCall,
        label: 'Skill',
        showToast,
      }),
    );

    await act(async () => {
      await result.current('/a', true);
    });

    // Two setItems calls: optimistic (true) then revert (false).
    expect(calls[0].find((i) => i.path === '/a')?.enabled).toBe(true);
    expect(calls[1].find((i) => i.path === '/a')?.enabled).toBe(false);
    expect(showToast).toHaveBeenCalledWith('nope', 'error');
  });

  it('respects a custom enabled field key', async () => {
    const items = [{ path: '/x', is_enabled: false }];
    const calls: any[] = [];
    const setItems = ((updater: any) => {
      calls.push(typeof updater === 'function' ? updater(items.slice()) : updater);
    }) as any;
    const apiCall = jest.fn().mockResolvedValue(undefined);

    const { result } = renderHook(() =>
      useEntityToggle<any>({
        setItems,
        enabledField: 'is_enabled',
        apiCall,
        label: 'Skill',
        showToast: jest.fn(),
      }),
    );

    await act(async () => {
      await result.current('/x', true);
    });

    expect(calls[0][0].is_enabled).toBe(true);
  });
});
