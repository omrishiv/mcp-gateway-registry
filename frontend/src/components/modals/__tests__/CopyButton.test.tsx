import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import CopyButton from '../CopyButton';

describe('CopyButton', () => {
  it('renders the default label', () => {
    render(<CopyButton getText={() => 'x'} />);
    expect(screen.getByRole('button', { name: /Copy JSON/ })).toBeInTheDocument();
  });

  it('calls the onCopy delegate with the text', async () => {
    const onCopy = jest.fn().mockResolvedValue(undefined);
    render(<CopyButton getText={() => 'payload'} onCopy={onCopy} />);
    fireEvent.click(screen.getByRole('button'));
    await waitFor(() => expect(onCopy).toHaveBeenCalledWith('payload'));
  });

  it('shows the copied label after a successful copy', async () => {
    const onCopy = jest.fn().mockResolvedValue(undefined);
    render(<CopyButton getText={() => 'x'} onCopy={onCopy} />);
    fireEvent.click(screen.getByRole('button'));
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /Copied/ })).toBeInTheDocument(),
    );
  });

  it('falls back to navigator.clipboard when no delegate is given', async () => {
    const writeText = jest.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    render(<CopyButton getText={() => 'clip'} />);
    fireEvent.click(screen.getByRole('button'));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('clip'));
  });

  it('is inert when disabled', () => {
    const onCopy = jest.fn();
    render(<CopyButton getText={() => 'x'} onCopy={onCopy} disabled />);
    const btn = screen.getByRole('button');
    expect(btn).toBeDisabled();
  });
});
