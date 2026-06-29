import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import EntityModal from '../EntityModal';

describe('EntityModal', () => {
  it('renders nothing when closed', () => {
    const { container } = render(
      <EntityModal isOpen={false} onClose={() => {}} title="Hidden">
        <p>body</p>
      </EntityModal>,
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders a string title and body when open', () => {
    render(
      <EntityModal isOpen onClose={() => {}} title="My Title">
        <p>body content</p>
      </EntityModal>,
    );
    expect(screen.getByText('My Title')).toBeInTheDocument();
    expect(screen.getByText('body content')).toBeInTheDocument();
  });

  it('renders a node title and header actions', () => {
    render(
      <EntityModal
        isOpen
        onClose={() => {}}
        title={<span>Rich Title</span>}
        headerActions={<button>Copy</button>}
      >
        <p>body</p>
      </EntityModal>,
    );
    expect(screen.getByText('Rich Title')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy' })).toBeInTheDocument();
  });

  it('calls onClose when the close button is clicked', () => {
    const onClose = jest.fn();
    render(
      <EntityModal isOpen onClose={onClose} title="X">
        <p>body</p>
      </EntityModal>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('calls onClose on Escape', () => {
    const onClose = jest.fn();
    render(
      <EntityModal isOpen onClose={onClose} title="X">
        <p>body</p>
      </EntityModal>,
    );
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });

  it('shows the loading state and hides children', () => {
    render(
      <EntityModal isOpen onClose={() => {}} title="X" loading>
        <p>body content</p>
      </EntityModal>,
    );
    expect(screen.getByText('Loading details...')).toBeInTheDocument();
    expect(screen.queryByText('body content')).not.toBeInTheDocument();
  });

  it('shows the error state and hides children', () => {
    render(
      <EntityModal isOpen onClose={() => {}} title="X" error="boom">
        <p>body content</p>
      </EntityModal>,
    );
    expect(screen.getByText('Error Loading Details')).toBeInTheDocument();
    expect(screen.getByText('boom')).toBeInTheDocument();
    expect(screen.queryByText('body content')).not.toBeInTheDocument();
  });
});
