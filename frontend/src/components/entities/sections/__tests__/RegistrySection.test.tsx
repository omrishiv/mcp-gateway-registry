import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import RegistrySection, { RegistryAccent } from '../RegistrySection';

const accent: RegistryAccent = {
  headerBg: 'header-bg',
  title: 'title-color',
  resyncButton: 'resync-btn',
  border: 'border-x',
};

interface Item {
  path: string;
  name: string;
}

const items: Item[] = [
  { path: '/a', name: 'Alpha' },
  { path: '/b', name: 'Beta' },
];
const renderCard = (item: Item) => <div key={item.path}>{item.name}</div>;

describe('RegistrySection', () => {
  it('renders just the grid (no header) when showHeader is false', () => {
    render(
      <RegistrySection
        registryId="local"
        domId="server-registry-local"
        items={items}
        expanded
        onToggle={() => {}}
        renderCard={renderCard}
        showHeader={false}
        countLabel="2 servers"
        displayName="Local Registry"
        accent={accent}
      />,
    );
    expect(screen.getByText('Alpha')).toBeInTheDocument();
    expect(screen.queryByText('Local Registry')).not.toBeInTheDocument();
  });

  it('renders the collapsible header with name and count when showHeader is true', () => {
    render(
      <RegistrySection
        registryId="peer-registry-x"
        domId="server-registry-peer-registry-x"
        items={items}
        expanded
        onToggle={() => {}}
        renderCard={renderCard}
        showHeader
        countLabel="2 servers"
        displayName="X (Federated)"
        accent={accent}
      />,
    );
    expect(screen.getByText('X (Federated)')).toBeInTheDocument();
    expect(screen.getByText('2 servers')).toBeInTheDocument();
    expect(screen.getByText('Alpha')).toBeInTheDocument();
  });

  it('hides the grid when collapsed', () => {
    render(
      <RegistrySection
        registryId="local"
        domId="d"
        items={items}
        expanded={false}
        onToggle={() => {}}
        renderCard={renderCard}
        showHeader
        countLabel="2 servers"
        displayName="Local Registry"
        accent={accent}
      />,
    );
    expect(screen.getByText('Local Registry')).toBeInTheDocument();
    expect(screen.queryByText('Alpha')).not.toBeInTheDocument();
  });

  it('calls onToggle when the header is clicked', () => {
    const onToggle = jest.fn();
    render(
      <RegistrySection
        registryId="local"
        domId="d"
        items={items}
        expanded
        onToggle={onToggle}
        renderCard={renderCard}
        showHeader
        countLabel="2 servers"
        displayName="Local Registry"
        accent={accent}
      />,
    );
    fireEvent.click(screen.getByText('Local Registry'));
    expect(onToggle).toHaveBeenCalled();
  });

  it('shows a resync button for federated registries only', () => {
    const onResync = jest.fn();
    const { rerender } = render(
      <RegistrySection
        registryId="peer-registry-x"
        domId="d"
        items={items}
        expanded
        onToggle={() => {}}
        renderCard={renderCard}
        showHeader
        countLabel="2 servers"
        displayName="X (Federated)"
        accent={accent}
        onResync={onResync}
        endpointUrl="https://peer.example"
      />,
    );
    const resync = screen.getByTitle(/Resync from/);
    fireEvent.click(resync);
    expect(onResync).toHaveBeenCalled();

    // Local registry: no resync button even if a handler is passed.
    rerender(
      <RegistrySection
        registryId="local"
        domId="d"
        items={items}
        expanded
        onToggle={() => {}}
        renderCard={renderCard}
        showHeader
        countLabel="2 servers"
        displayName="Local Registry"
        accent={accent}
        onResync={onResync}
      />,
    );
    expect(screen.queryByTitle(/Resync from/)).not.toBeInTheDocument();
  });

  it('appends extra cards after the item cards', () => {
    render(
      <RegistrySection
        registryId="local"
        domId="d"
        items={items}
        expanded
        onToggle={() => {}}
        renderCard={renderCard}
        showHeader={false}
        countLabel="2 servers"
        displayName="Local Registry"
        accent={accent}
        extraCards={<div>VirtualCard</div>}
      />,
    );
    expect(screen.getByText('VirtualCard')).toBeInTheDocument();
  });
});
