import React from 'react';
import { render, screen } from '@testing-library/react';
import EntityGrid from '../EntityGrid';

describe('EntityGrid', () => {
  it('renders its children', () => {
    render(
      <EntityGrid>
        <div>card-a</div>
        <div>card-b</div>
      </EntityGrid>,
    );
    expect(screen.getByText('card-a')).toBeInTheDocument();
    expect(screen.getByText('card-b')).toBeInTheDocument();
  });

  it('applies the responsive grid template and extra classes', () => {
    const { container } = render(
      <EntityGrid className="pb-12">
        <div>x</div>
      </EntityGrid>,
    );
    const grid = container.firstChild as HTMLElement;
    expect(grid.className).toContain('grid');
    expect(grid.className).toContain('pb-12');
    expect(grid.style.gridTemplateColumns).toContain('minmax(380px, 1fr)');
  });
});
