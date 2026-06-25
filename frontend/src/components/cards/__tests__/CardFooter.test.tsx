import React from 'react';
import { render, screen } from '@testing-library/react';
import CardFooter from '../CardFooter';

describe('CardFooter', () => {
  it('renders the status slot', () => {
    render(<CardFooter status={<span>Enabled</span>} />);
    expect(screen.getByText('Enabled')).toBeInTheDocument();
  });

  it('renders the controls slot when provided', () => {
    render(
      <CardFooter
        status={<span>Enabled</span>}
        controls={<button>Toggle</button>}
      />,
    );
    expect(screen.getByRole('button', { name: 'Toggle' })).toBeInTheDocument();
  });

  it('omits the controls container when no controls are passed', () => {
    const { container } = render(<CardFooter status={<span>Enabled</span>} />);
    // Only the status flex container should exist inside the justify-between row.
    const row = container.querySelector('.justify-between');
    expect(row?.children.length).toBe(1);
  });
});
