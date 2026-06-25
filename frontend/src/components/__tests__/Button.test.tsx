import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import Button from '../Button';

describe('Button', () => {
  it('renders its label', () => {
    render(<Button>Save</Button>);
    expect(screen.getByRole('button', { name: 'Save' })).toBeInTheDocument();
  });

  it('defaults to type="button" so it does not submit forms by accident', () => {
    render(<Button>Cancel</Button>);
    expect(screen.getByRole('button')).toHaveAttribute('type', 'button');
  });

  it('applies the variant class', () => {
    const { rerender } = render(<Button variant="primary">P</Button>);
    expect(screen.getByRole('button').className).toContain('btn-primary');
    rerender(<Button variant="danger">D</Button>);
    expect(screen.getByRole('button').className).toContain('btn-danger');
    rerender(<Button variant="ghost">G</Button>);
    expect(screen.getByRole('button').className).toContain('btn-ghost');
  });

  it('defaults to the secondary variant', () => {
    render(<Button>X</Button>);
    expect(screen.getByRole('button').className).toContain('btn-secondary');
  });

  it('fires onClick', () => {
    const onClick = jest.fn();
    render(<Button onClick={onClick}>Go</Button>);
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).toHaveBeenCalled();
  });

  it('forwards disabled', () => {
    render(<Button disabled>Off</Button>);
    expect(screen.getByRole('button')).toBeDisabled();
  });

  it('renders a leading icon and supports fullWidth + a submit type', () => {
    render(
      <Button type="submit" fullWidth leadingIcon={<svg data-testid="icon" />}>
        Submit
      </Button>,
    );
    const btn = screen.getByRole('button', { name: 'Submit' });
    expect(btn).toHaveAttribute('type', 'submit');
    expect(btn.className).toContain('w-full');
    expect(screen.getByTestId('icon')).toBeInTheDocument();
  });
});
