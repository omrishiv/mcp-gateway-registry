import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ThemeToggle from '../ThemeToggle';
import { ThemeProvider } from '../../contexts/ThemeContext';

const renderToggle = () =>
  render(
    <ThemeProvider>
      <ThemeToggle />
    </ThemeProvider>,
  );

describe('ThemeToggle', () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.className = '';
    delete (window as any).matchMedia;
  });

  it('shows the "switch to light" control in dark mode', () => {
    // No matchMedia -> defaults to dark.
    renderToggle();
    expect(
      screen.getByRole('button', { name: 'Switch to light mode' }),
    ).toBeInTheDocument();
  });

  it('flips mode and label when clicked', () => {
    renderToggle();
    const button = screen.getByRole('button', { name: 'Switch to light mode' });
    fireEvent.click(button);

    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(localStorage.getItem('theme')).toBe('light');
    expect(
      screen.getByRole('button', { name: 'Switch to dark mode' }),
    ).toBeInTheDocument();
  });
});
