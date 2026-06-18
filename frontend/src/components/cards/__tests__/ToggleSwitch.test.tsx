import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ToggleSwitch from '../ToggleSwitch';

describe('ToggleSwitch', () => {
  it('reflects the checked state', () => {
    render(
      <ToggleSwitch checked onChange={() => {}} ariaLabel="Enable widget" />,
    );
    expect(screen.getByRole('checkbox', { name: 'Enable widget' })).toBeChecked();
  });

  it('calls onChange with the new value when toggled on', () => {
    const onChange = jest.fn();
    render(
      <ToggleSwitch checked={false} onChange={onChange} ariaLabel="Enable widget" />,
    );
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable widget' }));
    expect(onChange).toHaveBeenCalledWith(true);
  });

  it('calls onChange with false when toggled off', () => {
    const onChange = jest.fn();
    render(
      <ToggleSwitch checked onChange={onChange} ariaLabel="Enable widget" />,
    );
    fireEvent.click(screen.getByRole('checkbox', { name: 'Enable widget' }));
    expect(onChange).toHaveBeenCalledWith(false);
  });

  it('marks the input disabled so the browser suppresses interaction', () => {
    const onChange = jest.fn();
    render(
      <ToggleSwitch
        checked={false}
        onChange={onChange}
        ariaLabel="Enable widget"
        disabled
      />,
    );
    expect(screen.getByRole('checkbox', { name: 'Enable widget' })).toBeDisabled();
  });
});
