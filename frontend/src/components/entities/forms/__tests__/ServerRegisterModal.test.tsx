import React, { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ServerRegisterModal, { ServerRegisterForm } from '../ServerRegisterModal';

const baseForm: ServerRegisterForm = {
  name: '',
  path: '',
  proxyPass: '',
  description: '',
  official: false,
  tags: [],
};

function Harness({
  loading = false,
  onSubmit = jest.fn((e: React.FormEvent) => e.preventDefault()),
  onClose = jest.fn(),
}: {
  loading?: boolean;
  onSubmit?: (e: React.FormEvent) => void;
  onClose?: () => void;
}) {
  const [form, setForm] = useState<ServerRegisterForm>(baseForm);
  return (
    <ServerRegisterModal
      form={form}
      setForm={setForm}
      loading={loading}
      onSubmit={onSubmit}
      onClose={onClose}
    />
  );
}

describe('ServerRegisterModal', () => {
  it('renders the register title and required fields', () => {
    render(<Harness />);
    expect(screen.getByText('Register New Server')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('e.g., My Custom Server')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('/my-server')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('http://localhost:8080')).toBeInTheDocument();
  });

  it('edits a controlled field', () => {
    render(<Harness />);
    const name = screen.getByPlaceholderText('e.g., My Custom Server');
    fireEvent.change(name, { target: { value: 'My Server' } });
    expect(screen.getByDisplayValue('My Server')).toBeInTheDocument();
  });

  it('calls onSubmit when the form is submitted', () => {
    const onSubmit = jest.fn((e: React.FormEvent) => e.preventDefault());
    const { container } = render(<Harness onSubmit={onSubmit} />);
    fireEvent.submit(container.querySelector('form')!);
    expect(onSubmit).toHaveBeenCalled();
  });

  it('calls onClose from cancel', () => {
    const onClose = jest.fn();
    render(<Harness onClose={onClose} />);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalled();
  });

  it('disables submit and shows Registering while loading', () => {
    render(<Harness loading />);
    expect(screen.getByRole('button', { name: 'Registering...' })).toBeDisabled();
  });
});
