import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import CustomEntityForm from '../CustomEntityForm';
import type { CustomTypeDescriptor } from '../../types/customEntity';

const descriptor: CustomTypeDescriptor = {
  name: 'dataset',
  display_name: 'Dataset',
  fields: [
    { name: 'owner', datatype: 'string', required: true } as any,
    { name: 'rows', datatype: 'number', required: false } as any,
  ],
} as CustomTypeDescriptor;

describe('CustomEntityForm', () => {
  it('renders create title and envelope + attribute fields', () => {
    render(
      <CustomEntityForm descriptor={descriptor} onSave={jest.fn()} onCancel={jest.fn()} />,
    );
    expect(screen.getByText('Create Dataset')).toBeInTheDocument();
    expect(screen.getByText(/Name/)).toBeInTheDocument();
    expect(screen.getByText(/Owner/)).toBeInTheDocument();
    expect(screen.getByText(/Rows/)).toBeInTheDocument();
  });

  it('shows edit title when a record is supplied', () => {
    render(
      <CustomEntityForm
        descriptor={descriptor}
        record={
          {
            name: 'ds1',
            description: '',
            visibility: 'private',
            allowed_groups: [],
            tags: [],
            attributes: {},
          } as any
        }
        onSave={jest.fn()}
        onCancel={jest.fn()}
      />,
    );
    expect(screen.getByText('Edit Dataset')).toBeInTheDocument();
    expect(screen.getByDisplayValue('ds1')).toBeInTheDocument();
  });

  it('validates that name is required before saving', async () => {
    const onSave = jest.fn();
    render(
      <CustomEntityForm descriptor={descriptor} onSave={onSave} onCancel={jest.fn()} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(screen.getByText('Name is required')).toBeInTheDocument());
    expect(onSave).not.toHaveBeenCalled();
  });

  it('reveals the allowed-groups chip input for group-restricted visibility', () => {
    render(
      <CustomEntityForm descriptor={descriptor} onSave={jest.fn()} onCancel={jest.fn()} />,
    );
    expect(screen.queryByText(/Allowed Groups/)).not.toBeInTheDocument();
    fireEvent.change(screen.getByDisplayValue('private'), {
      target: { value: 'group-restricted' },
    });
    expect(screen.getByText(/Allowed Groups/)).toBeInTheDocument();
  });

  it('submits a valid payload', async () => {
    const onSave = jest.fn().mockResolvedValue(undefined);
    render(
      <CustomEntityForm descriptor={descriptor} onSave={onSave} onCancel={jest.fn()} />,
    );
    // Name is the first text input in the envelope.
    const nameInput = screen.getAllByRole('textbox')[0];
    fireEvent.change(nameInput, { target: { value: 'my-dataset' } });
    fireEvent.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'my-dataset', visibility: 'private' }),
      ),
    );
  });

  it('calls onCancel from the cancel button', () => {
    const onCancel = jest.fn();
    render(
      <CustomEntityForm descriptor={descriptor} onSave={jest.fn()} onCancel={onCancel} />,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalled();
  });
});
