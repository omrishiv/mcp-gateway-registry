import React from 'react';
import FormField from './FormField';
import { fieldClass, FIELD_FOCUS } from './formClasses';

export type LifecycleStatus = 'active' | 'draft' | 'deprecated' | 'beta';

interface StatusFieldProps {
  value: LifecycleStatus;
  onChange: (status: LifecycleStatus) => void;
  label?: string;
  accent?: keyof typeof FIELD_FOCUS;
}

/**
 * The lifecycle-status select (Active/Draft/Beta/Deprecated) shared by the
 * server, agent, and skill forms.
 */
const StatusField: React.FC<StatusFieldProps> = ({
  value,
  onChange,
  label = 'Lifecycle Status',
  accent = 'purple',
}) => {
  return (
    <FormField label={label}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value as LifecycleStatus)}
        className={fieldClass(accent)}
      >
        <option value="active">Active</option>
        <option value="draft">Draft</option>
        <option value="beta">Beta</option>
        <option value="deprecated">Deprecated</option>
      </select>
    </FormField>
  );
};

export default StatusField;
