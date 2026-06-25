import React from 'react';
import {
  CustomEntityRecord,
  CustomTypeDescriptor,
} from '../types/customEntity';
import { labelFor } from '../utils/humanize';
import { formatValue } from './CustomEntityCard';
import { EntityModal, CopyButton } from './modals';

interface CustomEntityDetailProps {
  descriptor: CustomTypeDescriptor;
  record: CustomEntityRecord;
  onClose: () => void;
}

/**
 * Read-only detail view for a custom entity record. Composes the shared
 * EntityModal (flush layout) and CopyButton; the body is the descriptor-driven
 * envelope + per-type attribute definition lists, which is this view's
 * entity-specific content.
 *
 * Mounted conditionally by the parent (no isOpen prop), so it passes isOpen
 * permanently true to the modal shell.
 */
const CustomEntityDetail: React.FC<CustomEntityDetailProps> = ({
  descriptor,
  record,
  onClose,
}) => {
  return (
    <EntityModal
      isOpen
      onClose={onClose}
      maxWidth="2xl"
      layout="flush"
      title={
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white truncate">
          {record.name}
        </h2>
      }
      headerActions={
        <CopyButton
          variant="subtle"
          label="Copy JSON"
          // Copy the full record exactly as stored (envelope + attributes +
          // path/timestamps/ratings), pretty-printed.
          getText={() => JSON.stringify(record, null, 2)}
          title="Copy the full record JSON as stored"
        />
      }
    >
      <div className="space-y-6">
        {/* --- Envelope --- */}
        <dl className="grid grid-cols-3 gap-x-4 gap-y-2 text-sm">
          <dt className="text-gray-500 dark:text-gray-400">Visibility</dt>
          <dd className="col-span-2 text-gray-900 dark:text-white">{record.visibility}</dd>

          {record.visibility === 'group-restricted' && (
            <>
              <dt className="text-gray-500 dark:text-gray-400">Allowed Groups</dt>
              <dd className="col-span-2 text-gray-900 dark:text-white">
                {record.allowed_groups.length > 0 ? record.allowed_groups.join(', ') : '—'}
              </dd>
            </>
          )}

          <dt className="text-gray-500 dark:text-gray-400">Owner</dt>
          <dd className="col-span-2 text-gray-900 dark:text-white">{record.owner || '—'}</dd>

          {record.description && (
            <>
              <dt className="text-gray-500 dark:text-gray-400">Description</dt>
              <dd className="col-span-2 text-gray-900 dark:text-white whitespace-pre-wrap">
                {record.description}
              </dd>
            </>
          )}

          <dt className="text-gray-500 dark:text-gray-400">Tags</dt>
          <dd className="col-span-2 text-gray-900 dark:text-white">
            {record.tags.length > 0 ? record.tags.join(', ') : '—'}
          </dd>
        </dl>

        {/* --- Per-type attributes --- */}
        {descriptor.fields.length > 0 && (
          <dl className="grid grid-cols-3 gap-x-4 gap-y-2 text-sm pt-2 border-t border-gray-200 dark:border-gray-700">
            {descriptor.fields.map((field) => (
              <React.Fragment key={field.name}>
                <dt className="text-gray-500 dark:text-gray-400">{labelFor(field)}</dt>
                <dd className="col-span-2 text-gray-900 dark:text-white whitespace-pre-wrap">
                  {formatValue(field, record.attributes[field.name])}
                </dd>
              </React.Fragment>
            ))}
          </dl>
        )}
      </div>
    </EntityModal>
  );
};

export default CustomEntityDetail;
