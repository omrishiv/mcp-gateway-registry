import React, { useEffect } from 'react';
import { XMarkIcon } from '@heroicons/react/24/outline';
import {
  CustomEntityRecord,
  CustomTypeDescriptor,
} from '../types/customEntity';
import { labelFor } from '../utils/humanize';
import { formatValue } from './CustomEntityCard';

interface CustomEntityDetailProps {
  descriptor: CustomTypeDescriptor;
  record: CustomEntityRecord;
  onClose: () => void;
}

const CustomEntityDetail: React.FC<CustomEntityDetailProps> = ({
  descriptor,
  record,
  onClose,
}) => {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
      <div
        className="bg-white dark:bg-gray-800 rounded-xl shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] flex flex-col"
        role="dialog"
        aria-modal="true"
        aria-label={`${record.name} details`}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white truncate">
            {record.name}
          </h2>
          <button
            onClick={onClose}
            className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg transition-colors"
          >
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
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
      </div>
    </div>
  );
};

export default CustomEntityDetail;
