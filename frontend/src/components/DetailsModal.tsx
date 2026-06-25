import React from 'react';
import EntityModal, { ModalMaxWidth } from './modals/EntityModal';

interface DetailsModalProps {
  title: string;
  isOpen: boolean;
  onClose: () => void;
  loading?: boolean;
  error?: string | null;
  children: React.ReactNode;
  maxWidth?: ModalMaxWidth;
  /**
   * Tailwind z-index class for the backdrop. Default ``z-50`` is fine
   * for a top-level page modal. Pass ``z-[60]`` (or higher) when the
   * modal is rendered on top of another open modal — e.g. a duplicate
   * check that pre-flights from inside an open registration form.
   */
  zIndexClass?: string;
}

/**
 * Back-compat wrapper over the composable {@link EntityModal}.
 *
 * Existing callers (AgentDetailsModal, ServerDetailsModal, DuplicateCheckModal,
 * etc.) pass a plain string title and get the original padded layout, loading
 * spinner, and error panel. New modals should use EntityModal directly to get
 * the header-actions slot, node titles, and flush layout.
 */
const DetailsModal: React.FC<DetailsModalProps> = ({
  title,
  isOpen,
  onClose,
  loading = false,
  error = null,
  children,
  maxWidth = '4xl',
  zIndexClass = 'z-50',
}) => {
  return (
    <EntityModal
      title={title}
      isOpen={isOpen}
      onClose={onClose}
      loading={loading}
      error={error}
      maxWidth={maxWidth}
      zIndexClass={zIndexClass}
    >
      {children}
    </EntityModal>
  );
};

export default DetailsModal;
