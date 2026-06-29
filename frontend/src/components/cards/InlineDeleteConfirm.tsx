import React from 'react';
import DeleteConfirmation, {
  DeleteConfirmationProps,
} from '../DeleteConfirmation';

/**
 * Wraps the shared DeleteConfirmation in the centered, full-height container
 * the cards use to swap their body for a confirm prompt. Cards render this in
 * place of their normal content while a delete is pending, so the prompt fills
 * the card footprint instead of overlaying it.
 */
const InlineDeleteConfirm: React.FC<DeleteConfirmationProps> = (props) => {
  return (
    <div className="p-5 h-full flex flex-col justify-center">
      <DeleteConfirmation {...props} />
    </div>
  );
};

export default InlineDeleteConfirm;
