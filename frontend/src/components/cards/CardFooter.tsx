import React from 'react';
import clsx from 'clsx';
import { ACCENTS, AccentToken } from '../../theme/accents';

interface CardFooterProps {
  /** Left-aligned content, typically one or more StatusDots + StatusDivider. */
  status: React.ReactNode;
  /** Right-aligned content: timestamp, refresh button, toggle switch, etc. */
  controls?: React.ReactNode;
  /** Accent token — tints the footer to match the card. Defaults to neutral. */
  accent?: AccentToken;
  className?: string;
}

/**
 * The bordered footer bar shared by every entity card. Holds status indicators
 * on the left and controls on the right. The pinned-to-bottom behavior (mt-auto)
 * lets footers line up across a grid row regardless of body height.
 *
 * The footer is tinted by the card's accent so all five entity types follow the
 * same rule (accent drives the footer); only the color differs by type.
 */
const CardFooter: React.FC<CardFooterProps> = ({
  status,
  controls,
  accent = 'neutral',
  className,
}) => {
  return (
    <div
      className={clsx(
        'mt-auto px-5 py-4 border-t rounded-b-2xl',
        ACCENTS[accent].footer,
        className,
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">{status}</div>
        {controls && <div className="flex items-center gap-3">{controls}</div>}
      </div>
    </div>
  );
};

export default CardFooter;
