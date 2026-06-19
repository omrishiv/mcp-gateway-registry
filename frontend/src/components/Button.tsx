import React from 'react';
import clsx from 'clsx';

export type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';
export type ButtonSize = 'sm' | 'md';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Icon rendered before the label. */
  leadingIcon?: React.ReactNode;
  /** Stretch to fill the container width. */
  fullWidth?: boolean;
}

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  danger: 'btn-danger',
  ghost: 'btn-ghost',
};

// Size tweaks layered over the .btn-base padding (px-4 py-2 = md default).
const SIZE_CLASS: Record<ButtonSize, string> = {
  sm: 'text-sm px-3 py-1.5 gap-1.5',
  md: 'text-sm gap-2',
};

/**
 * Shared button. Color/hover come from the .btn-* component classes, which read
 * the semantic interaction tokens in index.css — so contrast and theme changes
 * live in ONE place (per mode) instead of being hand-rolled inline per call
 * site. This is what prevents "change the hover color in 23 files" again.
 *
 * `type` defaults to "button" so buttons inside forms don't submit by accident.
 */
const Button: React.FC<ButtonProps> = ({
  variant = 'secondary',
  size = 'md',
  leadingIcon,
  fullWidth = false,
  type = 'button',
  className,
  children,
  ...rest
}) => {
  return (
    <button
      type={type}
      className={clsx(
        VARIANT_CLASS[variant],
        SIZE_CLASS[size],
        fullWidth && 'w-full',
        className,
      )}
      {...rest}
    >
      {leadingIcon}
      {children}
    </button>
  );
};

export default Button;
