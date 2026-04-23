'use client'

import { useId, useCallback, KeyboardEvent } from 'react'
import styles from './Toggle.module.css'

interface ToggleProps {
  /** Whether the toggle is checked */
  checked: boolean
  /** Callback when toggle state changes */
  onChange: (checked: boolean) => void
  /** Label for the "off" state (left side) */
  labelOff?: string
  /** Label for the "on" state (right side) */
  labelOn?: string
  /** Disable the toggle */
  disabled?: boolean
  /** Accessible label for screen readers */
  'aria-label'?: string
  /** Size variant */
  size?: 'small' | 'default' | 'large'
  /** Additional className for the container */
  className?: string
}

export function Toggle({
  checked,
  onChange,
  labelOff,
  labelOn,
  disabled = false,
  'aria-label': ariaLabel,
  size = 'default',
  className,
}: ToggleProps) {
  const id = useId()

  const handleClick = useCallback(() => {
    if (!disabled) {
      onChange(!checked)
    }
  }, [disabled, checked, onChange])

  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLButtonElement>) => {
      if (disabled) return

      if (e.key === ' ' || e.key === 'Enter') {
        e.preventDefault()
        onChange(!checked)
      }
    },
    [disabled, checked, onChange]
  )

  const containerClasses = [
    styles.container,
    size === 'small' && styles.containerSmall,
    size === 'large' && styles.containerLarge,
    className,
  ]
    .filter(Boolean)
    .join(' ')

  const switchClasses = [
    styles.switch,
    size === 'small' && styles.switchSmall,
    size === 'large' && styles.switchLarge,
    disabled && styles.switchDisabled,
  ]
    .filter(Boolean)
    .join(' ')

  const knobClasses = [
    styles.knob,
    size === 'small' && styles.knobSmall,
    size === 'large' && styles.knobLarge,
    checked && styles.knobActive,
  ]
    .filter(Boolean)
    .join(' ')

  return (
    <div className={containerClasses}>
      {labelOff && (
        <span
          className={`${styles.label} ${!checked ? styles.labelActive : ''}`}
          onClick={handleClick}
        >
          {labelOff}
        </span>
      )}

      <button
        id={id}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={ariaLabel}
        disabled={disabled}
        className={switchClasses}
        onClick={handleClick}
        onKeyDown={handleKeyDown}
      >
        <span className={knobClasses} />
      </button>

      {labelOn && (
        <span
          className={`${styles.label} ${checked ? styles.labelActive : ''}`}
          onClick={handleClick}
        >
          {labelOn}
        </span>
      )}
    </div>
  )
}
