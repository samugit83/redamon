'use client'

import { CopyButton } from '../CopyButton'
import { secretTail } from '@/lib/secrets/secretTail'
import styles from './SecretValue.module.css'

interface SecretValueProps {
  /** The full secret; only its last four characters are shown. */
  value: string | null | undefined
  /** A short word before the value, e.g. "secret" for the second half of a key pair. */
  label?: string
  /** What the cell shows when there is no value. */
  empty?: string
}

/**
 * A secret as its last four characters, with a button that copies all of it.
 * The tooltip gives the length, never the value, so a screenshot or a shared
 * screen shows no more than the four characters.
 */
export function SecretValue({ value, label, empty = '-' }: SecretValueProps) {
  const full = typeof value === 'string' ? value : value == null ? '' : String(value)
  if (!full) return <span className={styles.empty}>{empty}</span>
  return (
    <span className={styles.secret} data-secret-length={full.length}>
      {label && <span className={styles.label}>{label}</span>}
      <code className={styles.tail} title={`${full.length} characters; copy to get the full value`}>
        {secretTail(full)}
      </code>
      <CopyButton text={full} />
    </span>
  )
}
