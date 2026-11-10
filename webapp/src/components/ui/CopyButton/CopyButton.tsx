'use client'

import { useCallback, useEffect, useRef, useState, type MouseEvent } from 'react'
import { Check, Copy, X } from 'lucide-react'
import { copyText } from '@/lib/copyText'
import styles from './CopyButton.module.css'

interface CopyButtonProps {
  /** The full text copied; the button renders nothing when it is empty. */
  text: string | null | undefined
  /** Tooltip and accessible name. */
  title?: string
  className?: string
}

type Status = { text: string; ok: boolean } | null

/**
 * An icon button that copies `text`. The click never reaches the row behind
 * it (tables expand or select a row on click), a failed copy says so, and the
 * confirmation remembers WHICH text it confirms: a table keyed by index reuses
 * the cell for another row after a sort, and a bare flag would tick the wrong one.
 */
export function CopyButton({ text, title = 'Copy full value', className }: CopyButtonProps) {
  const [status, setStatus] = useState<Status>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current)
  }, [])

  const value = text ?? ''
  const copy = useCallback((e: MouseEvent) => {
    e.stopPropagation()
    if (!value) return
    const show = (ok: boolean) => {
      setStatus({ text: value, ok })
      if (timer.current) clearTimeout(timer.current)
      timer.current = setTimeout(() => setStatus(null), 1500)
    }
    copyText(value).then(() => show(true), () => show(false))
  }, [value])

  if (!value) return null
  const shown = status?.text === value ? status : null
  return (
    <button
      type="button"
      className={className ? `${styles.copyButton} ${className}` : styles.copyButton}
      onClick={copy}
      title={shown ? (shown.ok ? 'Copied' : 'Copy failed') : title}
      aria-label={shown ? (shown.ok ? 'Copied' : 'Copy failed') : title}
      data-copy-state={shown ? (shown.ok ? 'copied' : 'failed') : 'idle'}
    >
      {shown ? (shown.ok ? <Check size={12} /> : <X size={12} />) : <Copy size={12} />}
    </button>
  )
}
