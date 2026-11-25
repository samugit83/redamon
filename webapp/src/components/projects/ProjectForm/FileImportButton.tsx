'use client'

import { useRef, useState, useEffect } from 'react'
import { FileUp, Loader2, Check, AlertCircle } from 'lucide-react'
import { Tooltip } from '@/components/ui'
import styles from './ProjectForm.module.css'

interface FileImportButtonProps {
  /** Called with parsed, deduped, validated tokens from the imported file. */
  onImport: (values: string[]) => void
  /** Vertical alignment: 'input' centers inside a single-line input; 'textarea' pins to top-right. */
  variant?: 'input' | 'textarea'
  /** Optional per-token validator. Failing tokens are skipped (count surfaced in feedback). */
  validator?: (token: string) => boolean
  /** Field name used in the hover tooltip (e.g. "status codes"). */
  fieldName?: string
  /** File accept string. */
  accept?: string
  disabled?: boolean
}

const DELIMITER_RE = /[\n\r,;\t|]+/
const MAX_SIZE = 5 * 1024 * 1024

export function parseFileText(text: string): string[] {
  const noBom = text.replace(/^\uFEFF/, '')
  const cleaned = noBom
    .split(/\r?\n/)
    .filter(line => {
      const trimmed = line.trim()
      return trimmed && !trimmed.startsWith('#') && !trimmed.startsWith('//')
    })
    .join('\n')
  const tokens = cleaned
    .split(DELIMITER_RE)
    .map(s => s.trim())
    .filter(Boolean)
  return Array.from(new Set(tokens))
}

export function FileImportButton({
  onImport,
  variant = 'input',
  validator,
  fieldName,
  accept = '.txt,.csv,.list,.lst,text/plain,text/csv',
  disabled = false,
}: FileImportButtonProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const flashTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [status, setStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle')
  const [statusText, setStatusText] = useState<string>('')

  // Clear any pending status-reset timer on unmount or before scheduling a new one.
  useEffect(() => {
    return () => {
      if (flashTimerRef.current) clearTimeout(flashTimerRef.current)
    }
  }, [])

  const flash = (s: 'success' | 'error', text: string, ms = 2500) => {
    if (flashTimerRef.current) clearTimeout(flashTimerRef.current)
    setStatus(s)
    setStatusText(text)
    flashTimerRef.current = setTimeout(() => {
      setStatus('idle')
      flashTimerRef.current = null
    }, ms)
  }

  const handleFile = async (file: File) => {
    setStatus('loading')
    try {
      if (file.size > MAX_SIZE) {
        flash('error', 'File too large (max 5MB)', 3000)
        return
      }
      const text = await file.text()
      let tokens = parseFileText(text)
      let skipped = 0
      if (validator) {
        const original = tokens.length
        tokens = tokens.filter(validator)
        skipped = original - tokens.length
      }
      if (tokens.length === 0) {
        flash('error', 'No values found in file', 3000)
        return
      }
      onImport(tokens)
      flash(
        'success',
        skipped > 0 ? `Imported ${tokens.length} (skipped ${skipped})` : `Imported ${tokens.length}`,
      )
    } catch {
      flash('error', 'Failed to read file', 3000)
    }
  }

  const tooltipContent = (
    <div className={styles.fileImportTooltip}>
      <strong className={styles.fileImportTooltipTitle}>Import from text file</strong>
      <span className={styles.fileImportTooltipBody}>
        {fieldName ? `Load ${fieldName} from a .txt or .csv file.` : 'Load values from a .txt or .csv file.'}
      </span>
      <div className={styles.fileImportTooltipSection}>
        <span className={styles.fileImportTooltipLabel}>Supported delimiters:</span>
        <ul className={styles.fileImportTooltipList}>
          <li>newlines</li>
          <li>commas <code>,</code></li>
          <li>semicolons <code>;</code></li>
          <li>tabs</li>
          <li>pipes <code>|</code></li>
        </ul>
      </div>
      <div className={styles.fileImportTooltipFooter}>
        Lines starting with <code>#</code> or <code>{'//'}</code> are ignored. Duplicates are removed.
      </div>
    </div>
  )

  const Icon =
    status === 'loading' ? Loader2 : status === 'success' ? Check : status === 'error' ? AlertCircle : FileUp

  const buttonClass = `${styles.fileImportButton} ${
    variant === 'textarea' ? styles.fileImportButtonTextareaPos : styles.fileImportButtonInputPos
  } ${status === 'success' ? styles.fileImportButtonSuccess : ''} ${
    status === 'error' ? styles.fileImportButtonError : ''
  }`

  return (
    <>
      <input
        ref={fileInputRef}
        type="file"
        accept={accept}
        style={{ display: 'none' }}
        onChange={e => {
          const file = e.target.files?.[0]
          if (file) handleFile(file)
          if (fileInputRef.current) fileInputRef.current.value = ''
        }}
      />
      <Tooltip content={status === 'idle' ? tooltipContent : statusText} position="left" delay={150} maxWidth={300}>
        <button
          type="button"
          className={buttonClass}
          onClick={() => !disabled && fileInputRef.current?.click()}
          disabled={disabled || status === 'loading'}
          aria-label="Import values from text file"
        >
          <Icon size={14} className={status === 'loading' ? styles.spinner : undefined} />
        </button>
      </Tooltip>
    </>
  )
}
