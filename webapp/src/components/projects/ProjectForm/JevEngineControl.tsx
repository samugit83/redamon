'use client'

import { AlertTriangle } from 'lucide-react'
import type { JevProviderStatus } from '@/hooks/useHasJevProvider'
import styles from './JevEngineControl.module.css'

interface JevEngineControlProps {
  /** true = the hook runs on Jev; false = on the LLM in aiPipelineModel. */
  value: boolean
  /** Writes the specific *AiUseJev field. Each caller passes a literal field name. */
  onSelect: (useJev: boolean) => void
  /** Whether AI is active for this hook (aiInPipeline, and any per-hook flag). */
  enabled: boolean
  jevStatus: JevProviderStatus
  /** Why the control is disabled when `enabled` is false. Defaults to the master switch. */
  disabledHint?: string
  /**
   * `engine` (default): LLM | Jev on an LLM hook. `jevOnly`: Off | Jev on a hook
   * that has no LLM twin, where false means the step runs without AI.
   */
  variant?: 'engine' | 'jevOnly'
}

/**
 * The LLM | Jev engine switch under a recon AI hook, or the Off | Jev switch of
 * a Jev-only hook (`variant="jevOnly"`). Both follow the same rules.
 *
 * It never auto-resets a stored `true`: a project with no valid selected provider
 * keeps the choice (the hook falls back to its static list at scan time), and a
 * badge says so. Switching a disabled-but-selected Jev back to LLM is allowed.
 * The server (validateJevEngineChange) is the authority on a switch-on.
 */
export function JevEngineControl({
  value, onSelect, enabled, jevStatus, disabledHint, variant = 'engine',
}: JevEngineControlProps) {
  const jevOnly = variant === 'jevOnly'
  const noToken = jevStatus === 'no'
  const loading = jevStatus === 'loading'
  const error = jevStatus === 'error'

  // A failed lookup must not invite a switch-on without a validated selection.
  const jevButtonDisabled = !enabled || loading || (jevStatus !== 'yes' && !value)

  const jevTitle = !enabled
    ? disabledHint ?? 'Enable "AI in Pipeline" in the Target tab to choose an engine.'
    : loading
    ? 'Checking the project’s selected Jev provider…'
    : noToken
    ? 'Select a Jev provider in Target → AI in Pipeline. Manage configurations in Settings → LLM Providers.'
    : error
    ? 'The selected Jev provider could not be checked. Retry in the Target tab.'
    : jevOnly
    ? 'Run this hook on the project’s selected Jev provider.'
    : 'Answer this hook with the project’s selected Jev provider instead of the LLM.'

  return (
    <div className={styles.wrap}>
      <div className={styles.segmented} role="group" aria-label={jevOnly ? 'Jev hook' : 'AI engine'}>
        <button
          type="button"
          className={`${styles.option} ${!value ? styles.active : ''}`}
          aria-pressed={!value}
          disabled={!enabled}
          title={!enabled ? jevTitle
            : jevOnly ? 'Leave this hook off: the step runs without AI.'
            : 'Answer this hook with the LLM in the AI Model picker.'}
          onClick={() => onSelect(false)}
        >
          {jevOnly ? 'Off' : 'LLM'}
        </button>
        <button
          type="button"
          className={`${styles.option} ${value ? styles.active : ''}`}
          aria-pressed={value}
          disabled={jevButtonDisabled}
          title={jevTitle}
          onClick={() => onSelect(true)}
        >
          Jev
        </button>
      </div>
      {error && (
        <span className={styles.note} role="status">
          <AlertTriangle size={12} /> Couldn&apos;t check the selected Jev provider; failed calls use deterministic fallbacks
        </span>
      )}
      {value && noToken && (
        <span className={styles.badge}>
          No valid Jev selection: this hook uses its static fallback
        </span>
      )}
    </div>
  )
}
