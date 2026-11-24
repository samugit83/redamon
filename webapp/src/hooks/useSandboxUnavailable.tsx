'use client'

/**
 * The modal of a Kali sandbox that cannot start, for the chat drawer and the
 * terminal (group 1, B.13). It reads a `sandbox_status` payload whose state is
 * `unavailable` and shows, through useAlertModal:
 *
 * - `ram`: "Not enough memory", the governor's figures in GB, Retry and Close;
 * - `hard`: "Sandbox limit reached", the count and its setting, Retry and Close;
 * - `refused`: the person may not use the sandbox on this project, no Retry;
 * - `error`, `stopped` (or no known reason): a start that failed or a sandbox
 *   that stopped, Retry and Close.
 *
 * The figures are the instance's totals (pool, reserved, free, count), never
 * another person's sandbox. The caller decides what Retry does.
 */
import { useCallback } from 'react'
import { useAlertModal } from '@/components/ui'
import { toGB } from '@/hooks/useSystemStats'
import {
  MODAL_CLOSE_LABEL,
  MODAL_HARD_BODY,
  MODAL_HARD_TITLE,
  MODAL_RAM_BODY,
  MODAL_RAM_TITLE,
  MODAL_REFUSED_BODY,
  MODAL_REFUSED_TITLE,
  MODAL_RETRY_LABEL,
} from '@/lib/sandbox/contract'

export type SandboxModalAnswer = 'retry' | 'close'

export const MODAL_ERROR_TITLE = 'Kali sandbox could not start'
export const MODAL_ERROR_BODY =
  'Your Kali sandbox could not start. Retry in a moment; if it keeps failing, ask an administrator to check the orchestrator.'
export const MODAL_STOPPED_TITLE = 'Kali sandbox stopped'
export const MODAL_STOPPED_BODY =
  'Your Kali sandbox stopped while it was in use. Retry to start it again.'

export interface SandboxModalContent {
  title: string
  body: string
  /** The governor's figures, one line, or null when the payload carries none usable. */
  figures: string | null
  retry: boolean
}

const DETAIL_MAX = 120

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : null
}

function amount(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null
}

/** The governor's fixed detail as one short sentence start, or '' (it is shown, so it is bounded). */
function detailText(value: unknown): string {
  if (typeof value !== 'string') return ''
  const clean = value.replace(/\s+/g, ' ').trim().slice(0, DETAIL_MAX)
  return clean ? clean[0].toUpperCase() + clean.slice(1) : ''
}

/** Figures only from a limit of the reason's own kind, so a payload never mixes them. */
function figuresFor(reason: 'ram' | 'hard', limitValue: unknown): string | null {
  const limit = record(limitValue)
  if (!limit || limit.limitType !== reason) return null
  const current = amount(limit.current)
  const ceiling = amount(limit.ceiling)
  if (current === null || ceiling === null) return null
  const detail = detailText(limit.detail)
  if (reason === 'ram') return `${detail || 'Memory'} (${toGB(current)} GB of ${toGB(ceiling)} GB).`
  const count = detail || `${Math.round(current)} of ${Math.round(ceiling)} Kali sandboxes allowed`
  const setting = typeof limit.settingName === 'string' && /^[A-Za-z0-9_]{1,64}$/.test(limit.settingName)
    ? ` Set by ${limit.settingName}.`
    : ''
  return `${count}.${setting}`
}

/** What the modal says for a `sandbox_status` payload, or null unless its state is `unavailable`. */
export function sandboxModalContent(payload: unknown): SandboxModalContent | null {
  const p = record(payload)
  if (!p || p.state !== 'unavailable') return null
  switch (p.reason) {
    case 'ram':
      return { title: MODAL_RAM_TITLE, body: MODAL_RAM_BODY, figures: figuresFor('ram', p.limit), retry: true }
    case 'hard':
      return { title: MODAL_HARD_TITLE, body: MODAL_HARD_BODY, figures: figuresFor('hard', p.limit), retry: true }
    case 'refused':
      return { title: MODAL_REFUSED_TITLE, body: MODAL_REFUSED_BODY, figures: null, retry: false }
    case 'stopped':
      return { title: MODAL_STOPPED_TITLE, body: MODAL_STOPPED_BODY, figures: null, retry: true }
    default:
      // `error`, or a reason this webapp does not know: the agent's own detail can
      // carry internal text, so none is shown.
      return { title: MODAL_ERROR_TITLE, body: MODAL_ERROR_BODY, figures: null, retry: true }
  }
}

/**
 * Returns `show(payload)`: it opens the modal and resolves with the person's
 * choice (`close` at once for a payload that is not `unavailable`).
 */
export function useSandboxUnavailable(): (payload: unknown) => Promise<SandboxModalAnswer> {
  const { confirm, alertError } = useAlertModal()
  return useCallback(async (payload: unknown): Promise<SandboxModalAnswer> => {
    const content = sandboxModalContent(payload)
    if (!content) return 'close'
    if (!content.retry) {
      await alertError(content.body, content.title)
      return 'close'
    }
    const retry = await confirm(
      <span>
        {content.body}
        {content.figures && (<><br /><br />{content.figures}</>)}
      </span>,
      content.title,
      { confirmLabel: MODAL_RETRY_LABEL, cancelLabel: MODAL_CLOSE_LABEL },
    )
    return retry ? 'retry' : 'close'
  }, [confirm, alertError])
}
