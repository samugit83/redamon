import type { ShareToggles } from '@/lib/authz/adminShares'

/**
 * How the console names a share's level (§6.1): Read or Read + Write, then the toggles it carries.
 * Pure, so the projects page's inline list and the Shares page say it the same way.
 */
const TOGGLE_WORDS: ReadonlyArray<[keyof ShareToggles, string]> = [
  ['rawData', 'Raw data'],
  ['runScans', 'Run scans'],
  ['useAgent', 'Use the agent'],
  ['exploit', 'Exploitation & shells'],
  ['manage', 'Manage (co-owner)'],
]

export function shareLevelLabel(access: string, toggles: ShareToggles): string {
  const level = access === 'write' ? 'Read + Write' : access === 'read' ? 'Read' : `Unknown level (${access})`
  const on = TOGGLE_WORDS.filter(([key]) => toggles[key]).map(([, words]) => words)
  return on.length ? `${level} · ${on.join(', ')}` : level
}

/** A date and time as the console shows them, or the fallback when there is none. */
export function whenLabel(iso: string | null, fallback: string): string {
  const when = iso ? new Date(iso) : null
  if (!when || Number.isNaN(when.getTime())) return fallback
  return when.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
