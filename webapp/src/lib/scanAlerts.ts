/**
 * Scheduled-scan alerts (help-wanted: real-time alerts via Slack / webhook).
 *
 * Slack incoming webhooks and generic JSON webhooks need no new dependency —
 * both are a single HTTPS POST. Email is deliberately NOT sent from here: the
 * webapp has no SMTP dependency, so operators who want email point the generic
 * webhook at their mailer (or a Slack email integration) instead.
 *
 * Every sender is fail-safe: it validates the URL scheme, bounds the request
 * with a timeout, and returns `{ ok, error }` instead of throwing, so a dead
 * webhook can never break the scheduler tick or the status poll that calls it.
 */

import type { ScanDiff } from './scanDiff'
import { summarizeDiff } from './scanDiff'

export type AlertChannel = 'slack' | 'webhook'

export interface AlertResult {
  ok: boolean
  error?: string
}

const MAX_URL_LENGTH = 2048
const REQUEST_TIMEOUT_MS = 10_000
const MAX_LISTED = 10

/** HTTPS-only; secrets stay server-side (callers must never echo the URL). */
export function isValidWebhookUrl(raw: unknown): boolean {
  if (typeof raw !== 'string') return false
  const v = raw.trim()
  if (!v || v.length > MAX_URL_LENGTH) return false
  if (/[\s<>"']/.test(v)) return false
  try {
    const u = new URL(v)
    return u.protocol === 'https:'
  } catch {
    return false
  }
}

/** Never log or store the URL itself — it is a bearer secret. */
export function redactWebhookUrl(raw: string): string {
  try {
    const u = new URL(raw)
    return `${u.protocol}//${u.host}/…`
  } catch {
    return '(invalid url)'
  }
}

function listed(items: string[]): string {
  if (items.length <= MAX_LISTED) return items.join(', ')
  return `${items.slice(0, MAX_LISTED).join(', ')} (+${items.length - MAX_LISTED} more)`
}

export function formatScanAlertText(opts: {
  projectName: string
  scheduleLabel?: string
  diff: ScanDiff
}): string {
  const { projectName, scheduleLabel, diff } = opts
  const lines = [
    `:radar: RedAmon scheduled scan — *${projectName}*${scheduleLabel ? ` (${scheduleLabel})` : ''}`,
    summarizeDiff(diff),
  ]
  if (diff.newSubdomains.length) lines.push(`New subdomains: ${listed(diff.newSubdomains)}`)
  if (diff.newPorts.length) {
    lines.push(
      `New ports: ${listed(diff.newPorts.map(p => `${p.host}:${p.port}/${p.protocol}`))}`
    )
  }
  if (diff.newCves.length) lines.push(`New CVEs: ${listed(diff.newCves)}`)
  return lines.join('\n')
}

async function postJson(url: string, body: unknown): Promise<AlertResult> {
  if (!isValidWebhookUrl(url)) return { ok: false, error: 'invalid webhook URL (https only)' }
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })
    if (!res.ok) return { ok: false, error: `webhook responded ${res.status}` }
    return { ok: true }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

/** Slack incoming webhook: `{ text }` payload. */
export function sendSlackAlert(webhookUrl: string, text: string): Promise<AlertResult> {
  return postJson(webhookUrl, { text })
}

export interface ScanWebhookPayload {
  event: 'scan.changes'
  projectId: string
  projectName: string
  scanJobId: string
  scheduleId: string | null
  summary: string
  newSubdomains: string[]
  removedSubdomains: string[]
  newPorts: ScanDiff['newPorts']
  removedPorts: ScanDiff['removedPorts']
  newCves: string[]
  newVulnCount: number
  at: string
}

/** Generic JSON webhook for SIEM/ticketing/email-bridge integrations. */
export function sendGenericWebhook(
  webhookUrl: string,
  payload: ScanWebhookPayload
): Promise<AlertResult> {
  return postJson(webhookUrl, payload)
}
