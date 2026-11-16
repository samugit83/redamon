'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { Loader2, Search } from 'lucide-react'
import { toApiError } from '@/lib/apiError'
import type { CheckUrlResult } from '@/lib/tradecraft/agentContract'
import { tradecraftClient, type CheckUrlInput } from '@/lib/tradecraft/client'
import { TYPE_LABELS } from './sections'
import css from './form.module.css'
import tc from '../tradecraft.module.css'

/** §4.5 "What Live costs without a cache", next to a Live recommendation. */
export const LIVE_COST = 'Live reads the site at every read: seconds per read, and nothing while the site is down.'

const ERRORS: Readonly<Record<string, string>> = {
  blocked_private_address: 'the address is private or internal, and is never fetched',
  userinfo_refused: 'a login in the URL is refused: use the Access settings',
  bad_url: 'the URL is not valid',
  timeout: 'the site took too long to answer',
  fetch_failed: 'the site could not be reached',
  homepage_http_error: 'the site answered with an error',
}

function size(bytes: number): string {
  if (bytes >= 1024 * 1024) return `about ${Math.round(bytes / (1024 * 1024))} MB`
  if (bytes >= 1024) return `about ${Math.round(bytes / 1024)} KB`
  return `${bytes} bytes`
}

function indexText(r: CheckUrlResult): string {
  const i = r.index
  if (!i || i.kind === 'none') return 'no index found'
  const n = i.count.toLocaleString('en-US')
  switch (i.kind) {
    case 'sitemap': return `sitemap.xml found (${n} pages)`
    case 'github_tree': return `${n} files`
    case 'searchindex': return `search index (${n} pages)`
    case 'nav': return `menu (${n} pages)`
    case 'pdf': return `${n} pages`
  }
}

/** The one-line result of §6.3 ("✓ Normal website · sitemap.xml found (412 pages) · robots.txt allows"). */
export function checkSummary(r: CheckUrlResult): string {
  if (!r.ok) return `✗ ${ERRORS[r.error_code] ?? r.error_code}`
  const parts = [
    r.detected_type ? TYPE_LABELS[r.detected_type] ?? r.detected_type : 'type unknown',
    indexText(r),
    r.robots_allows === null ? 'no robots.txt' : r.robots_allows ? 'robots.txt allows' : 'robots.txt disallows crawling',
  ]
  if (r.needs_browser) parts.push('needs the browser')
  parts.push(`${r.recommended_storage === 'stored' ? 'Stored' : 'Live'} recommended${r.estimated_bytes ? `, ${size(r.estimated_bytes)}` : ''}`)
  return `✓ ${parts.join(' · ')}`
}

/**
 * Check URL (§6.3): runs on a click, and again whenever `runToken` changes (a preset was
 * picked). Calls no model and saves nothing; the form pre-fills from the result it hands over.
 */
export function CheckUrlButton({ userId, input, disabled, runToken = 0, onResult }: {
  userId: string
  input: CheckUrlInput
  disabled?: boolean
  runToken?: number
  onResult: (result: CheckUrlResult | null) => void
}) {
  const [busy, setBusy] = useState(false)
  const [line, setLine] = useState<{ ok: boolean; text: string; live: boolean } | null>(null)
  const inputRef = useRef(input)
  inputRef.current = input
  const onResultRef = useRef(onResult)
  onResultRef.current = onResult

  const run = useCallback(async () => {
    setBusy(true)
    try {
      const { result } = await tradecraftClient.checkUrl(userId, inputRef.current)
      setLine({ ok: result.ok, text: checkSummary(result), live: result.ok && result.recommended_storage === 'live' })
      onResultRef.current(result)
    } catch (e) {
      setLine({ ok: false, text: `✗ ${toApiError(e, 'Check URL failed').message}`, live: false })
      onResultRef.current(null)
    } finally {
      setBusy(false)
    }
  }, [userId])

  useEffect(() => { if (runToken > 0) run() }, [runToken, run])

  return (
    <div className={css.override}>
      <div className={css.row}>
        <button type="button" className="secondaryButton" onClick={run} disabled={busy || disabled}>
          {busy ? <Loader2 size={14} className={tc.spin} /> : <Search size={14} />} Check URL
        </button>
      </div>
      {line && (
        <span className={line.ok ? css.checkResult : css.checkFailed} role="status">
          {line.text}{line.live ? ` ${LIVE_COST}` : ''}
        </span>
      )}
    </div>
  )
}
