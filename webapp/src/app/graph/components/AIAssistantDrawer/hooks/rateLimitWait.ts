import { useEffect, useState } from 'react'
import { MessageType } from '@/lib/websocket-types'

/**
 * A model call of the running chat waits for the provider's rate limit to
 * clear (the agent's `rate_limit_wait` frame, sent only, never saved). The
 * drawer shows it in place of the loading word, counting down to the retry.
 */
export interface RateLimitWait {
  /** Epoch ms when the agent tries again. */
  until: number
  seconds: number
  retry: number
  purpose: string
}

const PURPOSE = /^[a-z_]{1,40}$/

const PURPOSE_WORDS: Record<string, string> = {
  think: 'the next step',
  report: 'the summary',
  deep_think: 'Deep Think',
  scope_guardrail: 'the scope check',
  classify: 'the request classification',
  cypher: 'the graph query',
  fireteam_member: 'a Fireteam member',
  lats_expand: 'the attack-path search',
}

/**
 * Messages that say nothing about the run's progress, so a wait shown before
 * them is still current. Any other message means the run moved on (a parallel
 * Fireteam member still waiting announces its next retry again).
 */
const KEEPS_WAIT: ReadonlySet<string> = new Set([
  MessageType.RATE_LIMIT_WAIT, MessageType.PONG, MessageType.CONNECTED,
  MessageType.JOB_UPDATE, MessageType.LOOP_STATUS,
])

export function endsRateLimitWait(type: string): boolean {
  return !KEEPS_WAIT.has(type)
}

export function rateLimitWaitFromPayload(payload: unknown, now: number): RateLimitWait | null {
  const p = (payload ?? {}) as Record<string, unknown>
  const seconds = p.seconds
  const retry = p.retry
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0 || seconds > 3600) return null
  if (typeof retry !== 'number' || !Number.isInteger(retry) || retry < 1) return null
  const purpose = typeof p.purpose === 'string' && PURPOSE.test(p.purpose) ? p.purpose : 'other'
  const whole = Math.round(seconds)
  return { until: now + whole * 1000, seconds: whole, retry, purpose }
}

export function rateLimitWaitText(wait: RateLimitWait | null, now: number): string | null {
  if (!wait) return null
  const what = PURPOSE_WORDS[wait.purpose] ?? 'the model call'
  // Clamped: until the first tick, `now` can be older than the frame.
  const left = Math.min(Math.ceil((wait.until - now) / 1000), wait.seconds)
  if (left <= 0) return `Provider rate limit: retrying ${what} now`
  return `Provider rate limit: retrying ${what} in ${left} s`
}

/**
 * The drawer's wait: the setter the socket handler fills and the countdown.
 * A run can stop loading with no frame after its wait (a dropped socket, a send
 * that failed), so a wait never outlives the loading state or its session.
 */
export function useRateLimitWait(isLoading: boolean, sessionId: unknown) {
  const [wait, setRateLimitWait] = useState<RateLimitWait | null>(null)
  useEffect(() => { if (!isLoading) setRateLimitWait(null) }, [isLoading])
  useEffect(() => { setRateLimitWait(null) }, [sessionId])
  return { setRateLimitWait, rateLimitWord: useRateLimitWaitText(wait) }
}

/** The countdown text of a wait, re-rendered every second while one is shown. */
export function useRateLimitWaitText(wait: RateLimitWait | null): string | null {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!wait) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [wait])
  return rateLimitWaitText(wait, now)
}
