import { useCallback, useEffect, useLayoutEffect, useRef } from 'react'
import type { NameCheckResult } from '@/lib/userSkills'
import { ApiError, readApiError, toApiError } from '@/lib/apiError'

const DEBOUNCE_MS = 400

export interface NameEntry { key: string; name: string }

export type BatchNameCheckOutcome =
  | { keys: string[]; results: NameCheckResult[] }
  | { keys: string[]; failed: true; error?: ApiError }

const CHECK_FAILED = 'The names could not be checked'

/**
 * The upload dialog's early name answer for every row at once (POST .../name-check).
 * It sends only when the list of names changed, so editing a description never starts a
 * check, and a changed list aborts the older request at once: an answer for names the person
 * has since changed is never reported. Advisory only: the upload checks again under the lock.
 */
export function useBatchNameCheck(
  userId: string | null | undefined,
  entries: NameEntry[],
  onOutcome: (outcome: BatchNameCheckOutcome) => void,
): { checkNow: () => Promise<NameCheckResult[] | null> } {
  const report = useRef(onOutcome)
  const latest = useRef(entries)
  // Updated after each commit, before any effect or handler of that commit reads them.
  useLayoutEffect(() => {
    report.current = onOutcome
    latest.current = entries
  })
  const controller = useRef<AbortController | null>(null)
  const listKey = JSON.stringify(entries.map((e) => [e.key, e.name]))

  const run = useCallback(async (list: NameEntry[]): Promise<NameCheckResult[] | null> => {
    controller.current?.abort()
    if (!userId || !list.length) return null
    const ctrl = new AbortController()
    controller.current = ctrl
    const keys = list.map((e) => e.key)
    try {
      const res = await fetch(`/api/users/${userId}/attack-skills/name-check`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ names: list.map((e) => e.name) }),
        signal: ctrl.signal,
      })
      if (!res.ok) {
        const error = await readApiError(res, CHECK_FAILED)
        if (!ctrl.signal.aborted) report.current({ keys, failed: true, error })
        return null
      }
      const body = await res.json().catch(() => null)
      if (ctrl.signal.aborted) return null
      if (!Array.isArray(body?.results) || body.results.length !== keys.length) {
        report.current({ keys, failed: true, error: new ApiError({ reason: CHECK_FAILED, status: res.status, code: 'invalid_response' }) })
        return null
      }
      report.current({ keys, results: body.results })
      return body.results
    } catch (err) {
      if (!ctrl.signal.aborted) report.current({ keys, failed: true, error: toApiError(err, CHECK_FAILED) })
      return null
    }
  }, [userId])

  useEffect(() => {
    controller.current?.abort()
    const timer = setTimeout(() => { void run(latest.current) }, DEBOUNCE_MS)
    return () => clearTimeout(timer)
  }, [listKey, run])

  useEffect(() => () => controller.current?.abort(), [])

  const checkNow = useCallback(() => run(latest.current), [run])
  return { checkNow }
}
