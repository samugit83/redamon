/**
 * OpenRouter: `GET openrouter.ai/api/v1/key` (catalogue C1). Not billed; the
 * docs recommend polling it. It reports THIS key's spending limit and usage in
 * USD. The account's credit balance (`GET /credits`) answers 403 to anything but
 * a management key, and the report never asks for a more powerful key.
 */
import { clampRemaining, firstOfNextMonthUtc, isPlainObject, isoOrNull, nextMidnight, nextMondayUtc, num } from '../../parse'
import { body, meter, shapeError, usageResult } from '../../results'
import type { Meter, MeterWindow, ProbeDef, ProbeRequest, ProbeResponse, ProbeResult } from '../../types'
import { LLM_PROBE, bearer, fail } from './common'

const NO_BALANCE_NOTE = 'Account credit balance not shown: OpenRouter reveals it to management keys only'

export function request(key: string): ProbeRequest {
  return { method: 'GET', url: 'https://openrouter.ai/api/v1/key', headers: bearer(key) }
}

// OpenRouter weeks run Monday to Sunday, UTC: nextMondayUtc in parse.ts.
export { nextMondayUtc }

interface Period {
  window: MeterWindow
  resetsAt: string | null
}

/** `limit_reset` -> the meter window and the next reset; every period starts at 00:00 UTC. */
function period(reset: unknown, now: Date): Period {
  switch (reset) {
    case 'daily': return { window: 'day', resetsAt: nextMidnight('Z', now) }
    case 'weekly': return { window: 'week', resetsAt: nextMondayUtc(now) }
    case 'monthly': return { window: 'month', resetsAt: firstOfNextMonthUtc(now) }
    case null:
    case undefined: return { window: 'lifetime', resetsAt: null }
    default: return { window: 'balance', resetsAt: null }
  }
}

export function parse(res: ProbeResponse, now: Date): ProbeResult {
  // 402 is documented on inference only; on /key it could only mean the same.
  if (res.status === 402) return fail(res, 'quota_exhausted')
  if (res.status !== 200) return fail(res)
  const d = body(res).data
  if (!isPlainObject(d) || !('limit' in d || num(d.usage) != null)) return shapeError(res)

  const meters: Meter[] = []
  const limit = num(d.limit)
  if (limit != null) {
    const left = num(d.limit_remaining)
    const p = period(d.limit_reset, now)
    meters.push(meter({
      id: 'key_limit', label: 'Key limit', unit: 'usd', window: p.window,
      limit,
      remaining: left == null ? null : Math.max(0, left),
      used: left == null ? null : Math.max(0, limit - left),
      resetsAt: p.resetsAt, resetsAtSource: p.resetsAt ? 'computed' : null,
      primary: true,
    }))
  } else {
    // No limit on the key: what it spent is all there is to show.
    const daily = num(d.usage_daily)
    if (daily != null) {
      meters.push(meter({
        id: 'usage_daily', label: 'Spend today', unit: 'usd', window: 'day', used: daily,
        resetsAt: nextMidnight('Z', now), resetsAtSource: 'computed', primary: false, note: 'no key limit',
      }))
    }
    const weekly = num(d.usage_weekly)
    if (weekly != null) {
      meters.push(meter({
        id: 'usage_weekly', label: 'Spend this week', unit: 'usd', window: 'week', used: weekly,
        resetsAt: nextMondayUtc(now), resetsAtSource: 'computed', primary: false, note: 'no key limit',
      }))
    }
    const monthly = num(d.usage_monthly)
    if (monthly != null) {
      meters.push(meter({
        id: 'usage_monthly', label: 'Spend this month', unit: 'usd', window: 'month', used: monthly,
        resetsAt: firstOfNextMonthUtc(now), resetsAtSource: 'computed', primary: true, note: 'no key limit',
      }))
    }
  }

  // Free-model allowance: 50 requests/day before 10 credits are bought, 1000 after.
  const free = isPlainObject(d.free_model_daily_requests) ? d.free_model_daily_requests : undefined
  if (free) {
    const freeLimit = num(free.limit)
    const freeUsed = num(free.used)
    meters.push(meter({
      id: 'free_model_requests', label: 'Free-model requests (day)', unit: 'requests', window: 'day',
      used: freeUsed, limit: freeLimit, remaining: num(free.remaining) ?? clampRemaining(freeLimit, freeUsed),
      resetsAt: nextMidnight('Z', now), resetsAtSource: 'computed', primary: false,
    }))
  }

  const notes = [NO_BALANCE_NOTE]
  if (d.is_management_key === true) notes.push('This is a management key: it manages API keys and cannot call models')
  // `label` is not copied: an unnamed key's label is the key itself, partly masked.
  return usageResult(meters, {
    account: {
      plan: d.is_free_tier === true ? 'Free tier' : d.is_free_tier === false ? 'Paid' : undefined,
      expiresAt: isoOrNull(d.expires_at) ?? undefined,
    },
    notes,
  })
}

export const openrouterProbe: ProbeDef = {
  ...LLM_PROBE,
  id: 'llm-openrouter',
  service: 'openrouter',
  label: 'OpenRouter',
  kind: 'usage',
  costNote: 'Free: reading the key is not billed (OpenRouter recommends polling it)',
  docsUrl: 'https://openrouter.ai/docs/api/reference/limits',
  dashboardUrl: 'https://openrouter.ai/settings/credits',
  endpoint: 'GET openrouter.ai/api/v1/key',
  run: async ctx => parse(await ctx.http(request(ctx.key)), ctx.now),
}

/** Jev-only entries share billing metadata, never TypeSafe probes or inference calls. */
export const jevOpenrouterProbe: ProbeDef = {
  ...openrouterProbe,
  id: 'llm-jev-openrouter',
  service: 'jev_openrouter',
  label: 'OpenRouter (Jev)',
  costNote: 'Free key billing metadata only; does not prove Jev decision access',
  docsUrl: 'https://openrouter.ai/docs/guides/community/typesafe-sdk',
  run: async ctx => {
    const result = parse(await ctx.http(request(ctx.key)), ctx.now)
    return { ...result, notes: [...(result.notes ?? []), 'OpenRouter key billing metadata only; Jev decision access is not checked'] }
  },
}
