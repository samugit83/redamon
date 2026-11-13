import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { now } from '@/lib/authz/clock'
import { quotaLimit } from '@/lib/authz/quotas'
import { instanceProvidersInForce } from './entitlement'

/**
 * The daily budget of model calls on instance LLM providers (step 6.11, GV-12). The limit is the
 * person's `llmDailyCalls` quota (step 6.8; null = unlimited); the day's calls are `QuotaUsage` rows
 * of kind `llm_instance_calls`, counted for the person who ran each call. The agent reads both before
 * calls and reports its counts every minute (agentic/llm_budget.py, through /api/internal/llm-usage);
 * the preset generator, which calls providers from the webapp, checks and records here. On a shared
 * project the stricter of the actor's and the owner's budget refuses. Days are UTC.
 *
 * With RBAC_GOVERNANCE_ENABLED off no instance provider is used, nothing is read and nothing counted.
 */
export const LLM_USAGE_KIND = 'llm_instance_calls'

/** Bounds of one report entry: a minute of one agent's calls for one person. */
export const MAX_REPORTED_COUNT = 1_000_000
const DAY = /^\d{4}-\d{2}-\d{2}$/

/** The UTC day of `at`, as stored (`@db.Date`) and as the agent names it. */
export function utcDay(at: Date = now()): string {
  return at.toISOString().slice(0, 10)
}

const dayValue = (day: string) => new Date(`${day}T00:00:00.000Z`)

export interface Budget {
  /** The day's limit, or null for unlimited. */
  limit: number | null
  /** The calls stored for the day. */
  used: number
}

export async function usageOn(userId: string, day: string = utcDay()): Promise<number> {
  const row = await prisma.quotaUsage.findUnique({
    where: { userId_day_kind: { userId, day: dayValue(day), kind: LLM_USAGE_KIND } },
    select: { count: true },
  })
  return row?.count ?? 0
}

export async function budgetFor(userId: string): Promise<Budget> {
  if (!instanceProvidersInForce()) return { limit: null, used: 0 }
  const [limit, used] = await Promise.all([quotaLimit(userId, 'llmDailyCalls'), usageOn(userId)])
  return { limit, used }
}

export interface UsageEntry {
  userId: string
  day: string
  count: number
}

/** The entries of a report, or why it is refused. A day is today or yesterday (a report sent at midnight). */
export function parseUsageReport(body: unknown): UsageEntry[] | string {
  const counts = (body as { counts?: unknown } | null)?.counts
  if (!Array.isArray(counts) || counts.length > 1000) return 'counts must be a list of at most 1000 entries'
  const today = utcDay()
  const yesterday = utcDay(new Date(now().getTime() - 86_400_000))
  const out: UsageEntry[] = []
  for (const c of counts) {
    const e = c as Partial<UsageEntry> | null
    if (!e || typeof e.userId !== 'string' || !e.userId || e.userId.length > 128) return 'each entry needs a userId'
    if (typeof e.day !== 'string' || !DAY.test(e.day) || (e.day !== today && e.day !== yesterday)) return 'each entry needs a day: today or yesterday (UTC)'
    if (!Number.isInteger(e.count) || (e.count as number) < 1 || (e.count as number) > MAX_REPORTED_COUNT) return 'each count is a whole number from 1'
    out.push({ userId: e.userId, day: e.day, count: e.count as number })
  }
  return out
}

/**
 * Adds the counts to the stored ones. An entry for an account deleted since (the row would name no
 * user: P2003) is dropped and logged; anything else throws.
 */
export async function recordUsage(entries: readonly UsageEntry[]): Promise<number> {
  let recorded = 0
  for (const e of entries) {
    try {
      await prisma.quotaUsage.upsert({
        where: { userId_day_kind: { userId: e.userId, day: dayValue(e.day), kind: LLM_USAGE_KIND } },
        create: { userId: e.userId, day: dayValue(e.day), kind: LLM_USAGE_KIND, count: e.count },
        update: { count: { increment: e.count } },
      })
      recorded++
    } catch (err) {
      if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2003') {
        console.warn(`[rbac] llm_usage_dropped: account ${e.userId} is gone (${e.count} call(s) on ${e.day})`)
        continue
      }
      throw err
    }
  }
  return recorded
}

/** The first of these people whose budget is used up, or null. */
export async function exhaustedBudget(userIds: readonly string[]): Promise<{ userId: string; limit: number; used: number } | null> {
  for (const userId of [...new Set(userIds.filter(Boolean))]) {
    const { limit, used } = await budgetFor(userId)
    if (limit !== null && used >= limit) return { userId, limit, used }
  }
  return null
}
