/**
 * The conversation the agent sees, read from the database (never from the browser, §10.2 row 17):
 * the last HISTORY_TURNS messages before the one being answered, content only, failed answers left
 * out, at most HISTORY_CHARS with the oldest dropped first.
 */
import prisma from '@/lib/prisma'
import { HISTORY_CHARS, HISTORY_TURNS } from './constants'

export interface HistoryTurn {
  role: 'user' | 'assistant'
  content: string
}

export function capHistory(rows: ReadonlyArray<{ role: string; content: string; status: string }>): HistoryTurn[] {
  const kept = rows.filter((r) => (r.role === 'user' || r.role === 'assistant') && !(r.role === 'assistant' && r.status === 'failed'))
    .slice(-HISTORY_TURNS)
    .map((r) => ({ role: r.role as HistoryTurn['role'], content: r.content }))
  let total = kept.reduce((n, t) => n + t.content.length, 0)
  while (kept.length && total > HISTORY_CHARS) {
    total -= kept.shift()!.content.length
  }
  return kept
}

export async function loadHistory(threadId: string, beforeSeq: number): Promise<HistoryTurn[]> {
  const rows = await prisma.navigatorMessage.findMany({
    where: { threadId, seq: { lt: beforeSeq } },
    orderBy: { seq: 'desc' },
    take: HISTORY_TURNS + 4,
    select: { role: true, content: true, status: true },
  })
  return capHistory(rows.reverse())
}
