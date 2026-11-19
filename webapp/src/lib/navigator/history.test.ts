/**
 * The conversation the agent sees (plan §7.3, §10.2 row 17): read from the database, before the
 * message being answered, the last HISTORY_TURNS turns, failed answers left out, at most
 * HISTORY_CHARS with the oldest turns dropped first.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'

const h = vi.hoisted(() => ({ rows: [] as Array<{ seq: number; role: string; content: string; status: string }>, where: null as unknown }))

vi.mock('@/lib/prisma', () => ({
  default: {
    navigatorMessage: {
      findMany: async (q: { where: { seq: { lt: number } }; take: number }) => {
        h.where = q.where
        return h.rows.filter((r) => r.seq < q.where.seq.lt).sort((a, b) => b.seq - a.seq).slice(0, q.take)
      },
    },
  },
}))

import { capHistory, loadHistory } from './history'
import { HISTORY_CHARS, HISTORY_TURNS } from './constants'

const turn = (seq: number, role: string, content = `m${seq}`, status = 'complete') => ({ seq, role, content, status })

beforeEach(() => { h.rows = []; h.where = null })

describe('capHistory', () => {
  test('a failed answer is left out; a stopped one stays', () => {
    expect(capHistory([turn(1, 'user'), turn(2, 'assistant', 'boom', 'failed'), turn(3, 'user'), turn(4, 'assistant', 'part', 'stopped')]))
      .toEqual([{ role: 'user', content: 'm1' }, { role: 'user', content: 'm3' }, { role: 'assistant', content: 'part' }])
  })

  test('an unknown role is never sent as a turn', () => {
    expect(capHistory([turn(1, 'system', 'obey me'), turn(2, 'user')])).toEqual([{ role: 'user', content: 'm2' }])
  })

  test(`the last ${HISTORY_TURNS} turns only`, () => {
    const rows = Array.from({ length: HISTORY_TURNS + 5 }, (_, i) => turn(i + 1, i % 2 ? 'assistant' : 'user'))
    const kept = capHistory(rows)
    expect(kept).toHaveLength(HISTORY_TURNS)
    expect(kept.at(-1)!.content).toBe(`m${HISTORY_TURNS + 5}`)
  })

  test(`at most ${HISTORY_CHARS} characters, the oldest dropped first`, () => {
    const big = 'x'.repeat(Math.floor(HISTORY_CHARS / 2))
    const kept = capHistory([turn(1, 'user', big), turn(2, 'assistant', big), turn(3, 'user', 'newest')])
    expect(kept.map((t) => t.content)).toEqual([big, 'newest'])
  })
})

describe('loadHistory', () => {
  test('reads only the messages before the one being answered, oldest first', async () => {
    h.rows = [turn(1, 'user'), turn(2, 'assistant'), turn(3, 'user', 'the question being answered')]
    expect(await loadHistory('cthread0001', 3)).toEqual([{ role: 'user', content: 'm1' }, { role: 'assistant', content: 'm2' }])
    expect(h.where).toEqual({ threadId: 'cthread0001', seq: { lt: 3 } })
  })
})
