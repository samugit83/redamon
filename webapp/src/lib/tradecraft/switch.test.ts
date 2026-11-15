/**
 * The per-account Tradecraft 2.0 switch: off without a row, and every change written with
 * its audit row in one transaction, so a failed audit insert leaves the switch as it was.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

type Row = { userId: string; v2Enabled: boolean; v2EnabledAt: Date | null }

const h = vi.hoisted(() => ({
  rows: new Map<string, Row>(),
  audits: [] as Record<string, unknown>[],
  failAudit: false,
  events: [] as string[],
  locks: new Map<string, Promise<void>>(),
  // Lets a test hold every transaction after its first read, so two of them overlap.
  afterRead: null as null | (() => Promise<void>),
}))

/** Reads see the committed rows plus the transaction's own writes (READ COMMITTED). */
function store(committed: Map<string, Row>, own: Map<string, Row> | null, label: string) {
  const read = (userId: string) => own?.get(userId) ?? committed.get(userId)
  return {
    findUnique: async ({ where }: { where: { userId: string } }) => {
      h.events.push(`${label}.findUnique`)
      const r = read(where.userId)
      if (own && h.afterRead) await h.afterRead()
      return r ? { ...r } : null
    },
    upsert: async ({ where, create, update }: { where: { userId: string }; create: Row; update: Partial<Row> }) => {
      h.events.push(`${label}.upsert`)
      const prev = read(where.userId)
      const next = prev ? { ...prev, ...update } : { ...create, v2EnabledAt: create.v2EnabledAt ?? null }
      ;(own ?? committed).set(where.userId, next)
      return next
    },
  }
}

vi.mock('@/lib/prisma', () => {
  const db = {
    tradecraftUserSettings: store(h.rows, null, 'db'),
    $transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
      // The transaction's writes commit only when fn resolves; its advisory locks are held
      // until it ends, as pg_advisory_xact_lock does.
      const own = new Map<string, Row>()
      const held: (() => void)[] = []
      const tx = {
        $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
          if (!strings.join('?').includes('pg_advisory_xact_lock')) throw new Error('unexpected SQL')
          const key = String(values[0])
          h.events.push(`tx.lock ${key}`)
          for (let wait = h.locks.get(key); wait; wait = h.locks.get(key)) await wait
          let release!: () => void
          h.locks.set(key, new Promise<void>(r => { release = r }))
          held.push(() => { h.locks.delete(key); release() })
          return 1
        },
        tradecraftUserSettings: store(h.rows, own, 'tx'),
        auditLog: {
          create: async ({ data }: { data: Record<string, unknown> }) => {
            h.events.push('tx.audit')
            if (h.failAudit) throw new Error('audit insert failed')
            h.audits.push(data)
            return { id: `a${h.audits.length}`, createdAt: new Date(), ...data }
          },
        },
      }
      try {
        const out = await fn(tx)
        for (const [k, v] of own) h.rows.set(k, v)
        return out
      } finally {
        for (const release of held) release()
      }
    },
  }
  return { default: db, prisma: db }
})

import { setNowForTests } from '@/lib/authz/clock'
import { auditActorOf } from '@/lib/auditActor'
import { setTradecraftV2, tradecraftV2Enabled } from './switch'

const T0 = new Date('2026-11-15T10:00:00Z')
const ME = auditActorOf({ id: 'u1', email: 'u1@example.invalid' })

beforeEach(() => {
  h.rows.clear()
  h.audits = []
  h.events = []
  h.failAudit = false
  h.locks.clear()
  h.afterRead = null
  setNowForTests(() => T0)
  vi.spyOn(console, 'info').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  setNowForTests(null)
  vi.restoreAllMocks()
})

describe('tradecraft switch', () => {
  test('default_off_without_row', async () => {
    expect(await tradecraftV2Enabled('u1')).toBe(false)
  })

  test('reads_true_when_set', async () => {
    h.rows.set('u1', { userId: 'u1', v2Enabled: true, v2EnabledAt: T0 })
    h.rows.set('u2', { userId: 'u2', v2Enabled: false, v2EnabledAt: null })
    expect(await tradecraftV2Enabled('u1')).toBe(true)
    expect(await tradecraftV2Enabled('u2')).toBe(false)
  })

  test('write_records_audit_in_same_transaction', async () => {
    await setTradecraftV2(ME, 'u1', true)
    expect(h.rows.get('u1')).toMatchObject({ v2Enabled: true, v2EnabledAt: T0 })
    expect(h.events).toEqual(['tx.lock tradecraft_user_settings:u1', 'tx.findUnique', 'tx.upsert', 'tx.audit'])
    expect(h.audits).toEqual([expect.objectContaining({
      action: 'tradecraft.v2_switched',
      actorId: 'u1',
      actorEmail: 'u1@example.invalid',
      targetType: 'user',
      targetId: 'u1',
      permission: 'self:tradecraft',
      before: { v2Enabled: false },
      after: { v2Enabled: true },
    })])
    expect(await tradecraftV2Enabled('u1')).toBe(true)
  })

  test('a failed audit insert leaves the switch as it was', async () => {
    h.failAudit = true
    await expect(setTradecraftV2(ME, 'u1', true)).rejects.toThrow('audit insert failed')
    expect(h.rows.has('u1')).toBe(false)
    expect(await tradecraftV2Enabled('u1')).toBe(false)
  })

  test('turning it off clears the time it was turned on', async () => {
    await setTradecraftV2(ME, 'u1', true)
    await setTradecraftV2(ME, 'u1', false)
    expect(h.rows.get('u1')).toMatchObject({ v2Enabled: false, v2EnabledAt: null })
    expect(h.audits.map(a => a.after)).toEqual([{ v2Enabled: true }, { v2Enabled: false }])
  })

  test('the same value again changes nothing and records nothing', async () => {
    await setTradecraftV2(ME, 'u1', true)
    setNowForTests(() => new Date('2026-11-16T10:00:00Z'))
    await setTradecraftV2(ME, 'u1', true)
    expect(h.audits).toHaveLength(1)
    expect(h.rows.get('u1')!.v2EnabledAt).toEqual(T0)
    await setTradecraftV2(ME, 'u2', false)
    expect(h.rows.has('u2')).toBe(false)
    expect(h.audits).toHaveLength(1)
  })

  test('an admin acting as the account is the actor, the account is on whose behalf', async () => {
    await setTradecraftV2(auditActorOf({ id: 'admin-1', email: null }, 'u1'), 'u1', true)
    expect(h.audits[0]).toMatchObject({ actorId: 'admin-1', onBehalfOfUserId: 'u1', targetId: 'u1' })
  })
  test('two requests at once with the same value write one change and one audit row', async () => {
    // Each transaction pauses after its read, so without the lock both read "off".
    h.afterRead = () => new Promise(r => setTimeout(r, 5))
    await Promise.all([setTradecraftV2(ME, 'u1', true), setTradecraftV2(ME, 'u1', true)])
    expect(h.audits).toHaveLength(1)
    expect(h.audits[0]).toMatchObject({ before: { v2Enabled: false }, after: { v2Enabled: true } })
    expect(h.rows.get('u1')!.v2Enabled).toBe(true)
  })

  test('two "off" requests at once on a row that is on: one audit row, with the right before', async () => {
    h.rows.set('u1', { userId: 'u1', v2Enabled: true, v2EnabledAt: T0 })
    h.afterRead = () => new Promise(r => setTimeout(r, 5))
    await Promise.all([setTradecraftV2(ME, 'u1', false), setTradecraftV2(ME, 'u1', false)])
    expect(h.audits).toEqual([expect.objectContaining({ before: { v2Enabled: true }, after: { v2Enabled: false } })])
    expect(h.rows.get('u1')).toMatchObject({ v2Enabled: false, v2EnabledAt: null })
  })

  test('the lock is per account: two accounts switch at the same time', async () => {
    h.afterRead = () => new Promise(r => setTimeout(r, 5))
    await Promise.all([setTradecraftV2(ME, 'u1', true), setTradecraftV2(ME, 'u2', true)])
    expect(h.audits.map(a => a.targetId).sort()).toEqual(['u1', 'u2'])
    expect(h.events.filter(e => e.startsWith('tx.lock'))).toEqual(
      expect.arrayContaining(['tx.lock tradecraft_user_settings:u1', 'tx.lock tradecraft_user_settings:u2']))
  })
})
