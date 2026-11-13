/**
 * AU-06 (step 6.12): `AUDIT_FORWARD=stdout` prints every audit row the webapp writes once, as one
 * JSON line after `[audit-forward]`, for shipping the container log to an external store; `off`
 * (the default) prints none, and the `[audit] <action> ...` line of each row stays either way.
 * A row written in a transaction prints only after that transaction commits (`auditedTransaction`):
 * a rolled-back row never reaches the external store. Printing never fails the write. The line is the
 * stored row and nothing else, and a key named like a credential prints as `[redacted]` (§9.8).
 *
 * The writers covered: writeAudit, writeAuditTx, writeActAsAudit and the FireteamSettingsAudit
 * writer (lib/reconSettings/crossField.ts) named by the spec, and the three the kickoff re-check
 * added: the legacy-grant decisions and the What's-new dismissal (lib/authz/updateReview.ts) and the
 * act-as rows written in a transaction (lib/authz/actAs.ts). That no other writer exists, and that
 * every transaction writing a row runs in `auditedTransaction`, is auditWriters.static.test.ts.
 *
 * Databases: a small one here whose transaction stages its writes and keeps them only on commit;
 * the plugin tests' fakePrisma (updateReview); the account tests' accountDb (act-as).
 *
 * Run: npx vitest run --no-file-parallelism src/lib/auditForward.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

const h = vi.hoisted(() => ({ db: null as unknown }))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, {
    get: (_t, key) => (h.db as Record<string | symbol, unknown>)[key],
    has: (_t, key) => key in (h.db as object),
  })
  return { default: client, prisma: client }
})
vi.mock('@/lib/agentSockets', () => ({ closeAgentSockets: vi.fn(async () => ({ ok: true, closed: 0, stoppedRuns: 0 })) }))

import prisma from '@/lib/prisma'
import { writeAudit, writeAuditTx, writeActAsAudit } from '@/lib/audit'
import { FORWARD_PREFIX, auditedTransaction } from './auditForward'
import { writeFireteamAudit } from '@/lib/reconSettings/crossField'
import { decideLegacyGrant, dismissWhatsNew, REMOVE_ACTION, WHATS_NEW_DISMISSED_ACTION } from '@/lib/authz/updateReview'
import { recordActAsEnd, startImpersonation } from '@/lib/authz/actAs'
import { setNowForTests } from '@/lib/authz/clock'
import { createFakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { createAccountDb } from '@/lib/authz/__testing__/accountDb'

type Row = Record<string, unknown>
const NOW = new Date('2026-11-13T10:00:00Z')

/** A database whose transaction stages its writes and keeps them only when the callback resolves. */
function smallDb() {
  const stored = { audit: [] as Row[], actAs: [] as Row[], fireteam: [] as Row[] }
  let seq = 0
  let failCommit = false
  const tables = (into: typeof stored) => ({
    auditLog: {
      create: async ({ data }: { data: Row }) => {
        const row = { id: `al-${++seq}`, createdAt: NOW, ...data }
        into.audit.push(row)
        return { ...row }
      },
    },
    actAsAudit: {
      create: async ({ data }: { data: Row }) => {
        const row = { id: `aa-${++seq}`, createdAt: NOW, reason: null, durationMinutes: null, endedBy: null, ...data }
        into.actAs.push(row)
        return { ...row }
      },
    },
    fireteamSettingsAudit: {
      createMany: async ({ data }: { data: Row[] }) => {
        into.fireteam.push(...data)
        return { count: data.length }
      },
    },
  })
  return {
    ...tables(stored),
    async $transaction<T>(fn: (tx: unknown) => Promise<T>): Promise<T> {
      const staged = { audit: [] as Row[], actAs: [] as Row[], fireteam: [] as Row[] }
      const result = await fn(tables(staged))
      if (failCommit) throw new Error('could not serialize access')
      stored.audit.push(...staged.audit)
      stored.actAs.push(...staged.actAs)
      stored.fireteam.push(...staged.fireteam)
      return result
    },
    stored,
    failNextCommit: () => { failCommit = true },
  }
}

let info: ReturnType<typeof vi.spyOn>
let error: ReturnType<typeof vi.spyOn>
let warn: ReturnType<typeof vi.spyOn>
const printed = (): string[] => info.mock.calls.map((c: unknown[]) => String(c[0]))
const forwarded = (): string[] => printed().filter((l: string) => l.startsWith(`${FORWARD_PREFIX} `))
const forwardedRows = (): Row[] => forwarded().map((l: string) => JSON.parse(l.slice(FORWARD_PREFIX.length + 1)) as Row)
const errors = (): string[] => error.mock.calls.map((c: unknown[]) => String(c[0]))

const ENTRY = {
  actorId: 'admin-1',
  actorEmail: 'ada@e2e.local',
  action: 'user.role_changed',
  targetType: 'user',
  targetId: 'member-1',
  before: { role: 'standard' },
  after: { role: 'admin' },
}

beforeEach(() => {
  h.db = smallDb()
  setNowForTests(() => NOW)
  info = vi.spyOn(console, 'info').mockImplementation(() => {})
  error = vi.spyOn(console, 'error').mockImplementation(() => {})
  warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
})
afterEach(() => {
  setNowForTests(null)
  vi.unstubAllEnvs()
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
  vi.restoreAllMocks()
})

const db = () => h.db as ReturnType<typeof smallDb>

/** One row from each of the four writers the spec names (the Fireteam writer changes two fields: two rows). */
async function writeOneOfEach(): Promise<void> {
  await writeAudit({ ...ENTRY, action: 'auth.logout', targetId: 'admin-1' })
  await auditedTransaction(prisma, async (tx) => { await writeAuditTx(tx, ENTRY) })
  await writeActAsAudit({ adminId: 'admin-1', targetUserId: 'member-1', event: 'start', reason: 'ticket 12' })
  await writeFireteamAudit('project-1', { fireteamEnabled: false, fireteamMaxConcurrent: 2 },
    { fireteamEnabled: true, fireteamMaxConcurrent: 3 }, { userId: 'admin-1', source: 'api' })
}

describe('AUDIT_FORWARD off (the default)', () => {
  test.each([['unset', undefined], ['empty', ''], ['off', 'off'], ['OFF with spaces', ' OFF ']])(
    'off prints no [audit-forward] line (the [audit] line stays): %s', async (_name, value) => {
      if (value !== undefined) vi.stubEnv('AUDIT_FORWARD', value)
      await writeOneOfEach()
      expect(forwarded()).toEqual([])
      expect(printed()).toContain('[audit] user.role_changed actor=admin-1 target=user:member-1 source=api')
      expect(printed()).toContain('[audit] auth.logout actor=admin-1 target=user:admin-1 source=api')
      expect(db().stored.audit).toHaveLength(2)
      expect(db().stored.actAs).toHaveLength(1)
      expect(db().stored.fireteam).toHaveLength(2)
      expect(warn).not.toHaveBeenCalled()
    })

  test('off: auditedTransaction hands the caller\'s own callback to $transaction, and nothing else', async () => {
    const tx = { auditLog: { create: vi.fn(async () => ({})) } }
    const client = { $transaction: vi.fn(async (fn: (t: unknown) => Promise<unknown>) => fn(tx)) }
    const callback = async (t: unknown) => { await writeAuditTx(t as never, ENTRY); return 'done' }
    expect(await auditedTransaction(client as never, callback as never)).toBe('done')
    expect(client.$transaction.mock.calls).toEqual([[callback]])
    expect(tx.auditLog.create).toHaveBeenCalledTimes(1)
    expect(forwarded()).toEqual([])
  })

  test('a value other than off or stdout keeps forwarding off, with one warning per value', async () => {
    vi.stubEnv('AUDIT_FORWARD', 'syslog')
    await writeAudit(ENTRY)
    await writeAudit(ENTRY)
    expect(forwarded()).toEqual([])
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0][0])).toBe(`${FORWARD_PREFIX} AUDIT_FORWARD="syslog" is neither off nor stdout: forwarding stays off`)
  })
})

describe('AUDIT_FORWARD=stdout', () => {
  beforeEach(() => vi.stubEnv('AUDIT_FORWARD', 'stdout'))

  test('stdout prints one JSON line per row from each of the four writers', async () => {
    await writeOneOfEach()
    const lines = forwarded()
    expect(lines).toHaveLength(5)
    for (const line of lines) expect(line).not.toContain('\n')
    const rows = forwardedRows()
    expect(rows.map((r) => [r.table, r.action ?? r.event ?? r.field])).toEqual([
      ['audit_log', 'auth.logout'],
      ['audit_log', 'user.role_changed'],
      ['act_as_audit', 'start'],
      ['fireteam_settings_audit', 'fireteamEnabled'],
      ['fireteam_settings_audit', 'fireteamMaxConcurrent'],
    ])
    // Each line is the stored row (with its id and time) and nothing else.
    const stored = [...db().stored.audit, ...db().stored.actAs, ...db().stored.fireteam]
    const tables = ['audit_log', 'audit_log', 'act_as_audit', 'fireteam_settings_audit', 'fireteam_settings_audit']
    expect(rows).toEqual(stored.map((row, i) => ({ table: tables[i], ...JSON.parse(JSON.stringify(row)) })))
    expect(rows[1]).toMatchObject({ id: 'al-2', createdAt: NOW.toISOString(), actorEmail: 'ada@e2e.local', after: { role: 'admin' } })
    expect(rows[2]).toMatchObject({ adminId: 'admin-1', targetUserId: 'member-1', reason: 'ticket 12' })
    expect(rows[4]).toMatchObject({ projectId: 'project-1', oldValue: 2, newValue: 3, userId: 'admin-1' })
    // The [audit] lines stay.
    expect(printed()).toContain('[audit] user.role_changed actor=admin-1 target=user:member-1 source=api')
    expect(errors()).toEqual([])
  })

  test('a transaction\'s rows print after it commits, never inside it', async () => {
    await auditedTransaction(prisma, async (tx) => {
      await writeAuditTx(tx, ENTRY)
      await writeAuditTx(tx, { ...ENTRY, action: 'user.permissions_changed' })
      expect(forwarded()).toEqual([])
    })
    expect(forwardedRows().map((r) => r.action)).toEqual(['user.role_changed', 'user.permissions_changed'])
  })

  test('a rolled-back writeAuditTx prints nothing', async () => {
    await expect(auditedTransaction(prisma, async (tx) => {
      await writeAuditTx(tx, ENTRY)
      throw new Error('the change was refused')
    })).rejects.toThrow('the change was refused')
    expect(forwarded()).toEqual([])
    expect(db().stored.audit).toEqual([])
    // The commit itself fails after the callback resolved: nothing either.
    db().failNextCommit()
    await expect(auditedTransaction(prisma, async (tx) => { await writeAuditTx(tx, ENTRY) })).rejects.toThrow('could not serialize')
    expect(forwarded()).toEqual([])
    // A refused audit insert rolls back and prints nothing (AU-05 unchanged).
    await expect(auditedTransaction(prisma, async (tx) => {
      await writeAuditTx({ auditLog: { create: async () => { throw new Error('audit_log is locked') } } }, ENTRY)
      await writeAuditTx(tx, ENTRY)
    })).rejects.toThrow('audit_log is locked')
    expect(forwarded()).toEqual([])
  })

  test('the root client\'s rows print at once (their insert is the commit)', async () => {
    await writeAuditTx(prisma, ENTRY)
    expect(forwarded()).toHaveLength(1)
  })

  test('a row written in a transaction auditedTransaction does not run still prints, with an error line', async () => {
    await db().$transaction(async (tx) => { await writeAuditTx(tx as never, ENTRY) })
    expect(forwarded()).toHaveLength(1)
    expect(errors()).toContain(`${FORWARD_PREFIX} a audit_log row (user.role_changed) was written in a transaction auditedTransaction does not run: printed before its commit`)
  })

  test('failure to print never fails the write', async () => {
    info.mockImplementation((line: unknown) => {
      if (String(line).startsWith(FORWARD_PREFIX)) throw new Error('EPIPE: stdout is closed')
    })
    await writeAudit(ENTRY)
    await auditedTransaction(prisma, async (tx) => { await writeAuditTx(tx, ENTRY) })
    await writeActAsAudit({ adminId: 'admin-1', targetUserId: 'member-1', event: 'end' }, { strict: true })
    expect(db().stored.audit).toHaveLength(2)
    expect(db().stored.actAs).toHaveLength(1)
    info.mockImplementation(() => {})
    info.mockClear()

    // A row that cannot be serialised: the write stands, an error line says so, the others print.
    await auditedTransaction(prisma, async (tx) => {
      await writeAuditTx(tx, { ...ENTRY, after: { count: BigInt(3) } })
      await writeAuditTx(tx, { ...ENTRY, action: 'user.update' })
    })
    expect(db().stored.audit).toHaveLength(4)
    expect(forwardedRows().map((r) => r.action)).toEqual(['user.update'])
    expect(errors().some((l: string) => l.startsWith(`${FORWARD_PREFIX} could not print a audit_log row (user.role_changed): `))).toBe(true)
    expect(error.mock.calls.every((c: unknown[]) => !String(c[0]).includes('failed to persist'))).toBe(true)
  })

  test('a key named like a credential prints as [redacted]; the stored row is untouched', async () => {
    await writeAudit({
      ...ENTRY,
      after: { stepUpPassword: 'violet-harbour-lantern-42', links: [{ tokenHash: 'ab12' }], settingsHash: 'kept', emailSha256: 'kept-too' },
    })
    const [row] = forwardedRows()
    expect(row.after).toEqual({ stepUpPassword: '[redacted]', links: [{ tokenHash: '[redacted]' }], settingsHash: 'kept', emailSha256: 'kept-too' })
    expect(forwarded()[0]).not.toContain('violet-harbour-lantern-42')
    expect((db().stored.audit[0].after as Row).stepUpPassword).toBe('violet-harbour-lantern-42')
    expect(errors()).toContain(`${FORWARD_PREFIX} redacted stepUpPassword, tokenHash in a audit_log row (user.role_changed): an audit row must never hold a credential`)
  })

  test('the legacy-grant decision and the What\'s-new dismissal (updateReview.ts) print once each, the decision after its commit', async () => {
    const fake = createFakePrisma()
    fake.seed('user', [{ id: 'member-1', name: 'm', email: 'member-1@e2e.local', role: 'standard', password: 'h', legacyGrants: ['kali_terminal'] }])
    h.db = fake
    const actor = { actorId: 'admin-1', actingAsUserId: null, actorEmail: 'ada@e2e.local' }
    expect(await decideLegacyGrant(actor, 'member-1', 'kali_terminal', 'remove')).toEqual({ ok: true, changed: true })
    expect(await dismissWhatsNew(actor)).toEqual({ changed: true })
    expect(await dismissWhatsNew(actor)).toEqual({ changed: false })
    const rows = forwardedRows()
    expect(rows.map((r) => [r.table, r.action])).toEqual([['audit_log', REMOVE_ACTION], ['audit_log', WHATS_NEW_DISMISSED_ACTION]])
    expect(rows[0]).toMatchObject({ actorId: 'admin-1', targetId: 'member-1', after: { grant: 'kali_terminal' } })
    expect(rows.map((r) => r.id)).toEqual(fake.rows('auditLog').map((r) => r.id))
    // The decision's own [audit] line still prints after the commit.
    expect(printed()).toContain(`[audit] ${REMOVE_ACTION} actor=admin-1 target=user:member-1 source=api`)

    // A refused decision (nothing held) writes and prints nothing.
    expect(await decideLegacyGrant(actor, 'member-1', 'kali_terminal', 'remove')).toEqual({ ok: true, changed: false })
    expect(forwarded()).toHaveLength(2)
  })

  test('the act-as start and end rows written in their transaction (actAs.ts) print once each, after the commit', async () => {
    const accounts = createAccountDb()
    accounts.seedUsers([{ id: 'admin-1', role: 'admin' }, { id: 'member-1' }])
    h.db = accounts
    await startImpersonation({
      admin: { id: 'admin-1', sessionVersion: 0 }, targetUserId: 'member-1', seconds: 3600,
      reason: 'ticket 12', durationMinutes: 60, presentedToken: null,
    })
    expect(await recordActAsEnd({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'stopped' })).toBe(true)
    expect(await recordActAsEnd({ adminId: 'admin-1', targetUserId: 'member-1', endedBy: 'stopped' })).toBe(false)
    const rows = forwardedRows()
    expect(rows.map((r) => [r.table, r.event, r.endedBy ?? null])).toEqual([
      ['act_as_audit', 'start', null],
      ['act_as_audit', 'end', 'stopped'],
    ])
    expect(rows[0]).toMatchObject({ adminId: 'admin-1', targetUserId: 'member-1', reason: 'ticket 12', durationMinutes: 60 })
    expect(errors()).toEqual([])
  })
})
