/**
 * The backfill that fills the instance settings row with the tunnel and the TrafficMind
 * capture policy in force in the user rows (scripts/backfill-rbac-instance-settings.mjs,
 * step 2.4, ID-34): the readers' own picks, the sources and candidates in a marker written
 * with the row under an advisory lock, a copy that stays current while the identity switch
 * is off, a last copy when it goes on, never a row an admin wrote, never a user row.
 *
 * Prisma is an in-memory double whose `pg_advisory_xact_lock` serializes two transactions
 * and whose transaction rolls back its own writes when the callback throws.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/authz/instanceSettings.backfill.test.ts
 * @vitest-environment node
 */
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { describe, test, expect, beforeEach, vi } from 'vitest'
import {
  CAPTURE_DEFAULTS, CAPTURE_FIELDS, CAPTURE_ROW_ORDER, LOCK_KEY, MARKER_ACTION, SINGLETON_ID,
  TUNNEL_CANDIDATE_WHERE, TUNNEL_DEFAULTS, TUNNEL_FIELDS, TUNNEL_ROW_ORDER,
  backfillRbacInstanceSettings, failureReason, identitySwitchOn, run,
} from '../../../scripts/backfill-rbac-instance-settings.mjs'
import * as lib from '@/lib/sharedInstanceSettings'
import { parsePrismaModels } from './__testing__/prismaSchema'

type Row = Record<string, unknown>
type Where = Record<string, unknown>
type OrderBy = Record<string, 'asc' | 'desc'>[] | Record<string, 'asc' | 'desc'>

// The script's env parameter defaults to process.env, whose type requires NODE_ENV.
const env = (vars: Record<string, string>) => vars as unknown as NodeJS.ProcessEnv
const OFF = env({ RBAC_IDENTITY_ENABLED: 'false' })
const ON = env({ RBAC_IDENTITY_ENABLED: 'true' })

function matches(row: Row, where: Where | undefined): boolean {
  if (!where) return true
  return Object.entries(where).every(([k, cond]) => {
    if (k === 'OR') return (cond as Where[]).some((w) => matches(row, w))
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
      const c = cond as { not?: unknown; in?: unknown[] }
      if ('not' in c) return row[k] !== c.not
      if ('in' in c) return c.in!.includes(row[k])
    }
    return row[k] === cond
  })
}

function sorted(rows: Row[], orderBy: OrderBy | undefined): Row[] {
  const keys = (Array.isArray(orderBy) ? orderBy : orderBy ? [orderBy] : []).flatMap((o) => Object.entries(o))
  const val = (v: unknown) => (v instanceof Date ? v.getTime() : typeof v === 'boolean' ? Number(v) : v) as number | string
  return [...rows].sort((a, b) => {
    for (const [k, dir] of keys) {
      const x = val(a[k]); const y = val(b[k])
      if (x === y) continue
      return (x < y ? -1 : 1) * (dir === 'desc' ? -1 : 1)
    }
    return 0
  })
}

const project = (row: Row, select?: Row) =>
  select ? Object.fromEntries(Object.keys(select).map((k) => [k, structuredClone(row[k])])) : structuredClone(row)

class FakeDb {
  users: Row[] = []
  settings: Row[] = []
  instance: Row | null = null
  audit: Row[] = []
  locks: string[] = []
  userWrites = 0
  failUpsert = false
  private lockTail = new Map<string, Promise<void>>()
  private clock = 0

  async $transaction<T>(fn: (tx: unknown) => Promise<T>, opts?: unknown): Promise<T> {
    expect(opts).toEqual({ timeout: 120_000, maxWait: 30_000 })
    const snapshot = { instance: structuredClone(this.instance), audit: [...this.audit] }
    const releases: (() => void)[] = []
    const refuse = async () => { this.userWrites++; throw new Error('the backfill never writes a user row') }
    const tx = {
      $executeRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
        expect(strings.join('?')).toBe('SELECT pg_advisory_xact_lock(hashtext(?))')
        const key = String(values[0])
        this.locks.push(key)
        const prev = this.lockTail.get(key) ?? Promise.resolve()
        let release!: () => void
        const held = new Promise<void>((r) => { release = r })
        this.lockTail.set(key, prev.then(() => held))
        releases.push(release)
        await prev
        return 1
      },
      auditLog: {
        findFirst: async ({ where, orderBy }: { where: Where; orderBy: OrderBy }) => {
          expect(orderBy).toEqual({ createdAt: 'desc' })
          return sorted(this.audit.filter((r) => matches(r, where)), orderBy)[0] ?? null
        },
        create: async ({ data }: { data: Row }) => {
          const row = { ...structuredClone(data), createdAt: new Date(++this.clock) }
          this.audit.push(row)
          return row
        },
      },
      instanceSettings: {
        findUnique: async ({ where }: { where: { id: string } }) =>
          (this.instance && this.instance.id === where.id ? structuredClone(this.instance) : null),
        upsert: async ({ where, create, update }: { where: { id: string }; create: Row; update: Row }) => {
          // Let a second transaction run up to its lock in between.
          await new Promise((r) => setTimeout(r, 5))
          if (this.failUpsert) throw Object.assign(new Error('canceling statement due to lock timeout'), { code: 'P2010' })
          expect(where).toEqual({ id: SINGLETON_ID })
          this.instance = this.instance
            ? { ...this.instance, ...structuredClone(update), updatedAt: new Date(++this.clock) }
            : { ...structuredClone(create), updatedById: null, updatedAt: new Date(++this.clock) }
          return structuredClone(this.instance)
        },
      },
      userSettings: {
        findMany: async ({ where, orderBy, select }: { where: Where; orderBy: OrderBy; select: Row }) =>
          sorted(this.settings.filter((r) => matches(r, where)), orderBy).map((r) => project(r, select)),
        update: refuse, updateMany: refuse, upsert: refuse, create: refuse,
      },
      user: {
        findMany: async ({ where, select }: { where: Where; select: Row }) =>
          this.users.filter((r) => matches(r, where)).map((r) => project(r, select)),
        update: refuse, updateMany: refuse,
      },
    }
    try {
      return await fn(tx)
    } catch (err) {
      this.instance = snapshot.instance
      this.audit = snapshot.audit
      throw err
    } finally {
      for (const r of releases) r()
    }
  }
}

let db: FakeDb
const markers = () => db.audit.filter((r) => r.action === MARKER_ACTION)
const at = (iso: string) => new Date(iso)

function account(id: string, role = 'standard') { db.users.push({ id, role }) }

function settingsRow(userId: string, over: Row = {}) {
  db.settings.push({
    id: `s-${userId}`, userId, updatedAt: at('2026-03-01T09:00:00Z'),
    ...TUNNEL_DEFAULTS, ...structuredClone(CAPTURE_DEFAULTS), ...over,
  })
}

const instance = () => db.instance as Row

beforeEach(() => { db = new FakeDb() })

describe('the backfill script', () => {
  test('exports the lock key, the marker action and the singleton id', () => {
    expect(LOCK_KEY).toBe('system.rbac_instance_settings')
    expect(MARKER_ACTION).toBe('system.rbac_instance_settings_backfill')
    expect(SINGLETON_ID).toBe('instance')
  })

  test('its tunnel pick and field lists are the readers\' own (src/lib/sharedInstanceSettings.ts)', () => {
    expect(TUNNEL_ROW_ORDER).toEqual(lib.TUNNEL_ROW_ORDER)
    expect(TUNNEL_CANDIDATE_WHERE).toEqual(lib.TUNNEL_CANDIDATE_WHERE)
    expect(TUNNEL_FIELDS).toEqual([...lib.TUNNEL_FIELDS])
    expect(CAPTURE_FIELDS).toEqual([...lib.CAPTURE_FIELDS])
    expect(CAPTURE_ROW_ORDER).toEqual([{ updatedAt: 'desc' }, { id: 'asc' }])
  })

  test('the field lists and defaults are the schema\'s: every moved column, the same @default in both models', () => {
    const models = parsePrismaModels(readFileSync(path.resolve(__dirname, '../../../prisma/schema.prisma'), 'utf8'))
    const defaultOf = (model: string, f: string) => models[model].fields[f].line.match(/@default\((.*?)\)(?:\s|$)/)?.[1]
    const moved = Object.keys(models.InstanceSettings.fields)
      .filter((f) => f.startsWith('capture') && f !== 'captureSourceUserId' || f === 'scaIntelIgnoreSuffixes')
    expect(moved.sort()).toEqual([...CAPTURE_FIELDS].sort())
    const defaults: Row = { ...TUNNEL_DEFAULTS, ...CAPTURE_DEFAULTS }
    for (const f of [...TUNNEL_FIELDS, ...CAPTURE_FIELDS]) {
      const declared = defaultOf('InstanceSettings', f)
      expect(declared, f).toBe(defaultOf('UserSettings', f))
      const value = defaults[f]
      const expected = typeof value === 'string' ? `"${value}"`
        : typeof value === 'object' ? `"${JSON.stringify(value)}"` : String(value)
      expect(declared, f).toBe(expected)
    }
  })

  test.each([
    ['true', true], ['1', true], ['YES', true], [' yes ', true],
    ['', false], ['false', false], ['0', false], ['on', false], [undefined, false],
  ])('RBAC_IDENTITY_ENABLED=%j reads %s, as src/lib/authz/flags.ts reads it', (value, on) => {
    expect(identitySwitchOn(env(value === undefined ? {} : { RBAC_IDENTITY_ENABLED: value }))).toBe(on)
  })
})

describe('backfillRbacInstanceSettings', () => {
  test('tunnel pick is deterministic with two candidates: enabled first, then the latest save, then the lowest id', async () => {
    for (const id of ['m-c', 'm-a', 'm-b', 'm-d']) account(id)
    settingsRow('m-a', { tunnelsEnabled: true, ngrokAuthtoken: 'fake-ngrok-a', updatedAt: at('2026-03-10T09:00:00Z') })
    settingsRow('m-b', { tunnelsEnabled: true, chiselServerUrl: 'https://chisel.b.test', updatedAt: at('2026-03-20T09:00:00Z') })
    settingsRow('m-c', { tunnelsEnabled: false, ngrokAuthtoken: 'fake-ngrok-c', updatedAt: at('2026-05-01T09:00:00Z') })
    settingsRow('m-d', { tunnelsEnabled: true, updatedAt: at('2026-06-01T09:00:00Z') })
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(instance()).toMatchObject({
      id: 'instance', tunnelsEnabled: true, ngrokAuthtoken: '', chiselServerUrl: 'https://chisel.b.test', chiselAuth: '',
      tunnelSourceUserId: 'm-b',
    })
    expect(r.tunnelCandidates).toEqual(['m-b', 'm-a', 'm-c'])

    // The same population in another order picks the same row; a tie in time takes the lowest id.
    db = new FakeDb()
    settingsRow('m-z', { tunnelsEnabled: true, ngrokAuthtoken: 'fake-z', updatedAt: at('2026-03-20T09:00:00Z') })
    settingsRow('m-y', { tunnelsEnabled: true, ngrokAuthtoken: 'fake-y', updatedAt: at('2026-03-20T09:00:00Z') })
    db.settings.find((s) => s.userId === 'm-z')!.id = 's-0'
    await backfillRbacInstanceSettings(db, OFF)
    expect(instance()).toMatchObject({ ngrokAuthtoken: 'fake-z', tunnelSourceUserId: 'm-z' })
  })

  test('capture from the most recent admin row: every capture, egress and SCA value, members ignored', async () => {
    account('admin-a', 'admin'); account('admin-b', 'admin'); account('member')
    settingsRow('admin-a', { captureProxyEnabled: true, updatedAt: at('2026-03-01T09:00:00Z') })
    const bValues: Row = {
      captureProxyEnabled: false, captureProxyPort: 9999, captureProxyScope: 'recon', captureProxyStoreBodies: false,
      captureProxyMaxBodyKb: 128, captureProxyRetentionDays: 30, captureProxyRedactSecrets: false,
      captureProxyPassiveDetect: false, captureProxyStoreReqBodies: false, captureProxyStoreRespBodies: false,
      captureProxyMaxStoreMb: 0, captureProxyBodyRules: { image: 'disk' },
      captureEgressBlockEmptyHost: false, captureEgressBlockHardGuardrail: false, captureEgressFailClosed: false,
      captureEgressBlockUnresolvable: false, captureEgressBlockPrivate: false, captureEgressBlockLoopback: false,
      captureEgressBlockLinkLocal: false, captureEgressBlockCgnat: false, captureEgressBlockReserved: false,
      captureEgressBlockMulticast: false, captureEgressBlockUnspecified: false,
      scaIntelIgnoreSuffixes: 'example.test',
    }
    expect(Object.keys(bValues).sort()).toEqual([...CAPTURE_FIELDS].sort())
    settingsRow('admin-b', { ...bValues, updatedAt: at('2026-04-01T09:00:00Z') })
    settingsRow('member', { captureProxyEnabled: true, captureProxyPort: 1, updatedAt: at('2026-09-01T09:00:00Z') })
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(instance()).toMatchObject({ ...bValues, captureSourceUserId: 'admin-b' })
    expect(r.captureCandidates).toEqual(['admin-b', 'admin-a'])
  })

  test('no candidate -> the defaults, no source, a marker with no candidates', async () => {
    account('member')
    settingsRow('member')
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(instance()).toMatchObject({
      ...TUNNEL_DEFAULTS, ...CAPTURE_DEFAULTS, tunnelSourceUserId: null, captureSourceUserId: null,
    })
    expect(r).toMatchObject({ marker: true, wrote: true, tunnelCandidates: [], captureCandidates: [] })
    expect(markers()).toHaveLength(1)
    expect(markers()[0]).toMatchObject({
      targetType: 'system', source: 'system',
      after: {
        wrote: true, identity: false, tunnelSourceUserId: null, captureSourceUserId: null,
        tunnelCandidates: [], captureCandidates: [],
      },
    })
    expect(db.locks).toEqual([LOCK_KEY])
  })

  test('the marker names both sources and the candidates, never a credential', async () => {
    account('admin-a', 'admin'); account('m-a')
    settingsRow('admin-a')
    settingsRow('m-a', { tunnelsEnabled: true, ngrokAuthtoken: 'fake-ngrok-secret', chiselAuth: 'u:fake-pass' })
    await backfillRbacInstanceSettings(db, OFF)
    expect(markers()[0].after).toEqual({
      wrote: true, identity: false, tunnelSourceUserId: 'm-a', captureSourceUserId: 'admin-a',
      tunnelCandidates: ['m-a'], captureCandidates: ['admin-a'],
    })
    expect(JSON.stringify(db.audit)).not.toMatch(/fake-ngrok-secret|fake-pass/)
  })

  test('idempotent: a second boot writes nothing and records nothing; no user row is ever written', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { tunnelsEnabled: true, ngrokAuthtoken: 'fake' })
    await backfillRbacInstanceSettings(db, OFF)
    const first = structuredClone(db.instance)
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(r).toMatchObject({ marker: false, wrote: false })
    expect(db.instance).toEqual(first)
    expect(markers()).toHaveLength(1)
    expect(db.userWrites).toBe(0)
  })

  test('fills the row the host commands created, never its Root columns', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { captureProxyEnabled: false, chiselServerUrl: 'https://c.test' })
    db.instance = {
      id: 'instance', rootUserId: 'admin-a', rootConfirmedAt: at('2026-11-12T08:00:00Z'), rootAssignedBy: 'host',
      passwordMinLength: 14, ...TUNNEL_DEFAULTS, ...structuredClone(CAPTURE_DEFAULTS),
      tunnelSourceUserId: null, captureSourceUserId: null, updatedById: null,
    }
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(r).toMatchObject({ marker: true, wrote: true })
    expect(instance()).toMatchObject({
      rootUserId: 'admin-a', rootConfirmedAt: at('2026-11-12T08:00:00Z'), rootAssignedBy: 'host', passwordMinLength: 14,
      captureProxyEnabled: false, chiselServerUrl: 'https://c.test', tunnelSourceUserId: 'admin-a', captureSourceUserId: 'admin-a',
    })
  })

  test('a marker without the row (a downgrade dropped the table) fills it again, with a new marker', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { captureProxyRetentionDays: 30 })
    await backfillRbacInstanceSettings(db, OFF)
    db.instance = null
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(r).toMatchObject({ marker: true, wrote: true })
    expect(instance()).toMatchObject({ captureProxyRetentionDays: 30, captureSourceUserId: 'admin-a' })
    expect(markers()).toHaveLength(2)
  })

  test('switch off: a user row changed after the first boot is copied at the next one, without a new marker', async () => {
    account('admin-a', 'admin'); account('admin-b', 'admin')
    settingsRow('admin-a', { captureEgressBlockPrivate: true, updatedAt: at('2026-03-01T09:00:00Z') })
    await backfillRbacInstanceSettings(db, OFF)
    db.settings.push({
      id: 's-admin-b', userId: 'admin-b', updatedAt: at('2026-11-01T09:00:00Z'),
      ...TUNNEL_DEFAULTS, ...structuredClone(CAPTURE_DEFAULTS), captureEgressBlockPrivate: false,
    })
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(r).toMatchObject({ marker: false, wrote: true })
    expect(instance()).toMatchObject({ captureEgressBlockPrivate: false, captureSourceUserId: 'admin-b' })
    expect(markers()).toHaveLength(1)
  })

  test('the first boot with the switch on copies once more and records it; later boots leave the row', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { captureProxyPort: 8888 })
    await backfillRbacInstanceSettings(db, OFF)
    db.settings[0].captureProxyPort = 9000
    db.settings[0].updatedAt = at('2026-11-02T09:00:00Z')
    const r = await backfillRbacInstanceSettings(db, ON)
    expect(r).toMatchObject({ marker: true, wrote: true, identity: true })
    expect(instance().captureProxyPort).toBe(9000)
    expect(markers().map((m) => (m.after as Row).identity)).toEqual([false, true])

    db.settings[0].captureProxyPort = 7000
    const again = await backfillRbacInstanceSettings(db, ON)
    expect(again).toMatchObject({ marker: false, wrote: false })
    expect(instance().captureProxyPort).toBe(9000)
    expect(markers()).toHaveLength(2)
  })

  test('a row an admin wrote through the admin route is never overwritten', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { captureProxyPort: 8888 })
    // No marker yet (every earlier backfill failed) and the switch on: the admin's row stands.
    db.instance = {
      id: 'instance', ...TUNNEL_DEFAULTS, ...structuredClone(CAPTURE_DEFAULTS), captureProxyPort: 9443,
      tunnelSourceUserId: null, captureSourceUserId: 'admin-a', updatedById: 'admin-a',
    }
    const r = await backfillRbacInstanceSettings(db, ON)
    expect(r).toMatchObject({ marker: true, wrote: false, captureSourceUserId: 'admin-a' })
    expect(instance().captureProxyPort).toBe(9443)
    expect(instance().updatedById).toBe('admin-a')
  })

  test('a boot with the switch off again takes the user rows back as the truth', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { captureProxyPort: 8888 })
    await backfillRbacInstanceSettings(db, ON)
    // The admin route wrote the row and mirrored the value into the source row.
    Object.assign(db.instance!, { captureProxyPort: 9443, updatedById: 'admin-a' })
    db.settings[0].captureProxyPort = 9443
    expect(await backfillRbacInstanceSettings(db, ON)).toMatchObject({ wrote: false })
    // Switch off: a member of the admin set changes it through the user route.
    db.settings[0].captureProxyPort = 7000
    const r = await backfillRbacInstanceSettings(db, OFF)
    expect(r).toMatchObject({ marker: false, wrote: true })
    expect(instance()).toMatchObject({ captureProxyPort: 7000, updatedById: null })
  })

  test('two boots at once fill the row once', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { tunnelsEnabled: true, ngrokAuthtoken: 'fake' })
    const [a, b] = await Promise.all([backfillRbacInstanceSettings(db, OFF), backfillRbacInstanceSettings(db, OFF)])
    expect([a.marker, b.marker].sort()).toEqual([false, true])
    expect([a.wrote, b.wrote].sort()).toEqual([false, true])
    expect(markers()).toHaveLength(1)
  })

  test('a failure leaves nothing and never stops the boot; the next boot completes it', async () => {
    account('admin-a', 'admin')
    settingsRow('admin-a', { ngrokAuthtoken: 'fake-ngrok-secret' })
    db.failUpsert = true
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    await expect(run(db, OFF)).resolves.toBeUndefined()
    expect(db.instance).toBeNull()
    expect(markers()).toHaveLength(0)
    expect(error.mock.calls[0].map(String)).toEqual([
      '[rbac] could not fill the instance settings (retried next boot):', 'canceling statement due to lock timeout',
    ])
    db.failUpsert = false
    const log = vi.spyOn(console, 'log').mockImplementation(() => {})
    await run(db, OFF)
    expect(log.mock.calls.map((c) => String(c[0]))).toEqual([
      '[rbac] instance settings filled from the user rows: tunnel from admin-a (1 candidate(s)), capture from admin-a (1 admin row(s)).',
    ])
    expect(JSON.stringify([...log.mock.calls, ...error.mock.calls])).not.toContain('fake-ngrok-secret')
    log.mockRestore(); error.mockRestore()
  })

  test('a validation error is logged by name only: it would quote the credentials', () => {
    const err = Object.assign(new Error('Invalid `tx.instanceSettings.upsert()` invocation: { ngrokAuthtoken: "fake-secret" }'), {
      name: 'PrismaClientValidationError',
    })
    expect(failureReason(err)).toBe('PrismaClientValidationError')
    expect(failureReason(new Error('relation "instance_settings"\n does not exist'))).toBe('relation "instance_settings" does not exist')
  })
})

describe('the startup lists', () => {
  const dockerfile = readFileSync(path.resolve(__dirname, '../../../Dockerfile'), 'utf8')

  test('the entrypoint runs it after db push and the Nuclei backfill, before the server, never fatally', () => {
    const entry = dockerfile.split('\n').find((l) => l.startsWith('RUN printf') && l.includes('entrypoint'))!
    const push = entry.indexOf('db push')
    const nuclei = entry.indexOf('backfill-nuclei-template-owners.mjs')
    const ours = entry.indexOf('backfill-rbac-instance-settings.mjs')
    const server = entry.indexOf('exec node server.js')
    expect(push).toBeGreaterThan(0)
    expect(nuclei).toBeGreaterThan(push)
    expect(ours).toBeGreaterThan(nuclei)
    expect(server).toBeGreaterThan(ours)
    expect(entry).toMatch(/\\nnode scripts\/backfill-rbac-instance-settings\.mjs 2>&1\\n/)
  })

  test('the dev command runs it in the same place', () => {
    const dev = readFileSync(path.resolve(__dirname, '../../../../docker-compose.dev.yml'), 'utf8')
    const lines = dev.split('\n').map((l) => l.trim())
    const nuclei = lines.indexOf('node scripts/backfill-nuclei-template-owners.mjs')
    expect(nuclei).toBeGreaterThan(0)
    expect(lines[nuclei + 1]).toBe('node scripts/backfill-rbac-instance-settings.mjs')
  })
})
