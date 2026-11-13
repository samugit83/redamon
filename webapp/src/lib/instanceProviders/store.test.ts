/**
 * The instance provider store (step 6.11) over a small in-memory double of the two tables and the
 * instance row: what it reads and writes, that a provider's assignments become exactly the sets asked
 * (kept rows untouched), that deleting a provider answers its sets, and that a database the boot
 * `db push` has not given the tables yet (Prisma P2021) reads as `instance_providers_not_ready`.
 * Schema shape and cascade: schemaMaps.test.ts, cascade.test.ts; the real push: the upgrade harness.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/instanceProviders/store.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))

import {
  InstanceProvidersNotReady, createInstanceProvider, deleteInstanceProvider, providersAssignedToSet, readByoLlmForbidden,
  readInstanceProvider, readInstanceProviders, readProviderAssignments, updateInstanceProvider, writeByoLlmForbidden,
  type InstanceProviderData,
} from './store'

type Row = Record<string, unknown>
function matches(row: Row, where: Row = {}): boolean {
  return Object.entries(where).every(([k, v]) => {
    if (v && typeof v === 'object' && 'in' in (v as Row)) return ((v as { in: unknown[] }).in).includes(row[k])
    return row[k] === v
  })
}

function fakeDb() {
  let seq = 0
  const providers: Row[] = []
  let assignments: Row[] = []
  let instance: Row | null = { id: 'instance', byoLlmForbidden: false }
  const queries: string[] = []
  const pick = (r: Row, select?: Row) => (select ? Object.fromEntries(Object.keys(select).map((k) => [k, r[k]])) : { ...r })
  const db = {
    instanceLlmProvider: {
      findMany: async (a: { where?: Row }) => { queries.push('providers.findMany'); return providers.filter((p) => matches(p, a.where)).map((p) => ({ ...p })) },
      findUnique: async (a: { where: Row }) => { const p = providers.find((x) => matches(x, a.where)); return p ? { ...p } : null },
      create: async (a: { data: Row }) => {
        const row = { id: `inst-${++seq}`, createdAt: new Date(seq), updatedAt: new Date(seq), updatedById: null, ...a.data }
        providers.push(row)
        return { ...row }
      },
      update: async (a: { where: Row; data: Row }) => {
        const p = providers.find((x) => matches(x, a.where))
        if (!p) throw Object.assign(new Error('not found'), { code: 'P2025' })
        Object.assign(p, a.data)
        return { ...p }
      },
      delete: async (a: { where: Row }) => {
        const i = providers.findIndex((x) => matches(x, a.where))
        if (i < 0) throw Object.assign(new Error('not found'), { code: 'P2025' })
        const [gone] = providers.splice(i, 1)
        assignments = assignments.filter((x) => x.providerId !== gone.id)
        return gone
      },
    },
    permissionSetProvider: {
      findMany: async (a: { where?: Row; select?: Row }) => assignments.filter((x) => matches(x, a.where)).map((x) => pick(x, a.select)),
      deleteMany: async (a: { where?: Row }) => {
        const before = assignments.length
        assignments = assignments.filter((x) => !matches(x, a.where))
        return { count: before - assignments.length }
      },
      createMany: async (a: { data: Row[] }) => {
        for (const d of a.data) assignments.push({ createdAt: new Date(0), ...d })
        return { count: a.data.length }
      },
    },
    instanceSettings: {
      findUnique: async (a: { select?: Row }) => (instance ? pick(instance, a.select) : null),
      update: async (a: { data: Row }) => { Object.assign(instance!, a.data); return instance },
    },
  }
  return {
    db, queries, providers, assignments: () => assignments,
    dropInstance: () => { instance = null },
  }
}

const DATA: InstanceProviderData = {
  providerType: 'openai', name: 'Shared', apiKey: 'sk-1', baseUrl: '', modelIdentifier: '', defaultHeaders: {},
  timeout: 120, temperature: 0, maxTokens: 16384, sslVerify: true, reasoningEnabled: false, reasoningEffort: 'high',
  awsRegion: 'us-east-1', awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '',
}

let f: ReturnType<typeof fakeDb>
beforeEach(() => { f = fakeDb() })
const tx = () => f.db as never

describe('writes', () => {
  test('create stores the provider with its author and exactly its sets', async () => {
    const p = await createInstanceProvider(tx(), { data: DATA, setIds: ['builtin:recon-operator', 'set-red'], actorId: 'root-1' })
    expect(p).toMatchObject({ id: 'inst-1', name: 'Shared', apiKey: 'sk-1', createdById: 'root-1' })
    expect(f.assignments().map((a) => [a.setId, a.providerId, a.createdById])).toEqual([
      ['builtin:recon-operator', 'inst-1', 'root-1'], ['set-red', 'inst-1', 'root-1']])
  })

  test('update replaces the settings and makes the sets exactly the ones asked, kept rows untouched', async () => {
    await createInstanceProvider(tx(), { data: DATA, setIds: ['set-a', 'set-b'], actorId: 'root-1' })
    const kept = f.assignments().find((a) => a.setId === 'set-b')
    const { provider, setIdsBefore } = await updateInstanceProvider(tx(), 'inst-1', { data: { ...DATA, name: 'Renamed' }, setIds: ['set-b', 'set-c'], actorId: 'root-2' })
    expect(setIdsBefore).toEqual(['set-a', 'set-b'])
    expect(provider).toMatchObject({ name: 'Renamed', updatedById: 'root-2' })
    expect(f.assignments().map((a) => a.setId).sort()).toEqual(['set-b', 'set-c'])
    expect(f.assignments().find((a) => a.setId === 'set-b')).toBe(kept)
  })

  test('delete answers the sets it had and takes them with it', async () => {
    await createInstanceProvider(tx(), { data: DATA, setIds: ['set-b', 'set-a'], actorId: 'root-1' })
    expect(await deleteInstanceProvider(tx(), 'inst-1')).toEqual(['set-a', 'set-b'])
    expect(f.providers).toEqual([])
    expect(f.assignments()).toEqual([])
  })

  test('the policy is written on the instance row', async () => {
    await writeByoLlmForbidden(tx(), true)
    expect(await readByoLlmForbidden(tx())).toBe(true)
  })
})

describe('reads', () => {
  test('providers, one provider, assignments and the providers of a set', async () => {
    await createInstanceProvider(tx(), { data: DATA, setIds: ['set-a'], actorId: 'root-1' })
    await createInstanceProvider(tx(), { data: { ...DATA, name: 'Two' }, setIds: ['set-a', 'set-b'], actorId: 'root-1' })
    expect((await readInstanceProviders(undefined, tx())).map((p) => p.id)).toEqual(['inst-1', 'inst-2'])
    expect((await readInstanceProviders(['inst-2'], tx())).map((p) => p.name)).toEqual(['Two'])
    expect(await readInstanceProvider('inst-9', tx())).toBeNull()
    expect(await readProviderAssignments(['inst-2'], tx())).toEqual([{ setId: 'set-a', providerId: 'inst-2' }, { setId: 'set-b', providerId: 'inst-2' }])
    expect(await providersAssignedToSet('set-a', tx())).toEqual(['inst-1', 'inst-2'])
  })

  test('an empty id list asks the database nothing', async () => {
    expect(await readInstanceProviders([], tx())).toEqual([])
    expect(f.queries).toEqual([])
  })

  test('no instance row yet: the policy reads off', async () => {
    f.dropInstance()
    expect(await readByoLlmForbidden(tx())).toBe(false)
  })
})

describe('a database without the tables yet', () => {
  test('P2021 reads as instance_providers_not_ready; any other failure is thrown as it is', async () => {
    const missing = Object.assign(new Error('The table does not exist'), { code: 'P2021' })
    const db = { instanceLlmProvider: { findMany: async () => { throw missing } }, permissionSetProvider: { findMany: async () => { throw new Error('db down') } } }
    await expect(readInstanceProviders(undefined, db as never)).rejects.toBeInstanceOf(InstanceProvidersNotReady)
    await expect(readProviderAssignments(undefined, db as never)).rejects.toThrow('db down')
  })
})
