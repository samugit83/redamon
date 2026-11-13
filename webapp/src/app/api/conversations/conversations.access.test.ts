/**
 * Conversation privacy, sharing and retention (step 5.8; SH-22, DV-23, T24, OQ-07): the real routes, guards,
 * can(), projectAccess() and conversationAccess.ts over one in-memory database (the share routes' store,
 * shareDb.ts, plus conversations, their shares and the project access policy). The session, the agent and
 * Neo4j are doubles.
 *
 * On P1 (alice's): bob and carol hold Read + Write with Use AI agent (the owner consents), frank is a
 * co-owner with Use AI agent, dave a Read share with Raw data & files, erin a Read share without it; root is
 * the confirmed Root with break-glass on P1 when a test opens it; admin-1 an overseer (Full admin).
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/conversations/conversations.access.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { NextRequest } from 'next/server'
import { createShareDb, shareAccount, type ShareAccount, type ShareDb } from '@/lib/authz/__testing__/shareDb'

type Conv = {
  id: string; projectId: string; userId: string; sessionId: string; title: string; status: string
  agentRunning: boolean; currentPhase: string; iterationCount: number; activeSkillId: string
  createdAt: Date; updatedAt: Date; formerAuthorId: string | null; formerAuthorLabel: string | null
}

const h = vi.hoisted(() => ({
  client: null as unknown as Record<string | symbol, unknown>,
  identity: null as null | { session: { userId: string; role: string }; principal: unknown; actingAs: unknown },
  agentFetch: vi.fn(),
  neo4jRun: vi.fn(),
}))
vi.mock('@/lib/prisma', () => {
  const client = new Proxy({}, { get: (_t, k) => h.client[k] })
  return { default: client, prisma: client }
})
vi.mock('@/lib/session', () => ({
  getAuthzIdentity: async () => h.identity,
  getSession: async () => h.identity?.session ?? null,
  getEffectiveUser: async () => (h.identity ? { userId: (h.identity.principal as { id: string }).id } : null),
  isInternalRequest: () => false,
  mayActAs: async () => true,
  actAsInForce: async () => null,
}))
vi.mock('@/lib/agentFetch', () => {
  class AgentUnreachableError extends Error {}
  return { agentFetch: (...a: unknown[]) => h.agentFetch(...a), AgentUnreachableError }
})
vi.mock('../graph/neo4j', () => ({
  getGraphSession: () => ({ run: (...a: unknown[]) => h.neo4jRun(...a), close: async () => {} }),
}))

import { GET as LIST } from './route'
import { GET as GET_ONE, PATCH, DELETE } from './[id]/route'
import { POST as APPEND } from './[id]/messages/route'
import { POST as SHARE } from './[id]/share/route'
import { GET as GET_BY_SESSION } from './by-session/[sessionId]/route'
import { GET as GET_FIRETEAMS } from './by-session/[sessionId]/fireteams/route'
import { GET as GET_POLICY, POST as SET_POLICY } from './policy/route'
import { reassignConversationsOfDeletedAuthor, othersReader } from '@/lib/authz/conversationAccess'
import { setFlagsForTests } from '@/lib/authz/flags'
import { setNowForTests } from '@/lib/authz/clock'
import { clearSharingPolicyCacheForTests } from '@/lib/authz/sharingPolicy'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import { clearPrincipalCacheForTests } from '@/lib/authz/principal'
import { clearOversightMemoForTests } from '@/lib/authz/oversight'

const T0 = new Date('2026-11-13T12:00:00Z')
let db: ShareDb
let conversations: Conv[]
let shares: Map<string, { id: string; conversationId: string; sharedById: string }>
let policies: Map<string, { ownerCredentialConsentAt: Date | null; ownerCredentialConsentById: string | null; managersSeeAllConversations: boolean }>
let messages: Array<{ conversationId: string; sequenceNum: number; type: string }>
const accounts: Record<string, ShareAccount> = {}

type Where = Record<string, unknown>

function convMatches(row: Conv, where: Where | undefined): boolean {
  if (!where) return true
  for (const [k, v] of Object.entries(where)) {
    if (k === 'OR') { if (!(v as Where[]).some(w => convMatches(row, w))) return false; continue }
    if (k === 'share') { const has = [...shares.values()].some(s => s.conversationId === row.id); if ((v as { isNot: null }).isNot === null && !has) return false; continue }
    if (k === 'project') {
      const ownerNot = ((v as { userId: { not: string } }).userId).not
      if (projectOwners.get(row.projectId) === ownerNot) return false
      continue
    }
    if (k === 'id' && v && typeof v === 'object' && 'in' in (v as object)) { if (!(v as { in: string[] }).in.includes(row.id)) return false; continue }
    if ((row as Record<string, unknown>)[k] !== v) return false
  }
  return true
}
const projectOwners = new Map<string, string>()

function shaped(row: Conv, select?: Record<string, unknown>, include?: Record<string, unknown>): Record<string, unknown> {
  const full: Record<string, unknown> = { ...row }
  if (!select) {
    if (include?.messages) full.messages = messages.filter(m => m.conversationId === row.id)
    return full
  }
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(select)) {
    if (!v) continue
    if (k === 'user') { const u = accounts[row.userId]; out.user = u ? { name: u.name, email: u.email } : null }
    else if (k === 'share') { const s = [...shares.values()].find(x => x.conversationId === row.id); out.share = s ? { id: s.id } : null }
    else if (k === 'project') out.project = { userId: projectOwners.get(row.projectId) }
    else if (k === '_count') out._count = { messages: messages.filter(m => m.conversationId === row.id).length }
    else out[k] = full[k]
  }
  return out
}

function conversationTable() {
  const find = (where: Where) => conversations.find(c => ('id' in where ? c.id === where.id : c.sessionId === where.sessionId)) ?? null
  return {
    findUnique: async ({ where, select, include }: { where: Where; select?: Record<string, unknown>; include?: Record<string, unknown> }) => {
      const row = find(where)
      return row ? shaped(row, select, include) : null
    },
    findMany: async ({ where, select }: { where: Where; select?: Record<string, unknown> }) =>
      conversations.filter(c => convMatches(c, where)).map(c => shaped(c, select)),
    update: async ({ where, data }: { where: Where; data: Partial<Conv> }) => {
      const row = find(where)
      if (!row) throw Object.assign(new Error('missing'), { code: 'P2025' })
      Object.assign(row, data)
      return { ...row }
    },
    updateMany: async ({ where, data }: { where: Where; data: Partial<Conv> }) => {
      const hit = conversations.filter(c => convMatches(c, where))
      for (const c of hit) Object.assign(c, data)
      return { count: hit.length }
    },
    delete: async ({ where }: { where: Where }) => {
      const row = find(where)
      if (!row) throw Object.assign(new Error('missing'), { code: 'P2025' })
      conversations = conversations.filter(c => c !== row)
      for (const [k, s] of shares) if (s.conversationId === row.id) shares.delete(k)
      return row
    },
  }
}

function addConversation(id: string, userId: string, over: Partial<Conv> = {}) {
  conversations.push({
    id, projectId: 'P1', userId, sessionId: `s-${id}`, title: id, status: 'active', agentRunning: false,
    currentPhase: 'informational', iterationCount: 0, activeSkillId: '', createdAt: T0, updatedAt: T0,
    formerAuthorId: null, formerAuthorLabel: null, ...over,
  })
}

function signIn(id: string) {
  const principal = accounts[id]
  h.identity = { session: { userId: id, role: principal.role }, principal, actingAs: null }
}

const req = (url: string, init?: { method?: string; body?: unknown }) => new NextRequest(`http://localhost${url}`, {
  method: init?.method ?? 'GET',
  ...(init?.body !== undefined ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(init.body) } : {}),
})
const idp = (id: string) => ({ params: Promise.resolve({ id }) })
const sp = (sessionId: string) => ({ params: Promise.resolve({ sessionId }) })
const list = async () => {
  const res = await LIST(req('/api/conversations?projectId=P1'))
  return { status: res.status, body: await res.json() }
}
const listIds = async () => ((await list()).body as Array<{ id: string }>).map(c => c.id).sort()
const open = async (id: string) => {
  const res = await GET_ONE(req(`/api/conversations/${id}`), idp(id))
  return { status: res.status, body: await res.json() }
}
const share = (id: string, shared: boolean) => SHARE(req(`/api/conversations/${id}/share`, { method: 'POST', body: { shared } }), idp(id))
const setPolicy = (value: boolean) =>
  SET_POLICY(req('/api/conversations/policy?projectId=P1', { method: 'POST', body: { managersSeeAllConversations: value } }))
const readersOf = async (id: string, who: string[]) => {
  const out: string[] = []
  for (const w of who) {
    signIn(w)
    if ((await open(id)).status === 200) out.push(w)
  }
  return out
}
const EVERYONE = ['alice', 'bob', 'carol', 'frank', 'dave', 'erin', 'root', 'admin-1']

beforeEach(() => {
  setNowForTests(() => T0)
  db = createShareDb(() => T0)
  conversations = []
  shares = new Map()
  policies = new Map([['P1', { ownerCredentialConsentAt: T0, ownerCredentialConsentById: 'alice', managersSeeAllConversations: false }]])
  messages = [{ conversationId: 'c-bob', sequenceNum: 0, type: 'user_message' }]
  projectOwners.clear()
  let shareSeq = 0
  const shareTable = {
    findUnique: async ({ where }: { where: { conversationId: string } }) => {
      const s = [...shares.values()].find(x => x.conversationId === where.conversationId)
      return s ? { id: s.id } : null
    },
    create: async ({ data }: { data: { conversationId: string; sharedById: string } }) => {
      shareSeq += 1
      const row = { id: `sh${shareSeq}`, ...data }
      shares.set(row.id, row)
      return row
    },
    deleteMany: async ({ where }: { where: { conversationId: string } }) => {
      let count = 0
      for (const [k, s] of shares) if (s.conversationId === where.conversationId) { shares.delete(k); count++ }
      return { count }
    },
  }
  const policyTable = {
    findUnique: async ({ where, select }: { where: { projectId: string }; select: Record<string, boolean> }) => {
      const row = policies.get(where.projectId)
      return row ? Object.fromEntries(Object.keys(select).map(k => [k, (row as Record<string, unknown>)[k]])) : null
    },
    upsert: async ({ where, create, update }: { where: { projectId: string }; create: Record<string, unknown>; update: Record<string, unknown> }) => {
      const prev = policies.get(where.projectId)
      const next = prev ? { ...prev, ...update } : { ownerCredentialConsentAt: null, ownerCredentialConsentById: null, managersSeeAllConversations: false, ...create }
      policies.set(where.projectId, next as never)
      return next
    },
  }
  const client: Record<string | symbol, unknown> = {
    ...db.client,
    conversation: conversationTable(),
    conversationShare: shareTable,
    projectAccessPolicy: policyTable,
    chatMessage: {
      aggregate: async () => ({ _max: { sequenceNum: 0 } }),
      createMany: async ({ data }: { data: unknown[] }) => ({ count: data.length }),
    },
    fireteam: { findMany: async () => [] },
  }
  client.$transaction = (fn: (tx: unknown) => Promise<unknown>) => (db.client.$transaction as (f: () => Promise<unknown>) => Promise<unknown>)(async () => {
    const saved = { conversations: conversations.map(c => ({ ...c })), shares: new Map(shares), policies: new Map(policies) }
    try {
      return await fn(client)
    } catch (err) {
      ;({ conversations, shares, policies } = saved)
      throw err
    }
  })
  h.client = client
  for (const k of Object.keys(accounts)) delete accounts[k]
  for (const a of [
    shareAccount('alice', { name: 'Alice Owner' }), shareAccount('bob', { name: 'Bob Writer' }), shareAccount('carol', { name: 'Carol Writer' }),
    shareAccount('frank', { name: 'Frank CoOwner' }), shareAccount('dave', { name: 'Dave Raw' }), shareAccount('erin', { name: 'Erin Reader' }),
    shareAccount('root', { role: 'admin', name: 'Rita Root' }), shareAccount('admin-1', { role: 'admin', name: 'Ada Admin' }),
  ]) {
    accounts[a.id] = a
    db.addUser(a)
  }
  db.addProject('P1', 'alice')
  projectOwners.set('P1', 'alice')
  db.addShare({ projectId: 'P1', userId: 'bob', access: 'write', useAgent: true })
  db.addShare({ projectId: 'P1', userId: 'carol', access: 'write', useAgent: true })
  db.addShare({ projectId: 'P1', userId: 'frank', access: 'write', useAgent: true, manage: true })
  db.addShare({ projectId: 'P1', userId: 'dave', access: 'read', rawData: true })
  db.addShare({ projectId: 'P1', userId: 'erin', access: 'read' })
  db.setPolicy({ enabled: true, maxLevel: 'write' })
  db.setRoot('root', new Date('2026-10-01T00:00:00Z'))
  addConversation('c-alice', 'alice')
  addConversation('c-bob', 'bob')
  addConversation('c-carol', 'carol')
  h.agentFetch.mockReset().mockResolvedValue(new Response('{}', { status: 200 }))
  h.neo4jRun.mockReset().mockResolvedValue({ records: [] })
  setFlagsForTests({ identity: true, permissions: true, sharing: true, sharingWrite: true })
  clearSharingPolicyCacheForTests()
  clearCapabilityCachesForTests()
  clearInstanceRootCacheForTests()
  clearPrincipalCacheForTests()
  clearOversightMemoForTests()
  vi.spyOn(console, 'info').mockImplementation(() => {})
})
afterEach(() => {
  setFlagsForTests(null)
  setNowForTests(null)
  h.identity = null
  vi.restoreAllMocks()
})

describe('conversations are private by default (step 5.8, SH-22)', () => {
  test("a collaborator's conversation is invisible to everyone else: the owner, other collaborators, Root and an overseer", async () => {
    expect(await readersOf('c-bob', EVERYONE)).toEqual(['bob'])
    signIn('carol')
    expect(await listIds()).toEqual(['c-carol'])
    signIn('alice')
    expect(await listIds()).toEqual(['c-alice'])
    signIn('carol')
    expect((await GET_BY_SESSION(req('/api/conversations/by-session/s-c-bob'), sp('s-c-bob'))).status).toBe(404)
    expect((await GET_FIRETEAMS(req('/api/conversations/by-session/s-c-bob/fireteams'), sp('s-c-bob'))).status).toBe(404)
    // An overseer's refused attempt writes no oversight row (no guard ran for a reader below Raw data).
    expect(db.audit().filter(r => r.action === 'project.oversee')).toEqual([])
  })

  test('the author reads their own, with its view', async () => {
    signIn('bob')
    const own = await open('c-bob')
    expect(own.status).toBe(200)
    expect(own.body.access).toEqual({ mine: true, readOnly: false, shared: false, by: null, authorDeleted: false })
    expect((await list()).body).toEqual([expect.objectContaining({ id: 'c-bob', access: { mine: true, readOnly: false, shared: false, by: null, authorDeleted: false } })])
    expect((await list()).body[0]).not.toHaveProperty('userId')
  })
})

describe('every read path asks a permission with a project level (levelLessHelpers.test.ts)', () => {
  test("the author's read asks agent:chat: a writer without Use AI agent is refused their own; another person's asks graph:read at R*", async () => {
    const guards = await import('@/lib/authz/guards')
    const asked = vi.spyOn(guards, 'requirePermission')
    db.addShare({ projectId: 'P1', userId: 'carol', access: 'write' })
    signIn('carol')
    const own = await open('c-carol')
    expect([own.status, own.body.permission]).toEqual([403, 'agent:chat'])
    signIn('bob')
    await share('c-bob', true)
    asked.mockClear()
    signIn('dave')
    expect((await open('c-bob')).status).toBe(200)
    expect(asked.mock.calls.map(([, permission]) => permission)).toEqual(['graph:read'])
    // The managers policy never opens through a level below R*: a Read share without Raw data, even shared.
    signIn('erin')
    expect((await open('c-bob')).status).toBe(404)
  })
})

describe('a shared conversation is readable by the project, not writable (SH-22)', () => {
  test('the author shares it: everyone on the project with Raw data reads it read-only; nobody else writes it; unsharing closes it again', async () => {
    signIn('bob')
    const shared = await share('c-bob', true)
    expect([shared.status, await shared.json()]).toEqual([200, { shared: true, changed: true }])
    expect(db.audit().filter(r => r.action === 'conversation.share')).toEqual([
      expect.objectContaining({ actorId: 'bob', projectId: 'P1', permission: 'agent:conversations_share', targetType: 'conversation', targetId: 'c-bob' }),
    ])
    // Read at R*: the owner, both writers, the co-owner, the Read share with Raw data, Root's break-glass
    // (none open yet, so not Root); not the Read share without Raw data, nor the overseer.
    expect(await readersOf('c-bob', EVERYONE)).toEqual(['alice', 'bob', 'carol', 'frank', 'dave'])
    signIn('carol')
    const opened = await open('c-bob')
    expect(opened.body.access).toEqual({ mine: false, readOnly: true, shared: true, by: 'Bob Writer', authorDeleted: false })
    expect(opened.body.messages).toHaveLength(1)
    expect(await listIds()).toEqual(['c-bob', 'c-carol'])
    expect((await GET_BY_SESSION(req('/api/conversations/by-session/s-c-bob'), sp('s-c-bob'))).status).toBe(200)
    expect((await GET_FIRETEAMS(req('/api/conversations/by-session/s-c-bob/fireteams'), sp('s-c-bob'))).status).toBe(200)
    // Below the agent's level, a Read share with Raw data lists what is shared and has no own.
    signIn('dave')
    expect(await listIds()).toEqual(['c-bob'])
    signIn('erin')
    expect((await list()).status).toBe(403)

    // Not writable by anyone but its author: the same 404 as before.
    for (const who of ['carol', 'alice', 'frank']) {
      signIn(who)
      expect([who, (await PATCH(req('/api/conversations/c-bob', { method: 'PATCH', body: { title: 'x' } }), idp('c-bob'))).status]).toEqual([who, 404])
      expect([who, (await APPEND(req('/api/conversations/c-bob/messages', { method: 'POST', body: { type: 'user_message', data: {} } }), idp('c-bob'))).status]).toEqual([who, 404])
      expect([who, (await DELETE(req('/api/conversations/c-bob', { method: 'DELETE' }), idp('c-bob'))).status]).toEqual([who, 404])
      expect([who, (await share('c-bob', false)).status]).toEqual([who, 404])
    }
    expect(conversations.find(c => c.id === 'c-bob')?.title).toBe('c-bob')

    signIn('bob')
    expect(await (await share('c-bob', false)).json()).toEqual({ shared: false, changed: true })
    expect(await readersOf('c-bob', EVERYONE)).toEqual(['bob'])
  })

  test('sharing twice changes nothing and writes one row; a non-boolean is refused', async () => {
    signIn('bob')
    await share('c-bob', true)
    expect(await (await share('c-bob', true)).json()).toEqual({ shared: true, changed: false })
    expect(db.audit().filter(r => r.action === 'conversation.share')).toHaveLength(1)
    expect((await SHARE(req('/api/conversations/c-bob/share', { method: 'POST', body: { shared: 'yes' } }), idp('c-bob'))).status).toBe(400)
  })

  test('a failed audit row undoes the share', async () => {
    signIn('bob')
    db.failAudit('conversation.share')
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect((await share('c-bob', true)).status).toBe(500)
    expect(shares.size).toBe(0)
  })

  test('a collaborator without Use AI agent cannot share their own (agent:conversations_share is W+A)', async () => {
    db.addShare({ projectId: 'P1', userId: 'carol', access: 'write' })
    signIn('carol')
    expect((await share('c-carol', true)).status).toBe(403)
  })
})

describe('the owner\'s policy lets managers read all (OQ-07)', () => {
  test('the owner turns it on: the owner and the co-owner read every conversation; a writer still reads only shared ones; off closes them', async () => {
    signIn('frank')
    const refused = await setPolicy(true)
    expect([refused.status, (await refused.json()).level]).toEqual([403, 'O'])
    signIn('alice')
    expect(await (await GET_POLICY(req('/api/conversations/policy?projectId=P1'))).json()).toEqual({ managersSeeAllConversations: false })
    const on = await setPolicy(true)
    expect([on.status, await on.json()]).toEqual([200, { managersSeeAllConversations: true, changed: true }])
    expect(db.audit().filter(r => r.action === 'project.conversations_policy')).toEqual([
      expect.objectContaining({ actorId: 'alice', projectId: 'P1', after: { managersSeeAllConversations: true } }),
    ])
    // The consent stays as it was on the shared row.
    expect(policies.get('P1')).toMatchObject({ ownerCredentialConsentAt: T0, managersSeeAllConversations: true })

    expect(await readersOf('c-bob', EVERYONE)).toEqual(['alice', 'bob', 'frank'])
    signIn('frank')
    expect(await listIds()).toEqual(['c-alice', 'c-bob', 'c-carol'])
    expect((await open('c-bob')).body.access).toMatchObject({ mine: false, readOnly: true, shared: false, by: 'Bob Writer' })
    // A collaborator sees the policy, so they know who reads their conversations.
    signIn('carol')
    expect(await (await GET_POLICY(req('/api/conversations/policy?projectId=P1'))).json()).toEqual({ managersSeeAllConversations: true })
    expect(await listIds()).toEqual(['c-carol'])

    signIn('alice')
    await setPolicy(false)
    expect(await readersOf('c-bob', EVERYONE)).toEqual(['bob'])
  })
})

describe("break-glass reads private conversations; oversight does not (step 4.14's access)", () => {
  test("Root's live break-glass reads and lists every conversation; it ends with the break-glass", async () => {
    db.addBreakGlass('P1', 'root', new Date(T0.getTime() + 3_600_000))
    signIn('root')
    expect((await open('c-bob')).status).toBe(200)
    expect(await listIds()).toEqual(['c-alice', 'c-bob', 'c-carol'])
    // Read-only: break-glass writes nothing.
    expect((await PATCH(req('/api/conversations/c-bob', { method: 'PATCH', body: { title: 'x' } }), idp('c-bob'))).status).toBe(404)
    setNowForTests(() => new Date(T0.getTime() + 7_200_000))
    expect((await open('c-bob')).status).toBe(404)
  })

  test('the pure rule: below R* nothing; break-glass every one; shared any reader at R*; the policy only Manage', () => {
    const at = (level: 'owner' | 'write' | 'read', via: 'owner' | 'share' | 'break_glass' | 'oversight', toggles: Record<string, boolean>) =>
      ({ level, via, toggles: { rawData: false, ...toggles } })
    const none = { shared: false, managersSeeAll: false }
    expect(othersReader(at('read', 'oversight', {}), { shared: true, managersSeeAll: true })).toBeNull()
    expect(othersReader(at('read', 'share', {}), { shared: true, managersSeeAll: true })).toBeNull()
    expect(othersReader(at('read', 'break_glass', { rawData: true }), none)).toBe('break_glass')
    expect(othersReader(at('read', 'share', { rawData: true }), { shared: true, managersSeeAll: false })).toBe('shared')
    expect(othersReader(at('read', 'share', { rawData: true }), { shared: false, managersSeeAll: true })).toBeNull()
    expect(othersReader(at('write', 'share', { rawData: true }), { shared: false, managersSeeAll: true })).toBeNull()
    expect(othersReader(at('write', 'share', { rawData: true, manage: true }), { shared: false, managersSeeAll: true })).toBe('managers')
    expect(othersReader(at('owner', 'owner', { rawData: true }), { shared: false, managersSeeAll: true })).toBe('managers')
    expect(othersReader(at('owner', 'owner', { rawData: true }), none)).toBeNull()
  })
})

describe("a deleted collaborator's conversations: reassigned with the former author, read-only (T24, DV-23)", () => {
  test('the reassignment moves the conversations in other people\'s projects to each owner and keeps the former author', async () => {
    db.addProject('P2', 'bob')
    projectOwners.set('P2', 'bob')
    addConversation('c-bob-own', 'bob', { projectId: 'P2' })
    const moved = await reassignConversationsOfDeletedAuthor(h.client as never, 'bob', 'Bob Writer')
    expect(moved).toBe(1)
    expect(conversations.find(c => c.id === 'c-bob')).toMatchObject({ userId: 'alice', formerAuthorId: 'bob', formerAuthorLabel: 'Bob Writer' })
    // The author's own project is the teardown's, not reassigned.
    expect(conversations.find(c => c.id === 'c-bob-own')).toMatchObject({ userId: 'bob', formerAuthorId: null })
    // With the write switch off nothing is read or moved.
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    expect(await reassignConversationsOfDeletedAuthor(h.client as never, 'carol', 'Carol')).toBeNull()
    expect(conversations.find(c => c.id === 'c-carol')?.userId).toBe('carol')
  })

  test('the owner reads it "by <former author> (account deleted)", read-only: no title change, no message; the owner may delete it', async () => {
    addConversation('c-gone', 'alice', { formerAuthorId: 'gone-user', formerAuthorLabel: 'Gina Gone' })
    signIn('alice')
    const opened = await open('c-gone')
    expect(opened.body.access).toEqual({ mine: true, readOnly: true, shared: false, by: 'Gina Gone', authorDeleted: true })
    const patched = await PATCH(req('/api/conversations/c-gone', { method: 'PATCH', body: { title: 'x' } }), idp('c-gone'))
    expect([patched.status, (await patched.json()).code]).toEqual([409, 'conversation_read_only'])
    const appended = await APPEND(req('/api/conversations/c-gone/messages', { method: 'POST', body: { type: 'user_message', data: {} } }), idp('c-gone'))
    expect([appended.status, (await appended.json()).code]).toEqual([409, 'conversation_read_only'])
    expect((await DELETE(req('/api/conversations/c-gone', { method: 'DELETE' }), idp('c-gone'))).status).toBe(200)
    expect(conversations.some(c => c.id === 'c-gone')).toBe(false)
  })
})

describe('the author keeps deleting their own', () => {
  test('a shared conversation is deleted by its author, its share with it', async () => {
    signIn('bob')
    await share('c-bob', true)
    const res = await DELETE(req('/api/conversations/c-bob', { method: 'DELETE' }), idp('c-bob'))
    expect(res.status).toBe(200)
    expect(conversations.some(c => c.id === 'c-bob')).toBe(false)
    expect(shares.size).toBe(0)
    // The agent stop names the author; the graph delete the owner (step 5.3).
    expect(JSON.parse((h.agentFetch.mock.calls[0][1] as RequestInit).body as string)).toMatchObject({ user_id: 'bob' })
    expect(h.neo4jRun.mock.calls[0][1]).toMatchObject({ userId: 'alice', chainId: 's-c-bob' })
  })
})

describe('write sharing not in force: nothing changes (DV-30)', () => {
  test.each([
    ['the write switch off', { identity: true, permissions: true, sharing: true }, { enabled: true, maxLevel: 'write' }],
    ["Root's policy at Read", { identity: true, permissions: true, sharing: true, sharingWrite: true }, { enabled: true, maxLevel: 'read' }],
  ])('%s: a shared conversation is private again, the share and policy routes are gone', async (_what, flags, policy) => {
    shares.set('sh0', { id: 'sh0', conversationId: 'c-bob', sharedById: 'bob' })
    policies.get('P1')!.managersSeeAllConversations = true
    db.setPolicy(policy)
    setFlagsForTests(flags)
    clearSharingPolicyCacheForTests()
    expect(await readersOf('c-bob', ['alice', 'carol', 'frank', 'dave', 'root'])).toEqual([])
    signIn('bob')
    expect((await share('c-bob', false)).status).toBe(404)
    expect((await GET_POLICY(req('/api/conversations/policy?projectId=P1'))).status).toBe(404)
    signIn('alice')
    expect((await setPolicy(false)).status).toBe(404)
    expect(policies.get('P1')?.managersSeeAllConversations).toBe(true)
    expect(await listIds()).toEqual(['c-alice'])
  })

  test('the write switch off: the list and the conversation answer exactly as before, without a view', async () => {
    setFlagsForTests({ identity: true, permissions: true, sharing: true })
    signIn('alice')
    const listed = (await list()).body
    expect(listed.map((c: { id: string }) => c.id)).toEqual(['c-alice'])
    expect(Object.keys(listed[0]).sort()).toEqual([
      '_count', 'activeSkillId', 'agentRunning', 'createdAt', 'currentPhase', 'id', 'iterationCount', 'sessionId', 'status', 'title', 'updatedAt',
    ])
    const own = await open('c-alice')
    expect(own.status).toBe(200)
    expect(own.body).not.toHaveProperty('access')
  })
})
