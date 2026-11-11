/**
 * HD-23 across every handler of an account's own data (F-19): the admin bypass is a
 * masked READ. Each write handler (settings, LLM providers, MCP servers, attack and chat
 * skills, tradecraft, the upload dialog's routes, the onboarding pack, the provider and
 * MCP tests) refuses an admin on another account, through act-as or not, before any
 * database write or service call; an admin acting as a passwordless managed account and
 * the account itself pass the gate; every read handler still admits the admin.
 *
 * The real session helpers run over signed tokens; the cookie store, Prisma (reads answer
 * empty, any write is recorded and throws), the agent and fetch are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'm'.repeat(64))
vi.stubEnv('PLUGINS_ALLOWED_ORIGIN', '')

const h = vi.hoisted(() => ({
  auth: undefined as string | undefined,
  actAs: undefined as string | undefined,
  writes: [] as string[],
  services: [] as string[],
}))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => {
      if (name === 'redamon-auth' && h.auth) return { value: h.auth }
      if (name === 'redamon-act-as' && h.actAs) return { value: h.actAs }
      return undefined
    },
  })),
}))

const ACCOUNTS: Record<string, { role: string; password: string }> = {
  'admin-1': { role: 'admin', password: 'hash' },
  victim: { role: 'standard', password: 'hash' },
  managed: { role: 'standard', password: '' },
}

vi.mock('@/lib/prisma', () => {
  const READS = new Set(['findUnique', 'findFirst', 'findMany', 'count', 'aggregate', 'groupBy', 'findUniqueOrThrow', 'findFirstOrThrow'])
  const write = (what: string) => { h.writes.push(what); throw new Error(`database write in a refused request: ${what}`) }
  const model = (name: string) => new Proxy({}, {
    get: (_t, op: string) => {
      if (name === 'user' && op === 'findUnique') {
        return async ({ where }: { where: { id: string } }) => ACCOUNTS[where.id]
          ? { id: where.id, email: `${where.id}@e2e.local`, name: where.id, createdAt: new Date(0), ...ACCOUNTS[where.id] }
          : null
      }
      if (READS.has(op)) return async () => (op === 'findMany' || op === 'groupBy' ? [] : op === 'count' ? 0 : null)
      return async () => write(`${name}.${op}`)
    },
  })
  return {
    default: new Proxy({}, {
      get: (_t, key: string) => key === '$queryRaw' ? async () => []
        : key.startsWith('$') ? async () => write(key) : model(key),
    }),
  }
})
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: async (path: string) => { h.services.push(`agent ${path}`); throw new Error('agent double') },
  agentBaseUrl: () => 'http://agent:8090',
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => { h.writes.push('audit') } }))

import { createActAsToken, createToken } from '@/lib/auth'
import * as agentOnboarding from './agent-onboarding/route'
import * as attackSkills from './attack-skills/route'
import * as attackSkill from './attack-skills/[skillId]/route'
import * as attackAvailable from './attack-skills/available/route'
import * as attackBatch from './attack-skills/batch/route'
import * as attackGenerate from './attack-skills/generate-metadata/route'
import * as attackImport from './attack-skills/import-community/route'
import * as attackNameCheck from './attack-skills/name-check/route'
import * as chatSkills from './chat-skills/route'
import * as chatSkill from './chat-skills/[skillId]/route'
import * as chatImport from './chat-skills/import-community/route'
import * as providers from './llm-providers/route'
import * as provider from './llm-providers/[providerId]/route'
import * as providerTest from './llm-providers/[providerId]/test/route'
import * as mcpServers from './mcp/route'
import * as mcpServer from './mcp/[serverId]/route'
import * as mcpTokens from './mcp-tokens/route'
import * as settings from './settings/route'
import * as tradecraft from './tradecraft-resources/route'
import * as tradecraftOne from './tradecraft-resources/[resourceId]/route'
import * as tradecraftRefresh from './tradecraft-resources/[resourceId]/refresh/route'
import * as tradecraftVerify from './tradecraft-resources/[resourceId]/verify/route'
import * as mcpTest from '../../mcp/test/route'

type Handler = (req: NextRequest, ctx: { params: Promise<Record<string, string>> }) => Promise<Response>
type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'

const WRITES: [string, Record<string, unknown>, Method][] = [
  ['agent-onboarding', agentOnboarding, 'POST'],
  ['attack-skills', attackSkills, 'POST'],
  ['attack-skills/[skillId]', attackSkill, 'PUT'],
  ['attack-skills/[skillId]', attackSkill, 'DELETE'],
  ['attack-skills/batch', attackBatch, 'POST'],
  ['attack-skills/generate-metadata', attackGenerate, 'POST'],
  ['attack-skills/import-community', attackImport, 'POST'],
  ['attack-skills/name-check', attackNameCheck, 'POST'],
  ['chat-skills', chatSkills, 'POST'],
  ['chat-skills/[skillId]', chatSkill, 'PUT'],
  ['chat-skills/[skillId]', chatSkill, 'DELETE'],
  ['chat-skills/import-community', chatImport, 'POST'],
  ['llm-providers', providers, 'POST'],
  ['llm-providers/[providerId]', provider, 'PUT'],
  ['llm-providers/[providerId]', provider, 'DELETE'],
  ['llm-providers/[providerId]/test', providerTest, 'POST'],
  ['mcp', mcpServers, 'POST'],
  ['mcp/[serverId]', mcpServer, 'PUT'],
  ['mcp/[serverId]', mcpServer, 'DELETE'],
  ['settings', settings, 'PUT'],
  ['tradecraft-resources', tradecraft, 'POST'],
  ['tradecraft-resources/[resourceId]', tradecraftOne, 'PUT'],
  ['tradecraft-resources/[resourceId]', tradecraftOne, 'DELETE'],
  ['tradecraft-resources/[resourceId]/refresh', tradecraftRefresh, 'POST'],
  ['tradecraft-resources/[resourceId]/verify', tradecraftVerify, 'POST'],
]

const READS: [string, Record<string, unknown>][] = [
  ['attack-skills', attackSkills],
  ['attack-skills/[skillId]', attackSkill],
  ['attack-skills/available', attackAvailable],
  ['attack-skills/name-check', attackNameCheck],
  ['chat-skills', chatSkills],
  ['chat-skills/[skillId]', chatSkill],
  ['llm-providers', providers],
  ['llm-providers/[providerId]', provider],
  ['mcp', mcpServers],
  ['mcp-tokens', mcpTokens],
  ['settings', settings],
  ['tradecraft-resources', tradecraft],
  ['tradecraft-resources/[resourceId]', tradecraftOne],
]

async function call(mod: Record<string, unknown>, method: Method, id: string, path: string) {
  const url = `http://localhost:3000/api/users/${id}/${path}?name=x`
  const req = new NextRequest(url, {
    method,
    headers: { host: 'localhost:3000', 'content-type': 'application/json' },
    ...(method === 'GET' ? {} : { body: '{}' }),
  })
  const res = await (mod[method] as Handler)(req, {
    params: Promise.resolve({ id, skillId: 's1', providerId: 'p1', serverId: 'srv', resourceId: 'r1' }),
  })
  const text = await res.text()
  let body: Record<string, unknown> = {}
  try { body = JSON.parse(text) } catch { /* a non-JSON answer is not the gate's */ }
  return { status: res.status, body }
}

const refusedByGate = (r: { status: number; body: Record<string, unknown> }) =>
  r.status === 401 || (r.status === 403 && (r.body.code === 'own_account_only' || r.body.error === 'Forbidden'))

beforeEach(async () => {
  h.auth = await createToken('admin-1', 'admin')
  h.actAs = undefined
  h.writes = []
  h.services = []
  vi.stubGlobal('fetch', async (u: unknown) => { h.services.push(`fetch ${String(u)}`); throw new Error('fetch double') })
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
})

describe('HD-23: no admin write into another account', () => {
  test.each(WRITES)('%s %s: an admin on another account is refused before any write', async (path, mod, method) => {
    const r = await call(mod, method, 'victim', path)
    expect(r.status).toBe(403)
    expect(r.body.code).toBe('own_account_only')
    expect(h.writes).toEqual([])
    expect(h.services).toEqual([])
  })

  test.each(WRITES)('%s %s: an admin acting as a member is refused before any write', async (path, mod, method) => {
    h.actAs = await createActAsToken('admin-1', 'victim')
    const r = await call(mod, method, 'victim', path)
    expect(r.status).toBe(403)
    expect(r.body.code).toBe('own_account_only')
    expect(h.writes).toEqual([])
    expect(h.services).toEqual([])
  })

  test.each(WRITES)('%s %s: an admin acting as a passwordless managed account passes the gate', async (path, mod, method) => {
    h.actAs = await createActAsToken('admin-1', 'managed')
    expect(refusedByGate(await call(mod, method, 'managed', path))).toBe(false)
  })

  test.each(WRITES)('%s %s: the account itself passes the gate', async (path, mod, method) => {
    h.auth = await createToken('victim', 'standard')
    expect(refusedByGate(await call(mod, method, 'victim', path))).toBe(false)
  })

  test('the MCP test cannot send another account\'s saved token: refused for an admin', async () => {
    const req = new NextRequest('http://localhost:3000/api/mcp/test', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: 'victim', server: { id: 'srv', transport: 'streamable_http', url: 'https://x.example/mcp', auth: { type: 'bearer', token: '••••1234' } } }),
    })
    const res = await (mcpTest.POST as (r: NextRequest) => Promise<Response>)(req)
    expect(res.status).toBe(403)
    expect(h.services).toEqual([])
  })

  test('minting stays self-only (no managed exception either)', async () => {
    h.actAs = await createActAsToken('admin-1', 'managed')
    const r = await call(mcpTokens, 'POST', 'managed', 'mcp-tokens')
    expect(r.status).toBe(403)
    expect(h.writes).toEqual([])
  })
})

describe('HD-23: the admin keeps the masked read', () => {
  test.each(READS)('GET %s: an admin reads another account', async (path, mod) => {
    const r = await call(mod, 'GET', 'victim', path)
    expect(refusedByGate(r)).toBe(false)
    expect(h.writes).toEqual([])
  })
})
