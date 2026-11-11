/**
 * HD-23: the admin bypass is a masked READ, and the settings row also carries the MCP
 * servers (`mcpServers` JSON): their bearer tokens, custom header values and stdio env
 * values are masked here exactly as `/api/users/[id]/mcp` masks them, in the GET and in
 * the PUT's answer. The masking was keyed on the secret columns only, so an admin reading
 * a member's settings got every MCP credential in clear.
 *
 * The real session helpers run over signed tokens; the cookie store and Prisma are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'm'.repeat(64))
vi.stubEnv('INTERNAL_API_KEY', 'internal-key-for-tests-0000000000000')

const h = vi.hoisted(() => ({ auth: undefined as string | undefined }))

vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: (name: string) => (name === 'redamon-auth' && h.auth ? { value: h.auth } : undefined),
  })),
}))

const TOKEN = 'mcp-bearer-SECRET-0000000000000001'
const HEADER = 'mcp-header-SECRET-0000000000000002'
const ENV = 'mcp-env-SECRET-0000000000000003'
const TAVILY = 'tavily-SECRET-0000000000000004'

const ROW = {
  userId: 'member',
  tavilyApiKey: TAVILY,
  githubEnterpriseHost: 'ghe.example.test',
  tunnelsEnabled: false,
  mcpServers: [
    {
      id: 'http-srv', name: 'http', transport: 'streamable_http', url: 'https://mcp.example.test/mcp',
      auth: { type: 'bearer', token: TOKEN }, headers: { 'X-Api-Key': HEADER, 'X-Tenant': 'acme-tenant' },
    },
    { id: 'stdio-srv', name: 'stdio', transport: 'stdio', command: 'npx', args: ['some-mcp'], env: { API_KEY: ENV } },
  ],
}

const ACCOUNTS: Record<string, { role: string; password: string }> = {
  'admin-1': { role: 'admin', password: 'hash' },
  member: { role: 'standard', password: 'hash' },
}

vi.mock('@/lib/prisma', () => ({
  default: {
    user: {
      findUnique: async ({ where }: { where: { id: string } }) => ACCOUNTS[where.id]
        ? { id: where.id, email: `${where.id}@e2e.local`, name: where.id, createdAt: new Date(0), legacyGrants: [], ...ACCOUNTS[where.id] }
        : null,
    },
    userSettings: {
      findUnique: async () => structuredClone(ROW),
      upsert: async ({ update }: { update: Record<string, unknown> }) => ({ ...structuredClone(ROW), ...update }),
    },
    apiKeyRotationConfig: { findMany: async () => [] },
    $queryRaw: async () => [],
  },
}))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => {}) }))

import { createToken } from '@/lib/auth'
import { GET, PUT } from './route'

const params = { params: Promise.resolve({ id: 'member' }) }

function expectNoMcpSecret(text: string) {
  for (const secret of [TOKEN, HEADER, ENV, TAVILY]) expect(text).not.toContain(secret)
}

beforeEach(() => {
  h.auth = undefined
})

describe('HD-23: an admin reads another account\'s settings with every MCP secret masked', () => {
  test('the bearer token, the header values and the stdio env values never come back in clear', async () => {
    h.auth = await createToken('admin-1', 'admin')
    const res = await GET(new NextRequest('http://x/api/users/member/settings'), params)
    expect(res.status).toBe(200)
    const text = await res.text()
    expectNoMcpSecret(text)
    const body = JSON.parse(text)
    const [http, stdio] = body.mcpServers
    // masked as /api/users/[id]/mcp masks them: last four characters, every value
    expect(http.auth.token).toBe('••••••••0001')
    expect(http.headers).toEqual({ 'X-Api-Key': '••••••••0002', 'X-Tenant': '••••••••nant' })
    expect(stdio.env).toEqual({ API_KEY: '••••••••0003' })
    // configuration stays readable
    expect(http.url).toBe('https://mcp.example.test/mcp')
    expect(stdio.command).toBe('npx')
  })

  test('the account itself reads them masked too: no browser caller gets an MCP secret', async () => {
    h.auth = await createToken('member', 'standard')
    const res = await GET(new NextRequest('http://x/api/users/member/settings'), params)
    expect(res.status).toBe(200)
    expectNoMcpSecret(await res.text())
  })

  test('?internal=true without the internal key stays masked', async () => {
    h.auth = await createToken('admin-1', 'admin')
    const res = await GET(new NextRequest('http://x/api/users/member/settings?internal=true'), params)
    expectNoMcpSecret(await res.text())
  })

  test('the internal key with ?internal=true still reads them (service path unchanged)', async () => {
    const res = await GET(new NextRequest('http://x/api/users/member/settings?internal=true', {
      headers: { 'x-internal-key': 'internal-key-for-tests-0000000000000' },
    }), params)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).toContain(TOKEN)
    expect(text).toContain(ENV)
  })

  test('a stored mcpServers value that is not a list never leaks through the masked read', async () => {
    h.auth = await createToken('admin-1', 'admin')
    const original = ROW.mcpServers
    ;(ROW as Record<string, unknown>).mcpServers = { token: TOKEN }
    try {
      const res = await GET(new NextRequest('http://x/api/users/member/settings'), params)
      expect(res.status).toBe(200)
      const text = await res.text()
      expect(text).not.toContain(TOKEN)
      expect(JSON.parse(text).mcpServers).toEqual([])
    } finally {
      ROW.mcpServers = original
    }
  })
})

describe('the PUT answer masks the MCP servers like the GET', () => {
  test('a save returns the row with every MCP secret masked', async () => {
    h.auth = await createToken('member', 'standard')
    const res = await PUT(new NextRequest('http://x/api/users/member/settings', {
      method: 'PUT', body: JSON.stringify({ shodanApiKey: 'shodan-typed-key' }),
    }), params)
    expect(res.status).toBe(200)
    const text = await res.text()
    expectNoMcpSecret(text)
    expect(JSON.parse(text).mcpServers[0].auth.token).toBe('••••••••0001')
  })
})
