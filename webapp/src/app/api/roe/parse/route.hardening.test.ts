/**
 * `/api/roe/parse` hardening: same origin, limits before parsing, the registry
 * handshake with the agent, an audit row, and a log that carries no text.
 *
 * The extractor runs for real (a .txt upload through the child process), so
 * these also prove the route reaches it.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockEff = vi.fn()
const mockSettings = vi.fn()
const mockAgentFetch = vi.fn()
const mockAudit = vi.fn()

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: () => mockEff() }))
vi.mock('@/lib/prisma', () => ({
  default: { userSettings: { findUnique: (...a: unknown[]) => mockSettings(...a) } },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => mockAudit(...a) }))
vi.mock('@/lib/session', () => ({ getSession: async () => null }))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => mockAgentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))

import { POST } from './route'
import { REGISTRY_DIGEST } from '@/lib/reconSettings/registryDigest.generated'
import { AGENT_ENFORCEMENT_WARNING } from '@/lib/roe/agentWarning'
import { MAX_REQUEST_BYTES } from '@/lib/roe/limits'

const SECRET_LINE = 'Client contact: Jane Roe, +1 555 0100'

function request(opts: { text?: string; name?: string; type?: string; headers?: Record<string, string> } = {}) {
  const form = new FormData()
  form.append('file', new File([opts.text ?? `RoE\n${SECRET_LINE}\nMax 5 rps.`], opts.name ?? 'roe.txt', { type: opts.type ?? 'text/plain' }))
  return new NextRequest('http://localhost:3000/api/roe/parse', {
    method: 'POST', body: form, headers: { host: 'localhost:3000', ...(opts.headers ?? {}) },
  })
}

function agentAnswers(fields: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  mockAgentFetch.mockResolvedValue(new Response(JSON.stringify({
    fields, unknownKeys: [], registryDigest: REGISTRY_DIGEST, model_used: 'gpt-5', ...extra,
  }), { status: 200 }))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockEff.mockResolvedValue({ userId: 'alice' })
  mockSettings.mockResolvedValue({ featureModels: { roe_parse: 'gpt-5' } })
  agentAnswers({ roeGlobalMaxRps: 5 })
})

describe('refused before any work', () => {
  test('a cross-origin POST is 403', async () => {
    const res = await POST(request({ headers: { origin: 'http://guinea-pig.localhost:8080' } }))
    expect(res.status).toBe(403)
    expect((await res.json()).code).toBe('cross_origin')
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a declared body over the cap is 413 without reading it', async () => {
    const res = await POST(request({ headers: { 'content-length': String(MAX_REQUEST_BYTES + 1) } }))
    expect(res.status).toBe(413)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('an unsupported type is 400, and so is a type that contradicts the extension', async () => {
    expect((await POST(request({ name: 'roe.html', type: 'text/html' }))).status).toBe(400)
    expect((await POST(request({ name: 'roe.pdf', type: 'text/html' }))).status).toBe(400)
    expect(mockAgentFetch).not.toHaveBeenCalled()
  })

  test('a document the extractor cannot read is 422 and reaches no model', async () => {
    const res = await POST(request({ name: 'roe.pdf', type: 'application/pdf', text: 'not a pdf at all' }))
    expect(res.status).toBe(422)
    expect((await res.json()).code).toBe('extract_failed')
    expect(mockAgentFetch).not.toHaveBeenCalled()
  }, 30_000)
})

describe('the registry handshake', () => {
  test('an agent built from another registry is 503 and nothing is proposed', async () => {
    agentAnswers({ roeGlobalMaxRps: 5 }, { registryDigest: '0'.repeat(64) })
    const res = await POST(request())
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body.code).toBe('agent_registry_outdated')
    expect(body.changes).toBeUndefined()
    expect(mockAudit.mock.calls[0][0].after.outcome).toBe('agent_registry_outdated')
  }, 30_000)
})

describe('a successful parse', () => {
  test('carries both hashes, the page count and no truncation', async () => {
    const res = await POST(request())
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.bytesSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(body.textSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(body.truncated).toBe(false)
    expect(body.changes.map((c: { key: string }) => c.key)).toEqual(['roeGlobalMaxRps'])
    expect(body.registryDigest).toBe(REGISTRY_DIGEST)
  }, 30_000)

  test('the text the agent receives is the extractor\'s, and the audit row holds no text', async () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => {})
    await POST(request())
    const sent = JSON.parse((mockAgentFetch.mock.calls[0][1] as RequestInit).body as string)
    expect(sent.text).toContain(SECRET_LINE)

    expect(mockAudit).toHaveBeenCalledTimes(1)
    const entry = mockAudit.mock.calls[0][0]
    expect(entry).toMatchObject({ action: 'roe.parse', actorId: 'alice', targetType: 'create' })
    expect(entry.after).toMatchObject({ documentName: 'roe.txt', model: 'gpt-5', outcome: 'ok' })
    expect(JSON.stringify(entry)).not.toContain('Jane Roe')

    const logged = info.mock.calls.map(c => c.join(' ')).join('\n')
    expect(logged).toContain('[roe-parse] outcome=ok')
    expect(logged).not.toContain('Jane Roe')
    info.mockRestore()
  }, 30_000)

  test('a long document is flagged as truncated with a warning', async () => {
    const res = await POST(request({ text: 'Max 5 rps. ' + 'x'.repeat(60_000) }))
    const body = await res.json()
    expect(body.truncated).toBe(true)
    expect(body.warnings.join(' ')).toMatch(/only its first 50,000/)
  }, 30_000)

  test('a confirmation switched off by the document is rejected, not proposed', async () => {
    agentAnswers({ agentRequireToolConfirmation: false, roeGlobalMaxRps: 5 })
    const body = await (await POST(request())).json()
    expect(body.changes.map((c: { key: string }) => c.key)).toEqual(['roeGlobalMaxRps'])
    expect(body.rejected.map((r: { key: string }) => r.key)).toEqual(['agentRequireToolConfirmation'])
  }, 30_000)

  test('agent permissions with nothing that turns the RoE gate on carry the warning', async () => {
    agentAnswers({ roeForbiddenTools: ['execute_hydra'] })
    const body = await (await POST(request())).json()
    expect(body.warnings).toContain(AGENT_ENFORCEMENT_WARNING)

    agentAnswers({ roeForbiddenTools: ['execute_hydra'], roeGlobalMaxRps: 5 })
    const gated = await (await POST(request())).json()
    expect(gated.warnings).not.toContain(AGENT_ENFORCEMENT_WARNING)
  }, 30_000)
})

describe('an infrastructure failure names its code', () => {
  test('a database failure answers the fixed sentence and the Prisma code, never the message', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockSettings.mockRejectedValue(Object.assign(new Error(`Can't reach database server; ${SECRET_LINE}`), {
      code: 'P1001', name: 'PrismaClientInitializationError',
    }))
    const res = await POST(request())
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to parse the RoE document.', code: 'P1001' })
    expect(JSON.stringify(body)).not.toContain('Jane Roe')
    error.mockRestore()
  })

  test('a declared body over the cap carries the limit', async () => {
    const res = await POST(request({ headers: { 'content-length': String(MAX_REQUEST_BYTES + 1) } }))
    expect(res.status).toBe(413)
    expect(await res.json()).toMatchObject({ code: 'file_too_large', limitBytes: 9 * 1024 * 1024 })
  })
})
