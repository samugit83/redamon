/**
 * POST /api/users/[id]/attack-skills/generate-metadata: "Generate with AI" in the upload and
 * Edit dialogs. It runs the effective owner's own "Skill names & descriptions" model, builds
 * the agent body field by field, never sends a file that holds a key or token, re-validates
 * the model's answer as untrusted text, and audits the model and content hashes, never text.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  eff: { userId: 'alice' } as unknown,
  session: { userId: 'alice', role: 'standard' } as { userId: string; role: string } | null,
  settings: vi.fn(),
  agentFetch: vi.fn(),
  audits: [] as Record<string, unknown>[],
}))
vi.mock('@/lib/prisma', () => ({
  default: { userSettings: { findUnique: (...a: unknown[]) => h.settings(...a) } },
}))
vi.mock('@/lib/agentFetch', () => ({
  agentFetch: (...a: unknown[]) => h.agentFetch(...a),
  AgentUnreachableError: class AgentUnreachableError extends Error {},
}))
vi.mock('@/lib/session', async () => {
  const { NextResponse } = await import('next/server')
  return {
    getSession: async () => h.session,
    // session.ts requireAccountWrite (the write rule), over the account the test lets this
    // request write, h.eff: a response is that refusal, another account than the path's is 403.
    requireAccountWrite: async (id: string) => h.eff instanceof NextResponse ? h.eff
      : (h.eff as { userId: string }).userId === id ? null
        : NextResponse.json({ error: 'Forbidden', code: 'own_account_only' }, { status: 403 }),
  }
})
vi.mock('@/lib/access', async (orig) => ({
  ...(await orig<typeof import('@/lib/access')>()),
  requireEffectiveUser: async () => h.eff,
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async (e: Record<string, unknown>) => void h.audits.push(e) }))

import { POST } from './route'
import { contentSha256 } from '@/lib/userSkillWrites'
import { MAX_CONTENT_SIZE } from '@/lib/userSkills'

const MODEL = 'claude-haiku-4-5'
const params = (id: string) => ({ params: Promise.resolve({ id }) })

function generate(body: unknown, { id = 'alice', origin }: { id?: string; origin?: string } = {}) {
  return POST(new NextRequest(`http://localhost:3000/api/users/${id}/attack-skills/generate-metadata`, {
    method: 'POST',
    headers: { host: 'localhost:3000', 'content-type': 'application/json', ...(origin ? { origin } : {}) },
    body: JSON.stringify(body),
  }), params(id))
}

const item = (key: string, extra: Record<string, unknown> = {}) => ({
  key, fileName: `${key}.md`, content: `# ${key}\n\nA skill body for ${key}.`, name: '', fields: ['name', 'description'], ...extra,
})

const agentReply = (body: Record<string, unknown>, status = 200) =>
  h.agentFetch.mockResolvedValue(new Response(JSON.stringify(body), { status }))

function sentToAgent() {
  const [path, init] = h.agentFetch.mock.calls[0] as [string, RequestInit]
  return { path, body: JSON.parse(init.body as string) }
}

beforeEach(() => {
  vi.clearAllMocks()
  h.eff = { userId: 'alice' }
  h.session = { userId: 'alice', role: 'standard' }
  h.audits = []
  h.settings.mockResolvedValue({ featureModels: { skill_metadata: MODEL } })
  agentReply({ items: [{ key: 'a', name: 'Pickle Flow', description: 'Tests pickle deserialization.' }], model_used: MODEL })
})

describe('generate-metadata: the model and the agent', () => {
  test('no saved model is 409 model_required, and the agent is not called', async () => {
    h.settings.mockResolvedValue(null)
    const res = await generate({ items: [item('a')] })
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'model_required', featureId: 'skill_metadata' })
    expect(h.agentFetch).not.toHaveBeenCalled()
  })

  test('the happy path: an explicit agent body for the effective user, and the validated answer', async () => {
    const res = await generate({
      items: [item('a', { name: 'Typed', fields: ['description'], extra: 'dropped' })],
      otherNames: ['Other one'], userId: 'mallory', model: 'gpt-evil',
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ items: [{ key: 'a', description: 'Tests pickle deserialization.' }], modelUsed: MODEL })
    expect(sentToAgent()).toEqual({
      path: '/skill-metadata/generate',
      body: {
        items: [{ key: 'a', content: '# a\n\nA skill body for a.', file_name: 'a.md', name: 'Typed', want_name: false, want_description: true }],
        other_names: ['Other one'], model: MODEL, user_id: 'alice',
      },
    })
  })

  test('an agent reply without model_used is 502 agent_outdated; so is a 404', async () => {
    agentReply({ items: [] })
    let res = await generate({ items: [item('a')] })
    expect(res.status).toBe(502)
    expect((await res.json()).code).toBe('agent_outdated')
    agentReply({ detail: 'Not Found' }, 404)
    res = await generate({ items: [item('a')] })
    expect((await res.json()).code).toBe('agent_outdated')
    expect(h.audits).toEqual([])
  })

  test('a 503 model_unavailable from the agent passes with the fixed message', async () => {
    agentReply({ code: 'model_unavailable', error: 'provider said sk-live-LEAK', model_used: MODEL }, 503)
    const res = await generate({ items: [item('a')] })
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toMatchObject({ code: 'model_unavailable', error: `Your model ${MODEL} could not be used` })
    expect(JSON.stringify(body)).not.toContain('sk-live-LEAK')
  })

  test.each([
    ['6 items', { items: ['a', 'b', 'c', 'd', 'e', 'f'].map((k) => item(k)) }],
    ['no items', { items: [] }],
    ['duplicate keys', { items: [item('a'), item('a')] }],
    ['empty fields', { items: [item('a', { fields: [] })] }],
    ['an unknown field', { items: [item('a', { fields: ['name', 'content'] })] }],
    ['blank content', { items: [item('a', { content: '  \n' })] }],
    ['oversized content', { items: [item('a', { content: 'x'.repeat(MAX_CONTENT_SIZE + 1) })] }],
    ['an overlong key', { items: [item('k'.repeat(65))] }],
    ['an overlong name', { items: [item('a', { name: 'n'.repeat(101) })] }],
    ['an overlong file name', { items: [item('a', { fileName: `${'f'.repeat(253)}.md` })] }],
    ['51 other names', { items: [item('a')], otherNames: Array.from({ length: 51 }, (_, i) => `n${i}`) }],
  ])('%s is 400 items_invalid', async (_label, body) => {
    const res = await generate(body)
    expect(res.status).toBe(400)
    expect((await res.json()).code).toBe('items_invalid')
    expect(h.agentFetch).not.toHaveBeenCalled()
  })
})

describe('generate-metadata: the contract with the agent', () => {
  // agentic/tests/test_skill_metadata.py posts the same agent_request and expects the same
  // agent_response, so a field renamed on either side fails one of the two suites.
  const CONTRACT = JSON.parse(readFileSync(
    join(__dirname, '../../../../../../../../agentic/tests/fixtures/skill_metadata_contract.json'), 'utf8'))

  test('the route sends agent_request and turns agent_response into route_response', async () => {
    h.eff = { userId: CONTRACT.user_id }
    h.session = { userId: CONTRACT.user_id, role: 'standard' }
    h.settings.mockResolvedValue({ featureModels: { skill_metadata: CONTRACT.model } })
    agentReply(CONTRACT.agent_response)
    const res = await generate(CONTRACT.route_request, { id: CONTRACT.user_id })
    expect(res.status).toBe(200)
    expect(sentToAgent().body).toEqual(CONTRACT.agent_request)
    expect(await res.json()).toEqual(CONTRACT.route_response)
  })
})

describe('generate-metadata: who may call it', () => {
  test.each([
    ["another user's id", () => ({ id: 'bob' }), 403],
    ['an admin not simulating the owner', () => { h.eff = { userId: 'root' }; return {} }, 403],
    ['a foreign Origin', () => ({ origin: 'https://evil.example.com' }), 403],
    ['no session', () => { h.eff = NextResponse.json({ error: 'Unauthorized' }, { status: 401 }); return {} }, 401],
  ])('%s is refused before any model is read', async (_label, setup, status) => {
    const res = await generate({ items: [item('a')] }, setup() as { id?: string; origin?: string })
    expect(res.status).toBe(status)
    expect(h.settings).not.toHaveBeenCalled()
    expect(h.agentFetch).not.toHaveBeenCalled()
  })
})

describe('generate-metadata: failures it did not expect', () => {
  test('a settings read that throws is 500 with its Prisma code, never a bodiless 500', async () => {
    h.settings.mockRejectedValue(Object.assign(new Error('Timed out: SELECT "featureModels"'), {
      name: 'PrismaClientKnownRequestError', code: 'P2024',
    }))
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await generate({ items: [item('a')] })
    const text = await res.text()
    expect(res.status).toBe(500)
    expect(JSON.parse(text)).toEqual({ error: 'Failed to generate the names and descriptions', code: 'P2024' })
    expect(text).not.toContain('SELECT')
    expect(h.agentFetch).not.toHaveBeenCalled()
    log.mockRestore()
  })

  test("an agent crash is 502 with the agent's status", async () => {
    h.agentFetch.mockResolvedValue(new Response('Internal Server Error', { status: 500 }))
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const res = await generate({ items: [item('a')] })
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({
      error: 'The agent failed while handling this request. The details are in the agent log.',
      upstreamStatus: 500,
    })
    log.mockRestore()
  })
})

describe('generate-metadata: a file that holds a key is never sent', () => {
  test('the item is left out of the agent body and answered skill_contains_credentials', async () => {
    agentReply({ items: [{ key: 'b', name: 'Clean Flow', description: 'Clean.' }], model_used: MODEL })
    const res = await generate({
      items: [item('a', { content: '# Keys\n\naws_access_key_id = AKIAIOSFODNN7EXAMPLE' }), item('b')],
    })
    const body = await res.json()
    expect(body.items).toEqual([
      { key: 'a', error: 'skill_contains_credentials' },
      { key: 'b', name: 'Clean Flow', description: 'Clean.' },
    ])
    const sent = sentToAgent().body
    expect(sent.items.map((i: { key: string }) => i.key)).toEqual(['b'])
    expect(JSON.stringify(sent)).not.toContain('AKIAIOSFODNN7EXAMPLE')
  })

  test('a key-shaped name of another row never reaches the model through otherNames', async () => {
    await generate({ items: [item('a')], otherNames: ['Clean neighbour', 'ghp_' + 'a'.repeat(36), 'AKIAIOSFODNN7EXAMPLE'] })
    const sent = sentToAgent().body
    expect(sent.other_names).toEqual(['Clean neighbour'])
    expect(JSON.stringify(sent)).not.toMatch(/ghp_|AKIA/)
  })

  test('when it is the only item the agent and the model are never asked', async () => {
    const res = await generate({ items: [item('a', { name: 'AKIAIOSFODNN7EXAMPLE' })] })
    expect(await res.json()).toEqual({ items: [{ key: 'a', error: 'skill_contains_credentials' }], modelUsed: null })
    expect(h.agentFetch).not.toHaveBeenCalled()
    expect(h.settings).not.toHaveBeenCalled()
    expect(h.audits).toEqual([])
  })
})

describe('generate-metadata: the answer is re-validated', () => {
  test('a zero-width name is cleaned, a long multi-line description is one capped line, unknown keys dropped, a missing key is no_answer', async () => {
    const long = Array.from({ length: 120 }, (_, i) => `w${i}`).join('\n')
    agentReply({
      items: [
        { key: 'a', name: '  Pickle\u200B Flow  ', description: long, injected: '<script>' },
        { key: 'zzz', name: 'Stray' },
      ],
      model_used: MODEL,
    })
    const res = await generate({ items: [item('a'), item('b')] })
    const { items } = await res.json()
    expect(items[1]).toEqual({ key: 'b', error: 'no_answer' })
    expect(Object.keys(items[0]).sort()).toEqual(['description', 'key', 'name'])
    expect(items[0].name).toBe('Pickle Flow')
    expect(items[0].description).not.toMatch(/[\r\n]/)
    expect(items[0].description.length).toBeLessThanOrEqual(500)
  })

  test('a name the rules still refuse after cleaning is invalid_name, never cut', async () => {
    agentReply({ items: [{ key: 'a', name: 'n'.repeat(140), description: 'Fine.' }], model_used: MODEL })
    const { items } = await (await generate({ items: [item('a')] })).json()
    expect(items[0]).toEqual({ key: 'a', description: 'Fine.', error: 'invalid_name' })
  })

  test('a name with only spacing to fix is kept normalized; an unasked field is dropped; the agent error code passes when well formed', async () => {
    agentReply({
      items: [
        { key: 'a', name: '  Spaced   Name ', description: 'Not asked.' },
        { key: 'b', error: 'timeout' },
        { key: 'c', error: 'Traceback (most recent call last)' },
      ],
      model_used: MODEL,
    })
    const res = await generate({ items: [item('a', { fields: ['name'] }), item('b'), item('c')] })
    expect((await res.json()).items).toEqual([
      { key: 'a', name: 'Spaced Name' },
      { key: 'b', error: 'timeout' },
      { key: 'c', error: 'empty_answer' },
    ])
  })
})

describe('generate-metadata: the audit row', () => {
  test('holds the model, one hash, fields and outcome per requested item, and no text', async () => {
    const secret = '# Keys\n\nAKIAIOSFODNN7EXAMPLE'
    agentReply({ items: [{ key: 'a', name: 'Pickle Flow', description: 'Tests pickle.' }, { key: 'b', error: 'timeout' }], model_used: MODEL })
    await generate({ items: [item('a'), item('b', { fields: ['description'] }), item('c', { content: secret })] })
    expect(h.audits).toHaveLength(1)
    const [row] = h.audits
    expect(row).toMatchObject({
      actorId: 'alice', source: 'ui', action: 'user_attack_skill.ai_metadata', targetType: 'user_attack_skill', targetId: null,
    })
    expect(row.after).toEqual({
      userId: 'alice', model: MODEL,
      items: [
        { contentSha256: contentSha256(item('a').content), fields: ['name', 'description'], outcome: 'ok' },
        { contentSha256: contentSha256(item('b').content), fields: ['description'], outcome: 'timeout' },
        { contentSha256: contentSha256(secret), fields: ['name', 'description'], outcome: 'skill_contains_credentials' },
      ],
    })
    const text = JSON.stringify(row)
    for (const leak of ['Pickle Flow', 'Tests pickle', 'A skill body', 'a.md', 'AKIA']) expect(text).not.toContain(leak)
  })

  test('the audit names the caller even when the session ends during the agent call', async () => {
    h.agentFetch.mockImplementation(async () => {
      h.session = null
      return new Response(JSON.stringify({ items: [{ key: 'a', name: 'Pickle Flow', description: 'Tests pickle.' }], model_used: MODEL }), { status: 200 })
    })
    await generate({ items: [item('a')] })
    expect(h.audits).toHaveLength(1)
    expect(h.audits[0]).toMatchObject({ actorId: 'alice', source: 'ui' })
  })

  test('an admin acting as a passwordless managed owner is audited on behalf of the owner (HD-23: the only admin who writes)', async () => {
    h.session = { userId: 'root', role: 'admin' }
    await generate({ items: [item('a')] })
    expect(h.audits[0]).toMatchObject({ actorId: 'root', after: { userId: 'alice', onBehalfOf: 'alice' } })
  })

  test('no row when the agent fails, or when no item got a value', async () => {
    agentReply({ code: 'model_unavailable', error: 'x', model_used: MODEL }, 503)
    await generate({ items: [item('a')] })
    agentReply({ items: [{ key: 'a', error: 'timeout' }], model_used: MODEL })
    await generate({ items: [item('a')] })
    expect(h.audits).toEqual([])
  })
})
