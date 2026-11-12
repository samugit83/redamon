/**
 * The Agent Onboarding generation route.
 *
 * The two properties worth pinning here are both negative:
 *
 *  - it is SESSION-authed, not bearer-authed. A leaked MCP token must not be
 *    able to ask RedAmon to describe a permission set it does not hold.
 *  - it GRANTS NOTHING. The scopes in the body describe a document; no token is
 *    read and no row is written. A route that quietly persisted them would turn
 *    a preview into a privilege escalation.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  requireUserAccess: vi.fn(),
  audit: vi.fn(),
}))

vi.mock('@/lib/authz/selfService', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overSelfService()))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => h.requireUserAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { NextResponse } from 'next/server'
import { POST } from './route'

const params = (id = 'owner') => ({ params: Promise.resolve({ id }) })
const req = (body?: unknown) =>
  ({
    headers: new Headers(),
    json: async () => { if (body === undefined) throw new SyntaxError('bad'); return body },
  }) as never

const valid = (over: Record<string, unknown> = {}) => ({
  profile: 'bug_bounty',
  scopes: ['recon:read', 'triage:read'],
  serverUrl: 'https://redamon.example',
  style: 'mcp',
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.requireUserAccess.mockResolvedValue(null)
  // The build's full surface. Unset reads as off and withdraws the sandbox
  // tools, while docker-compose.yml defaults the switch on.
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  // Agent in the Loop is off by default; the loop tools are part of the build.
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
})

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('access', () => {
  test('it is judged on the browser session, not a bearer token', async () => {
    await POST(req(valid()), params('owner'))
    expect(h.requireUserAccess).toHaveBeenCalledOnce()
    expect(h.requireUserAccess.mock.calls[0][1]).toBe('owner')
  })

  test('a denied session short-circuits before any generation', async () => {
    h.requireUserAccess.mockResolvedValue(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
    const res = await POST(req(valid()), params('victim'))
    expect(res.status).toBe(401)
  })
})

describe('validation', () => {
  test('a malformed body is refused', async () => {
    expect((await POST(req(undefined), params())).status).toBe(400)
  })

  test('an unknown scope is refused rather than dropped', async () => {
    const res = await POST(req(valid({ scopes: ['recon:read', 'root:all'] })), params())
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/Unknown scope/)
  })

  test('an empty scope set is refused', async () => {
    expect((await POST(req(valid({ scopes: [] })), params())).status).toBe(400)
  })

  test('an unknown profile is refused', async () => {
    const res = await POST(req(valid({ profile: 'superuser' })), params())
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/Unknown profile/)
  })

  test('a null profile is accepted and renders the custom pack', async () => {
    const res = await POST(req(valid({ profile: null })), params())
    expect(res.status).toBe(200)
    const data = await res.json()
    expect(data.profile).toBeNull()
    expect(data.files[0].content).toContain('## Your job: Custom')
  })
})

describe('the server URL is the only caller-controlled text in the output', () => {
  test('a javascript: scheme is refused, not escaped', async () => {
    const res = await POST(req(valid({ serverUrl: 'javascript:alert(1)' })), params())
    expect(res.status).toBe(400)
  })

  test('a relative URL is refused', async () => {
    expect((await POST(req(valid({ serverUrl: '/api/mcp-server' })), params())).status).toBe(400)
  })

  test('an absurdly long URL is refused', async () => {
    const res = await POST(req(valid({ serverUrl: `https://${'a'.repeat(600)}.example` })), params())
    expect(res.status).toBe(400)
  })

  test('only the ORIGIN survives, so a pasted deep link still works', async () => {
    const res = await POST(
      req(valid({ serverUrl: 'https://redamon.example/settings?tab=mcp#token' })),
      params()
    )
    const data = await res.json()
    expect(data.files[0].content).toContain('https://redamon.example/api/mcp-server')
    expect(data.files[0].content).not.toContain('tab=mcp')
  })

  test('markdown injected through the URL cannot reach the document', async () => {
    const res = await POST(
      req(valid({ serverUrl: 'https://evil.example/")](http://x) # OWNED' })),
      params()
    )
    expect(res.status).toBe(200)
    const text = (await res.json()).files.map((f: { content: string }) => f.content).join('\n')
    expect(text).not.toContain('OWNED')
    expect(text).toContain('https://evil.example/api/mcp-server')
  })

  test('an omitted URL falls back to a placeholder rather than failing', async () => {
    const res = await POST(req(valid({ serverUrl: undefined })), params())
    expect(res.status).toBe(200)
    expect((await res.json()).files[0].content).toContain('your-redamon-host')
  })
})

describe('the generated pack', () => {
  test('it returns SKILL.md plus its references', async () => {
    const res = await POST(req(valid({ scopes: ['recon:read', 'triage:read'] })), params())
    const data = await res.json()
    expect(data.files[0].path).toBe('SKILL.md')
    expect(data.files.length).toBeGreaterThan(1)
    expect(data.files.every((f: { path: string }) => f.path.endsWith('.md'))).toBe(true)
  })

  test('single layout collapses it into one file', async () => {
    const res = await POST(req(valid({ layout: 'single' })), params())
    expect((await res.json()).files).toHaveLength(1)
  })

  test('the raw-HTTP style adds the curl form', async () => {
    const mcp = await (await POST(req(valid({ style: 'mcp' })), params())).json()
    const http = await (await POST(req(valid({ style: 'http' })), params())).json()
    expect(mcp.files[0].content).not.toContain('curl -s')
    expect(http.files[0].content).toContain('curl -s')
    expect(http.files[0].content).toContain('application/json, text/event-stream')
  })

  test('it reports which tools the described token could and could not call', async () => {
    const data = await (await POST(req(valid({ scopes: ['recon:read'] })), params())).json()
    expect(data.available).toContain('list_projects')
    expect(data.unavailable).toContain('kali_exec')
    expect(data.scopes).toEqual(['recon:read'])
  })

  test('it is not cacheable by a shared proxy', async () => {
    const res = await POST(req(valid()), params())
    expect(res.headers.get('Cache-Control')).toBe('no-store')
  })
})

describe('it grants nothing', () => {
  test('generating for every permission writes no audit row and no token', async () => {
    // The scopes in the body describe a DOCUMENT. If this route ever started
    // persisting them, a preview would become a privilege escalation.
    const res = await POST(
      req(valid({ scopes: ['recon:read', 'kali:exec', 'recon:overwrite', 'triage:write'] })),
      params()
    )
    expect(res.status).toBe(200)
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('no real token value can appear in the output', async () => {
    const data = await (await POST(req(valid({ scopes: ['recon:read'] })), params())).json()
    const text = data.files.map((f: { content: string }) => f.content).join('\n')
    expect(text).not.toMatch(/rdmn_mcp_[0-9a-f]{8,}/)
  })
})

// --- ROW 4: a withdrawn tool must not be taught ---------------------------------

describe('a tool this deployment withdrew is absent from the pack', () => {
  /**
   * `MCP_DISABLED_TOOLS` is the operator's emergency lever for one misbehaving
   * tool. The pack is generated from the server's own `tools/list`, and the
   * withdrawal happens at REGISTRATION inside buildMcpServer, so a withdrawn
   * tool never reaches the renderer.
   *
   * That property is what this asserts, through the real route rather than by
   * hand-filtering an array: if the filtering ever moved into a route or a
   * caller, the pack would keep teaching an agent to call a tool the server has
   * stopped advertising, and every call would fail at run time.
   */
  test('the withdrawn tool appears nowhere in the generated files', async () => {
    vi.stubEnv('MCP_DISABLED_TOOLS', 'get_blast_radius,list_exploit_paths')
    const res = await POST(req(valid({ profile: 'reporting', scopes: ['recon:read', 'triage:read'] })), params())
    expect(res.status).toBe(200)

    const data = await res.json()
    const text = data.files.map((f: { content: string }) => f.content).join('\n')
    expect(text, 'the pack still teaches a withdrawn tool').not.toContain('get_blast_radius')
    expect(text).not.toContain('list_exploit_paths')
    expect(data.available).not.toContain('get_blast_radius')
    // Not merely absent everywhere: it must not be listed as "you cannot call"
    // either, which would tell the agent to go and ask for a permission.
    expect(data.unavailable).not.toContain('get_blast_radius')
    // A tool that was NOT withdrawn is still there, so this is not an empty pack.
    expect(text).toContain('list_findings')
  })

  test('with nothing withdrawn the same tools are present', async () => {
    // The control: without this, the assertion above would pass on a pack that
    // never mentioned those tools for an unrelated reason.
    vi.stubEnv('MCP_DISABLED_TOOLS', '')
    const data = await (await POST(
      req(valid({ profile: 'reporting', scopes: ['recon:read', 'triage:read'] })), params()
    )).json()
    expect(data.available).toContain('get_blast_radius')
    expect(data.available).toContain('list_exploit_paths')
  })
})

// --- REGRESSION: a sandbox switched off was still taught -----------------------

describe('a deployment with the sandbox off teaches no sandbox tool', () => {
  /**
   * MCP_KALI_EXEC_ENABLED=false used to leave the sandbox tools in tools/list,
   * so a pentest pack for a token holding `kali:exec` taught a validation step
   * that could only ever fail. They are now withdrawn at registration, the same
   * path as MCP_DISABLED_TOOLS, so the pack follows for free.
   */
  const pentest = () => POST(
    req(valid({ profile: 'pentest', scopes: ['recon:read', 'triage:read', 'kali:exec'] })),
    params()
  )
  const sandboxTools = ['kali_toolbox', 'kali_exec', 'kali_output', 'kali_cancel']

  test('no file, procedure or tool list mentions the sandbox', async () => {
    vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'false')
    const res = await pentest()
    expect(res.status).toBe(200)

    const data = await res.json()
    const paths = data.files.map((f: { path: string }) => f.path)
    expect(paths).not.toContain('references/kali-exec.md')
    const text = data.files.map((f: { content: string }) => f.content).join('\n')
    for (const name of sandboxTools) {
      expect(text, `the pack still teaches ${name}`).not.toContain(name)
      expect(data.available).not.toContain(name)
      // Absent, not "needs a permission": the token HOLDS kali:exec, so that
      // would send the agent to ask for something that cannot help.
      expect(data.unavailable).not.toContain(name)
    }
    expect(text).toContain('list_findings')
  })

  test('with the sandbox on, the same request teaches it', async () => {
    // The control: without it the assertions above would pass on a pack that
    // never mentioned the sandbox for an unrelated reason.
    const data = await (await pentest()).json()
    expect(data.files.map((f: { path: string }) => f.path)).toContain('references/kali-exec.md')
    for (const name of sandboxTools) expect(data.available).toContain(name)
  })
})

describe('a failure outside the generation itself', () => {
  test('a session check that throws answers a sentence and a code, not an empty 500', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    h.requireUserAccess.mockRejectedValue(Object.assign(new Error("Can't reach database server"), { code: 'P1001' }))
    const res = await POST(req(valid()), params())
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Could not generate the onboarding pack', code: 'P1001' })
  })
})

// --- Agent in the Loop: the client, the switch -------------------------------

describe('the Agent in the Loop pack', () => {
  const loopReq = (over: Record<string, unknown> = {}) => POST(
    req(valid({ profile: 'agent_in_the_loop', scopes: ['recon:read', 'agent:loop'], ...over })),
    params(),
  )

  test('each client gets its own setup files', async () => {
    const claude = await (await loopReq({ client: 'claude-code' })).json()
    expect(claude.files.map((f: { path: string }) => f.path)).toContain('templates/claude-mcp.json')
    const codex = await (await loopReq({ client: 'codex' })).json()
    expect(codex.files.map((f: { path: string }) => f.path)).toContain('templates/codex-config.toml')
    expect(codex.features).toEqual({ agentInTheLoop: true })
  })

  test('no client means Claude Code; an unknown one is refused', async () => {
    const res = await loopReq()
    expect((await res.json()).files.map((f: { path: string }) => f.path)).toContain('templates/claude-settings.json')
    expect((await loopReq({ client: 'cursor' })).status).toBe(400)
  })

  test('with the switch off the profile answers 409 loop_disabled', async () => {
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'false')
    const res = await loopReq()
    expect(res.status).toBe(409)
    expect((await res.json()).code).toBe('loop_disabled')
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  })
})
