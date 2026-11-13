/**
 * The MCP exec tools.
 *
 * These are the only tools that reach a live third-party target outside a scan,
 * so what is pinned here is the containment, not the happy path:
 *
 *  - every switch fails CLOSED, and the deployment switch is checked before any
 *    work is done;
 *  - the command is never inspected or rewritten here. Admission is server-side
 *    in the agent, and a second copy of those rules in this file is exactly the
 *    copy that would drift;
 *  - a refused command is audited, because it is the only record that someone
 *    tried to reach outside their scope.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  findProject: vi.fn(),
  writeAudit: vi.fn(),
  exec: vi.fn(),
  status: vi.fn(),
  cancel: vi.fn(),
}))

vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.findProject(...a) } },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.writeAudit(...a) }))
vi.mock('@/lib/mcp/kaliClient', () => ({
  kaliExec: (...a: unknown[]) => h.exec(...a),
  kaliJobStatus: (...a: unknown[]) => h.status(...a),
  kaliJobCancel: (...a: unknown[]) => h.cancel(...a),
}))
// The real policy unless a test answers for it (step 5.10: a share's level and toggles).
vi.mock('@/lib/authz/projectAccess', async (orig) => {
  const actual = await orig<typeof import('@/lib/authz/projectAccess')>()
  return { ...actual, projectAccess: vi.fn(actual.projectAccess) }
})

import { McpScopeError, McpAccessDenied, McpLevelDenied, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { projectAccess, type ProjectAccess, type ProjectAccessToggles } from '@/lib/authz/projectAccess'
import { McpToolError } from './errors'
import { cancelCommand, execCommand, kaliExecEnabled, readCommandOutput } from './kaliTools'
import type { McpContext } from './tools'

const ctx = (scopes: McpScope[] = ['kali:exec']): McpContext => ({
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'agent', scopes,
  },
})

const doneJob = {
  jobId: 'j1', status: 'done', exitCode: 0, output: 'HTTP/1.1 200 OK',
  nextCursor: 15, command: 'curl -I https://acme.tld',
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.unstubAllEnvs()
  __resetRateLimiter()
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', mcpKaliExecEnabled: true })
  h.exec.mockResolvedValue(doneJob)
  h.status.mockResolvedValue(doneJob)
  h.cancel.mockResolvedValue({ ...doneJob, status: 'cancelled' })
})

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('the deployment switch', () => {
  test('is off by default, so enabling the MCP server does not enable this', () => {
    vi.unstubAllEnvs()
    expect(kaliExecEnabled()).toBe(false)
  })

  test('an unrecognised value is off, never on', () => {
    for (const value of ['yes', 'TRUE', 'on', '']) {
      vi.stubEnv('MCP_KALI_EXEC_ENABLED', value)
      expect(kaliExecEnabled(), value).toBe(false)
    }
  })

  test('all three tools refuse while it is off, and nothing reaches the agent', async () => {
    vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'false')
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld')).rejects.toThrow(/disabled/i)
    await expect(readCommandOutput(ctx(), 'p1', 'j1')).rejects.toThrow(/disabled/i)
    await expect(cancelCommand(ctx(), 'p1', 'j1')).rejects.toThrow(/disabled/i)
    expect(h.exec).not.toHaveBeenCalled()
    expect(h.status).not.toHaveBeenCalled()
    expect(h.cancel).not.toHaveBeenCalled()
  })

  test('it is checked before the project is even looked up', async () => {
    // Order matters: a disabled deployment must not become a way to probe which
    // project ids exist.
    vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'false')
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld')).rejects.toThrow()
    expect(h.findProject).not.toHaveBeenCalled()
  })
})

describe('permissions and ownership', () => {
  test('every tool needs kali:exec', async () => {
    const without = ctx(['recon:read', 'recon:scan', 'recon:settings', 'graph:cypher'])
    await expect(execCommand(without, 'p1', 'curl https://acme.tld')).rejects.toBeInstanceOf(McpScopeError)
    await expect(readCommandOutput(without, 'p1', 'j1')).rejects.toBeInstanceOf(McpScopeError)
    await expect(cancelCommand(without, 'p1', 'j1')).rejects.toBeInstanceOf(McpScopeError)
  })

  test('the scope is checked before the switch, so a denial never leaks the config', async () => {
    vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'false')
    await expect(execCommand(ctx([]), 'p1', 'curl https://acme.tld'))
      .rejects.toBeInstanceOf(McpScopeError)
  })

  test('another user\'s project is not found, and nothing runs', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else', mcpKaliExecEnabled: true })
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld'))
      .rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.exec).not.toHaveBeenCalled()
  })
})

describe('the per-project opt-in', () => {
  test('all three tools refuse when the project has not opted in', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', mcpKaliExecEnabled: false })
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld')).rejects.toThrow(/not enabled for this project/)
    await expect(readCommandOutput(ctx(), 'p1', 'j1')).rejects.toThrow(/not enabled for this project/)
    await expect(cancelCommand(ctx(), 'p1', 'j1')).rejects.toThrow(/not enabled for this project/)
    expect(h.exec).not.toHaveBeenCalled()
  })

  test('a project that cannot be read fails closed', async () => {
    // A null row is caught by the ownership check first and reported as "not
    // found", which is the right answer. What matters here is the direction of
    // the failure: nothing runs. Falling through would make a transient
    // database problem the way to bypass the switch.
    h.findProject.mockResolvedValue(null)
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld')).rejects.toThrow()
    expect(h.exec).not.toHaveBeenCalled()
  })

  test('a row missing the opt-in column is not treated as opted in', async () => {
    // An undefined field must not be truthy-adjacent: an older row, or a select
    // that silently stopped returning the column, is NOT consent.
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner' })
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld')).rejects.toThrow(/not enabled/)
    expect(h.exec).not.toHaveBeenCalled()
  })

  test('the refusal says a token cannot turn it on itself', async () => {
    // mcpKaliExecEnabled is DENIED to update_recon_settings, so an agent that
    // reads "enable it" as an instruction would otherwise waste calls trying.
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', mcpKaliExecEnabled: false })
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld'))
      .rejects.toThrow(/token cannot enable it/)
  })

  test('it is checked after ownership, so it cannot probe foreign project ids', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'someone-else', mcpKaliExecEnabled: false })
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld'))
      .rejects.toBeInstanceOf(McpAccessDenied)
  })
})

describe('kali_exec', () => {
  test('passes the command through untouched', async () => {
    // Admission is server-side. A check or a rewrite here would be a second
    // copy of the rules, and the copy that drifts is the one that lets
    // something through.
    await execCommand(ctx(), 'p1', "curl -A 'Mozilla 5.0' https://acme.tld")
    expect(h.exec).toHaveBeenCalledWith('p1', "curl -A 'Mozilla 5.0' https://acme.tld", undefined)
  })

  test('trims but does not otherwise alter the command', async () => {
    await execCommand(ctx(), 'p1', '  curl https://acme.tld  ')
    expect(h.exec).toHaveBeenCalledWith('p1', 'curl https://acme.tld', undefined)
  })

  test('returns the job with the cursor needed to read on', async () => {
    const result = await execCommand(ctx(), 'p1', 'curl https://acme.tld') as Record<string, unknown>
    expect(result.jobId).toBe('j1')
    expect(result.status).toBe('done')
    expect(result.exitCode).toBe(0)
    expect(result.nextCursor).toBe(15)
    expect(result.command).toBe('curl -I https://acme.tld')
  })

  test('an unfinished command says how to follow it', async () => {
    h.exec.mockResolvedValue({ ...doneJob, status: 'running', exitCode: null })
    const result = await execCommand(ctx(), 'p1', 'nikto -h https://acme.tld') as Record<string, unknown>
    expect(result.note).toMatch(/kali_output/)
    expect(result.note).toMatch(/kali_cancel/)
  })

  test('an empty command is refused before the agent is called', async () => {
    for (const command of ['', '   ']) {
      await expect(execCommand(ctx(), 'p1', command)).rejects.toBeInstanceOf(McpToolError)
    }
    expect(h.exec).not.toHaveBeenCalled()
  })

  test('an oversized command is refused before it is written to an audit row', async () => {
    await expect(execCommand(ctx(), 'p1', 'curl ' + 'a'.repeat(3000)))
      .rejects.toThrow(/longer than/)
    expect(h.exec).not.toHaveBeenCalled()
    expect(h.writeAudit).not.toHaveBeenCalled()
  })

  test('a negative wait is refused', async () => {
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld', -1)).rejects.toThrow(/positive/)
  })

  test('the exec rate bucket is tight and per token', async () => {
    vi.stubEnv('MCP_RATE_EXEC_PER_MIN', '2')
    await execCommand(ctx(), 'p1', 'curl https://acme.tld')
    await execCommand(ctx(), 'p1', 'curl https://acme.tld')
    await expect(execCommand(ctx(), 'p1', 'curl https://acme.tld')).rejects.toThrow(/Rate limit/)
  })
})

describe('audit', () => {
  test('a successful command is recorded with what actually ran', async () => {
    await execCommand(ctx(), 'p1', 'curl -I https://acme.tld')
    const row = h.writeAudit.mock.calls[0][0]
    expect(row.action).toBe('mcp.kali_exec')
    expect(row.targetId).toBe('p1')
    // The re-quoted form the guard admitted, not the raw string typed.
    expect(row.after.command).toBe('curl -I https://acme.tld')
    expect(row.after.tokenPrefix).toBe('rdmn_mcp_aaaaaaaa')
  })

  test('a REFUSED command is audited too, with the command that was tried', async () => {
    // This is the only record that someone tried to reach outside their scope.
    h.exec.mockRejectedValue(new McpToolError("'victim.tld' is outside this project's scope.", 'refused'))
    await expect(execCommand(ctx(), 'p1', 'curl https://victim.tld')).rejects.toThrow()
    const row = h.writeAudit.mock.calls[0][0]
    expect(row.action).toBe('mcp.kali_exec.refused')
    expect(row.after.command).toBe('curl https://victim.tld')
    expect(row.after.reason).toBe('refused')
  })

  test('the refusal message reaches the caller so it can fix the command', async () => {
    h.exec.mockRejectedValue(new McpToolError("'victim.tld' is outside this project's scope.", 'refused'))
    await expect(execCommand(ctx(), 'p1', 'curl https://victim.tld'))
      .rejects.toThrow(/outside this project's scope/)
  })

  test('a cancel is recorded', async () => {
    await cancelCommand(ctx(), 'p1', 'j1')
    expect(h.writeAudit.mock.calls[0][0].action).toBe('mcp.kali_cancel')
  })
})

describe('kali_output', () => {
  test('reads from the start when no cursor is given', async () => {
    await readCommandOutput(ctx(), 'p1', 'j1')
    expect(h.status).toHaveBeenCalledWith('p1', 'j1', 0)
  })

  test('resumes from the cursor it is given', async () => {
    await readCommandOutput(ctx(), 'p1', 'j1', 512)
    expect(h.status).toHaveBeenCalledWith('p1', 'j1', 512)
  })

  test('a truncated read says there is more, and where', async () => {
    h.status.mockResolvedValue({ ...doneJob, truncated: true, nextCursor: 100_000 })
    const result = await readCommandOutput(ctx(), 'p1', 'j1') as Record<string, unknown>
    expect(result.truncated).toBe(true)
    expect(result.nextCursor).toBe(100_000)
    expect(result.note).toMatch(/kali_output/)
  })

  test('a bad cursor is refused rather than coerced', async () => {
    for (const cursor of [-1, 1.5]) {
      await expect(readCommandOutput(ctx(), 'p1', 'j1', cursor)).rejects.toThrow(/cursor/)
    }
  })

  test('a missing jobId is refused', async () => {
    await expect(readCommandOutput(ctx(), 'p1', '')).rejects.toThrow(/jobId/)
  })

  test('polling uses the cheap bucket, so watching is not priced like starting', async () => {
    vi.stubEnv('MCP_RATE_EXEC_PER_MIN', '1')
    await execCommand(ctx(), 'p1', 'curl https://acme.tld')
    // The exec bucket is now spent; polling must still work.
    for (let i = 0; i < 5; i++) await readCommandOutput(ctx(), 'p1', 'j1')
    expect(h.status).toHaveBeenCalledTimes(5)
  })
})

describe('a finished job that FAILED', () => {
  // REGRESSION: the agent reports why a job failed in `error`, and the webapp
  // dropped it. "exitCode 1" with no reason is not actionable, and the most
  // common reason by far is the sandbox's 300s cap.
  const timedOut = {
    ...doneJob, status: 'failed', exitCode: 1, output: 'partial\n',
    failure: '[ERROR] Command timed out after 300 seconds.',
  }

  test('the reason reaches the caller', async () => {
    h.status.mockResolvedValue(timedOut)
    const r = await readCommandOutput(ctx(), 'p1', 'j1') as Record<string, unknown>
    expect(r.failure).toMatch(/timed out after 300 seconds/)
    expect(r.status).toBe('failed')
    expect(r.exitCode).toBe(1)
  })

  test('a timeout is never presented as a clean run', async () => {
    // The dangerous direction: an agent reporting a killed scan as "clean".
    h.status.mockResolvedValue(timedOut)
    const r = await readCommandOutput(ctx(), 'p1', 'j1') as Record<string, unknown>
    expect(r.note).toMatch(/INCOMPLETE/)
    expect(r.note).toMatch(/do not report it as clean/i)
  })

  test('the timeout note says how to split the work', async () => {
    h.status.mockResolvedValue(timedOut)
    const r = await readCommandOutput(ctx(), 'p1', 'j1') as Record<string, unknown>
    expect(r.note).toMatch(/nuclei -tags|port range|--fast|maxtime/)
  })

  test('output collected before the cap is still returned', async () => {
    h.status.mockResolvedValue(timedOut)
    const r = await readCommandOutput(ctx(), 'p1', 'j1') as Record<string, unknown>
    expect(r.output).toBe('partial\n')
  })

  test('an ordinary non-zero exit keeps the plain note', async () => {
    h.status.mockResolvedValue({ ...doneJob, status: 'failed', exitCode: 1 })
    const r = await readCommandOutput(ctx(), 'p1', 'j1') as Record<string, unknown>
    expect(r.note).toMatch(/TOOL failing, not RedAmon refusing/)
    expect(r.failure).toBeUndefined()
  })
})

// Step 5.10 (SH-49): on a project shared with the token's user the sandbox tools need the token's
// opt-in to shared projects (step 4.10), the `kali:exec` scope (kept only while the user holds
// `agent:kali_exec`, step 3.10) and agent:kali_exec's level W+X: a Read + Write share with
// Exploitation & shells, which counts only with the owner's consent. The audit names the person.
describe('a project shared with the token user (step 5.10)', () => {
  const policy = vi.mocked(projectAccess)
  const shared = (level: 'read' | 'write', toggles: Partial<ProjectAccessToggles> = {}, via: ProjectAccess['via'] = 'share') =>
    ({ project: { id: 'p1', userId: 'owner' }, level, toggles: { rawData: level === 'write', ...toggles }, via }) as ProjectAccess
  const collab = (sharedProjects: { allowlist: string[] } | null = { allowlist: [] }): McpContext => ({
    token: { tokenId: 't2', userId: 'collab', tokenPrefix: 'rdmn_mcp_bbbbbbbb', name: 'agent', scopes: ['kali:exec'], sharedProjects },
  })
  const all = (c: McpContext) => [
    () => execCommand(c, 'p1', 'curl https://acme.tld'),
    () => readCommandOutput(c, 'p1', 'j1'),
    () => cancelCommand(c, 'p1', 'j1'),
  ]

  afterEach(async () => {
    const actual = await vi.importActual<typeof import('@/lib/authz/projectAccess')>('@/lib/authz/projectAccess')
    policy.mockImplementation(actual.projectAccess)
  })

  test('shared project needs W+X: with Exploitation & shells the command runs, audited as the person', async () => {
    policy.mockResolvedValue(shared('write', { exploit: true }))
    const out = await execCommand(collab(), 'p1', 'curl https://acme.tld')
    expect(out).toMatchObject({ projectId: 'p1', status: 'done' })
    expect(h.exec).toHaveBeenCalledWith('p1', 'curl https://acme.tld', undefined)
    expect(h.writeAudit).toHaveBeenCalledWith(expect.objectContaining({ actorId: 'collab', action: 'mcp.kali_exec', targetId: 'p1' }))
    await readCommandOutput(collab(), 'p1', 'j1')
    await cancelCommand(collab(), 'p1', 'j1')
    expect(h.status).toHaveBeenCalled()
    expect(h.cancel).toHaveBeenCalled()
  })

  test('shared project needs W+X: Read + Write without Exploitation & shells is refused by name, nothing runs', async () => {
    policy.mockResolvedValue(shared('write', { useAgent: true, runScans: true, manage: true }))
    for (const call of all(collab())) {
      const err = await call().catch((e: unknown) => e)
      expect(err).toBeInstanceOf(McpLevelDenied)
      expect((err as Error).message).toMatch(/without Exploitation & shells/)
    }
    expect(h.exec).not.toHaveBeenCalled()
    expect(h.status).not.toHaveBeenCalled()
    expect(h.cancel).not.toHaveBeenCalled()
    expect(h.findProject).not.toHaveBeenCalled()
  })

  test('shared project needs W+X: a read share is refused, oversight is not found', async () => {
    policy.mockResolvedValue(shared('read', { rawData: true }))
    await expect(execCommand(collab(), 'p1', 'id')).rejects.toBeInstanceOf(McpLevelDenied)
    policy.mockResolvedValue(shared('read', {}, 'oversight'))
    const err = await execCommand(collab(), 'p1', 'id').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(McpAccessDenied)
    expect(err).not.toBeInstanceOf(McpLevelDenied)
    expect(h.exec).not.toHaveBeenCalled()
  })

  test('shared project needs W+X: a token that did not opt in to shared projects is not found', async () => {
    policy.mockResolvedValue(shared('write', { exploit: true }))
    await expect(execCommand(collab(null), 'p1', 'id')).rejects.toBeInstanceOf(McpAccessDenied)
    await expect(execCommand(collab({ allowlist: ['p-other'] }), 'p1', 'id')).rejects.toBeInstanceOf(McpAccessDenied)
    expect(h.exec).not.toHaveBeenCalled()
  })

  test("shared project needs W+X: the project's own opt-in still applies to a collaborator", async () => {
    policy.mockResolvedValue(shared('write', { exploit: true }))
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'owner', mcpKaliExecEnabled: false })
    await expect(execCommand(collab(), 'p1', 'id')).rejects.toMatchObject({ code: 'project_opt_out' })
    expect(h.exec).not.toHaveBeenCalled()
  })
})
