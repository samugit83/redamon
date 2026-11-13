/**
 * The shared Priority Board actions: what every write enforces, whichever door
 * (the UI routes or the MCP tools) it came through.
 *
 * Run: npx vitest run src/lib/triage/actions.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  activation: vi.fn(),
  liveRun: vi.fn(),
  invalidate: vi.fn(),
  audit: vi.fn(),
  fetch: vi.fn(),
}))

vi.mock('@/lib/agentFetch', () => ({ agentBaseUrl: () => 'http://agent' }))
vi.mock('@/lib/agentAuth', () => ({
  internalKeyHeaders: (b: Record<string, string> = {}) => ({ ...b, 'x-internal-key': 'k' }),
}))
vi.mock('@/lib/activationLock', () => ({ isActivationInProgress: (...a: unknown[]) => h.activation(...a) }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: (...a: unknown[]) => h.liveRun(...a) }))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: (...a: unknown[]) => h.invalidate(...a) }))
vi.mock('@/lib/audit', () => ({ writeAudit: (...a: unknown[]) => h.audit(...a) }))

import { __setLayeredAgentConfirmed,
  recordVerdict, submitReview, listFindings, readFinding, startRun, stopRun,
  TriageActionError,
} from './actions'

const T = { userId: 'alice', projectId: 'p1' }

function answer(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status })
}
function sent(i = 0) {
  const [url, init] = h.fetch.mock.calls[i] as [string, RequestInit]
  return { url, body: JSON.parse(init.body as string) }
}
const VERDICT_OK = { updated: true, label: 'Vulnerability', rescored: true,
                     before: { score: 40 }, after: { score: 75 }, row: { id: 'v1' },
                     layered_publish: true }

beforeEach(() => {
  vi.clearAllMocks()
  __setLayeredAgentConfirmed(true)
  globalThis.fetch = h.fetch as unknown as typeof fetch
  h.activation.mockResolvedValue(false)
  h.liveRun.mockResolvedValue(null)
  h.fetch.mockResolvedValue(answer(VERDICT_OK))
})

async function refusal(p: Promise<unknown>): Promise<TriageActionError> {
  try {
    await p
  } catch (err) {
    expect(err).toBeInstanceOf(TriageActionError)
    return err as TriageActionError
  }
  throw new Error('expected a refusal')
}

describe('recordVerdict', () => {
  test('writes, invalidates the graph cache and returns the rescored row', async () => {
    const out = await recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'app' })
    expect(out).toMatchObject({ rescored: true, after: { score: 75 }, row: { id: 'v1' } })
    expect(h.invalidate).toHaveBeenCalledWith('p1')
    const { url, body } = sent()
    expect(url).toBe('http://agent/graph/triage')
    expect(body).toMatchObject({ op: 'human_verdict', user_id: 'alice', project_id: 'p1',
                                 node_id: 'v1', status: 'confirmed' })
    expect(body.source).toBeUndefined()
  })

  test('refuses during a version switch without calling the agent (B19)', async () => {
    h.activation.mockResolvedValue(true)
    const err = await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'app' }))
    expect(err.code).toBe('busy')
    expect(h.fetch).not.toHaveBeenCalled()
  })

  test('an unreadable activation state refuses (fail closed)', async () => {
    h.activation.mockRejectedValue(new Error('db down'))
    expect((await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed',
                                             channel: 'app' }))).code).toBe('busy')
  })

  test('a switch that started while the write ran turns success into an error', async () => {
    h.activation.mockResolvedValueOnce(false).mockResolvedValueOnce(true)
    const err = await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'app' }))
    expect(err.code).toBe('activation_changed')
    expect(err.message).toMatch(/re-check the finding after the switch/)
    expect(h.invalidate).not.toHaveBeenCalled()
  })

  test('an MCP verdict carries the MCP source and the token prefix', async () => {
    await recordVerdict(T, { findingId: 'v1', status: 'likely_noise', channel: 'mcp',
                             tokenPrefix: 'rdmn_mcp_0a1b2c3d', verdictBy: 'alice' })
    expect(sent().body).toMatchObject({ source: 'mcp', token_prefix: 'rdmn_mcp_0a1b2c3d',
                                        verdict_by: 'alice' })
  })

  test('an app verdict never sends a token prefix', async () => {
    await recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'app',
                             tokenPrefix: 'rdmn_mcp_0a1b2c3d' })
    expect(sent().body.token_prefix).toBeUndefined()
  })

  test('an older agent cannot let an MCP verdict overwrite an app decision, run or no run', async () => {
    // With no run live, the ack was not asked for, and an agent that predates
    // the `decided_in_app` rule overwrote a person's in-app decision.
    __setLayeredAgentConfirmed(false)
    h.fetch.mockResolvedValueOnce(answer({ error: "unknown op 'finding_detail'" }, 400))
    const err = await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'mcp' }))
    expect(err.code).toBe('agent_outdated')
    expect(h.fetch).toHaveBeenCalledOnce()           // the probe, and no write
    expect(sent(0).body.op).toBe('finding_detail')
  })

  test('an acknowledged agent takes the MCP verdict, and is not asked again', async () => {
    __setLayeredAgentConfirmed(false)
    h.fetch.mockResolvedValueOnce(answer({ found: true, layered_publish: true }))
      .mockResolvedValueOnce(answer(VERDICT_OK)).mockResolvedValueOnce(answer(VERDICT_OK))
    await recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'mcp' })
    expect(sent(1).body.op).toBe('human_verdict')
    await recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'mcp' })
    expect(h.fetch).toHaveBeenCalledTimes(3)         // probe, write, write
  })

  test('a person\'s verdict never waits on a run: the publish honours it', async () => {
    h.liveRun.mockResolvedValue({ id: 'r1', status: 'running' })
    await recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'app' })
    expect(h.fetch).toHaveBeenCalledOnce()
  })

  test('refusals map to stable codes', async () => {
    for (const [body, code] of [
      [{ updated: false, reason: 'muted' }, 'muted'],
      [{ updated: false, reason: 'decided_in_app' }, 'decided_in_app'],
      [{ updated: false, reason: 'ambiguous', labels: ['Secret', 'Vulnerability'] }, 'ambiguous'],
      [{ updated: false, reason: 'not_found' }, 'not_found'],
    ] as const) {
      h.fetch.mockResolvedValueOnce(answer(body))
      const err = await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed', channel: 'mcp' }))
      expect(err.code).toBe(code)
    }
  })

  test('a write timeout from the agent is busy', async () => {
    h.fetch.mockResolvedValueOnce(answer({ error: 'locked', code: 'busy' }, 503))
    expect((await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed',
                                             channel: 'app' }))).code).toBe('busy')
  })

  test('a lost answer to a write is an unknown outcome, not "unavailable"', async () => {
    h.fetch.mockRejectedValueOnce(Object.assign(new Error('reset'), { code: 'ECONNRESET' }))
    expect((await refusal(recordVerdict(T, { findingId: 'v1', status: 'confirmed',
                                             channel: 'app' }))).code).toBe('outcome_unknown')
  })
})

describe('what a failure reports (G-8)', () => {
  test('an agent failure carries the agent status, code and class, never its text', async () => {
    h.fetch.mockResolvedValueOnce(answer({
      error: 'The triage operation failed. The details are in the agent log.',
      code: 'internal_error', error_class: 'ServiceUnavailable',
    }, 500))
    const err = await refusal(listFindings(T, { channel: 'app' }))
    expect(err.code).toBe('agent_failed')
    expect(err.message).toBe('The findings service failed.')
    expect(err.details).toEqual({ upstreamStatus: 500, agentCode: 'internal_error', errorClass: 'ServiceUnavailable' })
  })

  test('a deployment without INTERNAL_API_KEY keeps the agent sentence that says what to do', async () => {
    const text = 'INTERNAL_API_KEY is not configured; triage operations are disabled. Generate the secret via redamon.sh.'
    h.fetch.mockResolvedValueOnce(answer({ error: text, code: 'not_configured' }, 503))
    const err = await refusal(listFindings(T, { channel: 'app' }))
    expect(err.message).toBe(text)
    expect(err.details).toMatchObject({ upstreamStatus: 503, agentCode: 'not_configured' })
  })

  test('an unreachable agent names the errno', async () => {
    h.fetch.mockRejectedValueOnce(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }))
    const err = await refusal(listFindings(T, { channel: 'app' }))
    expect(err.code).toBe('agent_unreachable')
    expect(err.details).toEqual({ cause: 'ECONNREFUSED' })
  })
})

describe('submitReview', () => {
  const input = {
    findingId: 'v1', evidenceHash: 'a'.repeat(40), verdict: 'doubtful',
    evidenceQuote: 'SECRET-QUOTE', why: 'SECRET-WHY', fixLever: 'SECRET-LEVER',
    tokenId: 'tok1', tokenPrefix: 'rdmn_mcp_0a1b2c3d', actorUserId: 'alice',
  }

  test('is audited with the token and a hash of the text, never the text', async () => {
    h.fetch.mockResolvedValue(answer({ written: true, label: 'Vulnerability', rescored: true,
                                       before: { score: 70 }, after: { score: 20 },
                                       accepted: { verdict: 'doubtful', disputed_facts: [] },
                                       dropped: [], layered_publish: true }))
    const out = await submitReview(T, input)
    expect(out.accepted).toMatchObject({ verdict: 'doubtful' })
    const audit = h.audit.mock.calls[0][0]
    expect(audit.action).toBe('triage.review')
    expect(audit.after).toMatchObject({ tokenId: 'tok1', tokenPrefix: 'rdmn_mcp_0a1b2c3d',
                                        verdict: 'doubtful' })
    expect(audit.after.textSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(audit)).not.toMatch(/SECRET-/)
    expect(sent().body).toMatchObject({ op: 'submit_review', source: 'mcp',
                                        evidence_hash: 'a'.repeat(40),
                                        review: { verdict: 'doubtful', why: 'SECRET-WHY' } })
    expect(h.invalidate).toHaveBeenCalledWith('p1')
  })

  test('a refusal names its reason in words an agent can act on', async () => {
    h.fetch.mockResolvedValue(answer({ written: false, reason: 'decided_by_person' }))
    const err = await refusal(submitReview(T, input))
    expect(err.code).toBe('decided_by_person')
    expect(err.message).toMatch(/person decided/)
    expect(h.audit).not.toHaveBeenCalled()
  })

  test('refuses during a version switch', async () => {
    h.activation.mockResolvedValue(true)
    expect((await refusal(submitReview(T, input))).code).toBe('busy')
    expect(h.fetch).not.toHaveBeenCalled()
  })
})

describe('reads and runs', () => {
  test('listFindings pushes the filters down', async () => {
    h.fetch.mockResolvedValue(answer({ findings: [], total: 0 }))
    await listFindings(T, { filters: { decidedBy: 'review', reviewCurrent: 'stale' }, channel: 'app' })
    expect(sent().body).toMatchObject({ op: 'list_findings', decided_by: 'review',
                                        review_current: 'stale' })
  })

  test('readFinding turns an ambiguous id into a named refusal', async () => {
    h.fetch.mockResolvedValue(answer({ found: false, ambiguous: ['Secret', 'Vulnerability'] }))
    const err = await refusal(readFinding(T, 'v1', undefined, 'app'))
    expect(err.code).toBe('ambiguous')
    expect(err.details).toEqual({ labels: ['Secret', 'Vulnerability'] })
  })

  test('startRun posts to the headless endpoint with the trigger and budget', async () => {
    h.fetch.mockResolvedValue(answer({ runId: 'run-9', attached: false }, 202))
    const out = await startRun(T, { trigger: 'mcp', tokenId: 'tok1', maxReviewBudget: 1000 })
    expect(out).toEqual({ runId: 'run-9', attached: false })
    const { url, body } = sent()
    expect(url).toBe('http://agent/triage/runs')
    expect(body).toEqual({ user_id: 'alice', project_id: 'p1', trigger: 'mcp',
                           token_id: 'tok1', max_review_budget: 1000 })
  })

  test("startRun names a collaborator's run's person beside the tenant (step 5.10)", async () => {
    h.fetch.mockResolvedValue(answer({ runId: 'run-9', attached: false }, 202))
    await startRun(T, { trigger: 'mcp', tokenId: 'tok1', maxReviewBudget: 1000, actorUserId: 'bob' })
    expect(sent().body).toEqual({ user_id: 'alice', project_id: 'p1', trigger: 'mcp', actor_user_id: 'bob',
                                  token_id: 'tok1', max_review_budget: 1000 })
  })

  test('stopRun reports a refusal while publishing', async () => {
    h.fetch.mockResolvedValue(answer({ stopped: false, reason: 'publishing', runId: 'r1' }))
    expect(await stopRun(T, 'mcp')).toEqual({ stopped: false, reason: 'publishing', runId: 'r1' })
    expect(sent().url).toBe('http://agent/triage/runs/stop')
  })
})
