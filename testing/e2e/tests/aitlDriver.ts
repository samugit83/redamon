import { expect, type APIRequestContext } from '@playwright/test'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'

/**
 * A scripted Agent in the Loop driver: it plays the person's external agent over
 * /api/mcp-server, waiting for steps and answering them by purpose. Shared by
 * agentInTheLoop.spec.ts and captureAgentInTheLoopDocsShots.spec.ts.
 */

export const LAB_IP = '172.28.0.91'
const LAB_CONTAINER = 'skiller-sqli'
let labHost = LAB_IP

const sandboxNetwork = (userId: string) =>
  `redamon-sbx-${createHash('sha256').update(userId).digest('hex').slice(0, 16)}`
const docker = (...args: string[]) => new Promise<string>(resolve =>
  execFile('docker', args, (_err, stdout) => resolve(String(stdout ?? '').trim())))
const labIpOn = (net: string) =>
  docker('inspect', '-f', `{{with index .NetworkSettings.Networks "${net}"}}{{.IPAddress}}{{end}}`, LAB_CONTAINER)

/** The lab's address as the person's Kali sandbox reaches it (set by labOnSandbox). */
export const labAddress = () => labHost

/**
 * Puts the lab where the person's sandbox can reach it. A sandbox routes only its own network
 * (redamon-sbx-<sandbox key>, sandbox_contract.network_name, a /28 of 10.214.0.0/16) and an
 * isolated gateway, so the lab's pentest-net address 172.28.0.91 is never reached from it: the
 * sandbox is started first (a no-op MCP kali_exec on `projectId`, which must allow MCP sandbox
 * commands), the lab joins its network as kali_reverse_ports_live.py's labs do, and the answers
 * then use the lab's address there. A watcher joins it again, and reads the address again, if the
 * sandbox's network is recreated during the run. Returns the function that stops the watcher and
 * takes the lab off.
 */
export async function labOnSandbox(
  api: APIRequestContext, kaliToken: string, projectId: string, userId: string,
): Promise<() => Promise<void>> {
  for (let i = 0; i < 12; i++) {
    const r = await mcpCall(api, kaliToken, 'kali_exec', { projectId, command: 'true', waitSeconds: 30 })
    if (!r.isError && r.json?.status !== 'starting') break
    expect(i, `the sandbox did not start: ${r.text.slice(0, 200)}`).toBeLessThan(11)
    await new Promise(res => setTimeout(res, 5_000))
  }
  const net = sandboxNetwork(userId)
  await docker('network', 'connect', net, LAB_CONTAINER)
  labHost = await labIpOn(net)
  expect(labHost, `the lab has no address on ${net}`).toMatch(/^10\.214\./)
  let busy = false
  const timer = setInterval(() => {
    if (busy) return
    busy = true
    // Refused while the lab is already on the network; fine.
    void docker('network', 'connect', net, LAB_CONTAINER)
      .then(() => labIpOn(net)).then(ip => { if (ip) labHost = ip })
      .finally(() => { busy = false })
  }, 1_000)
  return async () => {
    clearInterval(timer)
    await docker('network', 'disconnect', net, LAB_CONTAINER)
    labHost = LAB_IP
  }
}

export interface CallResult { isError: boolean; text: string; json: Record<string, any> | null }
export type Step = Record<string, any>

let rpcId = 0

export async function mcpCall(
  api: APIRequestContext, token: string, name: string, args: Record<string, unknown>,
): Promise<CallResult> {
  const res = await api.post('/api/mcp-server', {
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json, text/event-stream',
    },
    data: { jsonrpc: '2.0', id: ++rpcId, method: 'tools/call', params: { name, arguments: args } },
    timeout: 90_000,
  })
  const body = await res.json()
  const result = body.result ?? {}
  const text = (result.content ?? []).map((c: { text?: string }) => c.text ?? '').join('\n')
  let json: Record<string, any> | null = null
  try { json = JSON.parse(text) } catch { json = null }
  return { isError: Boolean(result.isError || body.error), text: text || JSON.stringify(body.error ?? {}), json }
}

/** The session ids of the chats on `projectId`, newest first. */
export async function sessionIds(api: APIRequestContext, projectId: string): Promise<string[]> {
  const res = await api.get(`/api/conversations?projectId=${projectId}`)
  if (!res.ok()) return []
  const rows = (await res.json()) as { sessionId?: string }[]
  return Array.isArray(rows) ? rows.map(r => r.sessionId!).filter(Boolean) : []
}

/** The session id of the chat just started on `projectId`: one that is not in `before`. */
export async function newSession(api: APIRequestContext, projectId: string, before: string[], timeoutMs = 30_000): Promise<string> {
  const until = Date.now() + timeoutMs
  while (Date.now() < until) {
    const fresh = (await sessionIds(api, projectId)).find(id => !before.includes(id))
    if (fresh) return fresh
    await new Promise(r => setTimeout(r, 500))
  }
  throw new Error(`no new chat session on ${projectId}`)
}

export class Driver {
  /**
   * The one session this driver answers. A driver serves every loop run of its user, so a
   * test that does not scope it would also answer a run another test left behind.
   */
  session?: string

  constructor(private api: APIRequestContext, private token: string, readonly name?: string) {}

  async wait(waitSeconds = 20, sessionId = this.session): Promise<{ step: Step | null; sessions: Step[]; hint: string }> {
    const r = await mcpCall(this.api, this.token, 'loop_wait_step', {
      waitSeconds, ...(this.name ? { driver: this.name } : {}), ...(sessionId ? { sessionId } : {}),
    })
    expect(r.isError, r.text).toBe(false)
    return r.json as never
  }

  /** The next step, read in full (every page). */
  async next(timeoutMs = 120_000): Promise<Step> {
    const until = Date.now() + timeoutMs
    while (Date.now() < until) {
      const got = await this.wait()
      if (got.step) return this.readAll(got.step)
    }
    throw new Error('no step arrived')
  }

  async readAll(step: Step, full = false): Promise<Step> {
    let prompt = step.prompt as string
    let cursor = step.page.nextCursor as number | null
    while (cursor !== null) {
      const r = await this.get(step.stepId, cursor, full)
      prompt += r.prompt
      cursor = r.page.nextCursor
    }
    return { ...step, fullPrompt: prompt }
  }

  async get(stepId: string, cursor = 0, full = false): Promise<Step> {
    const r = await mcpCall(this.api, this.token, 'loop_get_step', {
      stepId, cursor, full, ...(this.name ? { driver: this.name } : {}),
    })
    expect(r.isError, r.text).toBe(false)
    return r.json!.step
  }

  submit(stepId: string, answer: string) {
    return mcpCall(this.api, this.token, 'loop_submit_step', { stepId, answer, ...(this.name ? { driver: this.name } : {}) })
  }

  decline(stepId: string, reason: string) {
    return mcpCall(this.api, this.token, 'loop_submit_step', { stepId, declined: true, reason })
  }

  /** Wait until a session of one of `projectIds` reaches `state`, answering nothing. */
  async until(state: string, projectIds: string[], timeoutMs = 120_000): Promise<Step> {
    const until = Date.now() + timeoutMs
    while (Date.now() < until) {
      const got = await this.wait(5)
      const s = got.sessions.find((x: Step) => projectIds.includes(x.projectId))
      if (s?.state === state) return s
    }
    throw new Error(`session never reached ${state}`)
  }

  /** Answer the setup steps a run opens before its first think, then return that think step. */
  async firstThink(): Promise<Step> {
    for (;;) {
      const step = await this.next()
      if (step.purpose === 'think') return step
      const answer = (ANSWERS as Record<string, string>)[step.purpose]
      if (!answer) {
        await this.decline(step.stepId, 'e2e driver: unexpected purpose')
        throw new Error(`unexpected purpose ${step.purpose}`)
      }
      expect((await this.submit(step.stepId, answer)).isError).toBe(false)
    }
  }

  /** Answer think steps with `complete` until a report step comes, and answer it too. */
  async finish(report = ANSWERS.report) {
    for (;;) {
      const step = await this.next()
      if (step.purpose === 'report') {
        await this.submit(step.stepId, report)
        return
      }
      const answer = step.purpose === 'think' ? ANSWERS.complete : (ANSWERS as Record<string, string>)[step.purpose]
      expect(answer, `unexpected purpose ${step.purpose}`).toBeTruthy()
      await this.submit(step.stepId, answer!)
    }
  }
}

const json = (o: unknown) => JSON.stringify(o)

/** Scripted answers, by purpose (the shapes the agent's parsers expect). */
export const ANSWERS = {
  scope_guardrail: json({ allowed: true, reason: 'local lab in scope' }),
  get classify() {
    return json({
      attack_path_type: 'sql_injection', required_phase: 'informational', confidence: 0.9,
      reasoning: 'fingerprinting a lab web server', target_host: labHost, target_port: 5000,
    })
  },
  deep_think: json({
    situation_assessment: 'nothing known yet about the lab web server', competing_hypotheses: [],
    attack_vectors_identified: ['web application'], recommended_approach: 'fingerprint the server first',
    priority_order: ['fetch the landing page'], risks_and_mitigations: 'read-only requests only',
  }),
  report: '# AitL e2e report\n\nThe lab web server answered on port 5000. This report was written by the e2e driver.',
  get curl() {
    return json({
      thought: 'AITL-E2E fetch the landing page', reasoning: 'see what the server answers',
      action: 'use_tool', tool_name: 'execute_curl', tool_args: { args: `-s -i http://${labHost}:5000/` },
      updated_todo_list: [],
    })
  },
  toExploitation: json({
    thought: 'AITL-E2E the landing page is known', reasoning: 'the objective needs the exploitation phase next',
    action: 'transition_phase',
    phase_transition: { to_phase: 'exploitation', reason: 'e2e', planned_actions: ['none'], risks: ['none'] },
    updated_todo_list: [],
  }),
  complete: json({
    thought: 'AITL-E2E done', reasoning: 'the e2e scenario is complete', action: 'complete',
    completion_reason: 'AitL e2e scenario complete', updated_todo_list: [],
  }),
}
