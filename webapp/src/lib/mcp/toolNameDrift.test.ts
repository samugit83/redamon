/**
 * P8: no shipped agent-facing string names a tool that is not on the surface.
 *
 * `playbook.ts` is the one that makes this worth a test rather than a habit. It
 * is read by the connected agent AT RUN TIME, so a line still saying "call
 * `tighten_engagement_roe`" does not produce a stale doc, it sends an agent
 * after something that answers "unknown tool" - and an unattended agent's reply
 * to an opaque failure is usually another attempt.
 *
 * The same failure has a quieter form in `onboarding.ts` and `scopeCopy.ts`:
 * those are written into the onboarding pack and the token-permission UI, so a
 * deleted tool named there teaches a person a capability that does not exist.
 *
 * Deliberately crude, and checked against the LIVE `tools/list` rather than a
 * list of names, because a list of names is the thing that goes stale.
 *
 * @vitest-environment node
 */
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'

import { describe, test, expect, beforeAll, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js'

import { buildMcpServer } from './server'
import type { McpContext } from './tools'

const ctx: McpContext = {
  token: {
    tokenId: 't1', userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa',
    name: 'drift', scopes: ['recon:read'] as never,
  },
}

let live: Set<string>

beforeAll(async () => {
  // The build's full surface. Unset reads as off and withdraws the sandbox
  // tools, while docker-compose.yml defaults the switch on.
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  // Agent in the Loop is off by default; the loop tools are part of the build.
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  const server = buildMcpServer(ctx)
  const client = new Client({ name: 'drift-test', version: '1.0.0' }, { capabilities: {} })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  try {
    const result = await client.request({ method: 'tools/list' }, ListToolsResultSchema)
    live = new Set(result.tools.map(t => t.name))
  } finally {
    await client.close()
    await server.close()
  }
})

/** Files whose strings reach an agent or a person at run time. */
const AGENT_FACING = [
  'playbook.ts',
  'onboarding.ts',
  'scopeCopy.ts',
  'catalogTools.ts',
  'instructions.ts',
  'writeTools.ts',
  'engagementTools.ts',
  // The tool descriptions and the result notes: server.ts carries every
  // description an agent reads in tools/list, and profiles.ts the job-specific
  // traps the pack renders. Both were outside the sweep while claiming "nothing
  // here can mute".
  'server.ts',
  'profiles.ts',
  'muteTools.ts',
  'verdictTools.ts',
  'findingTools.ts',
  // update_project_scope's refusals and result note point the agent at the
  // next call (preflight_scope_check), so they go stale like any description.
  'scopeTools.ts',
  // The loop tools' refusals and hints tell a driver what to call next, and
  // the loop skill teaches the whole procedure.
  'loopTools.ts',
  'loopSkill.ts',
]

/**
 * Anything shaped like one of our tool names.
 *
 * Two words or more in snake_case, starting with a verb-ish token we actually
 * use. Deliberately narrow: matching every snake_case identifier would flag
 * Python settings keys and SQL columns, and a test that cries wolf is one
 * people switch off.
 */
const TOOL_SHAPED = /\b((?:get|list|start|stop|update|create|query|run|set|cancel|queue|compare|describe|attach|preflight|tighten|kali|graph|mute|unmute|search|submit|loop)_[a-z][a-z0-9_]{2,})\b/g

/**
 * Comments are stripped, deliberately.
 *
 * A comment explaining that a tool was DELETED is the correction, not the
 * defect, and flagging it would teach people to remove the explanation rather
 * than the stale instruction. What reaches an agent is the string literals.
 */
function stripComments(text: string): string {
  return text
    .split('\n')
    .map(line => (/^\s*(\/\/|\*|\/\*)/.test(line) ? '' : line))
    .join('\n')
}

function namedIn(file: string): Map<string, number[]> {
  const raw = readFileSync(fileURLToPath(new URL(`./${file}`, import.meta.url)), 'utf8')
  const found = new Map<string, number[]>()
  for (const [i, line] of stripComments(raw).split('\n').entries()) {
    for (const m of line.matchAll(TOOL_SHAPED)) {
      const name = m[1]
      // An audit action, not a tool: `mcp.attach_authorization`.
      if (line.includes(`mcp.${name}`)) continue
      found.set(name, [...(found.get(name) ?? []), i + 1])
    }
  }
  return found
}

/**
 * Snake_case identifiers that are not tools and never were.
 *
 * Named individually rather than skipped by a pattern, so a NEW name that is
 * not a tool still has to be looked at once.
 */
const NOT_TOOLS = new Set([
  // Registry dispositions, which share the shape by coincidence.
  'create_only',
  // Outcome codes on an audit row, never spoken to an agent.
  'start_outcome_unknown', 'start_refused_', 'stop_failed',
  // Error codes an agent does see, on purpose: each names the check-then-retry
  // contract in the tool description, and none is a tool.
  'mute_outcome_unknown', 'unmute_outcome_unknown',
  // Audit actions written without the `mcp.` prefix on their own line.
  'attach_authorization',
  // graph_summary's warning code for a lost graph (plan 09.4).
  'graph_data_missing',
  // The refusal code of a driver token that also holds a write or exec scope.
  'loop_token_too_broad',
  // A loop run that ended for want of an answer: codes a driver reads in the
  // session list, and the pack tells it how to resume after each.
  'loop_no_driver', 'loop_step_not_answered',
])

describe('P8: every tool named in an agent-facing string exists', () => {
  test('the live surface was actually read', () => {
    expect(live.size).toBeGreaterThan(20)
    expect(live.has('query_graph')).toBe(true)
  })

  test.each(AGENT_FACING)('%s names no tool that tools/list does not have', file => {
    const problems: string[] = []
    for (const [name, lines] of namedIn(file)) {
      if (live.has(name) || NOT_TOOLS.has(name)) continue
      problems.push(`${file}:${lines.join(',')}: '${name}'`)
    }
    expect(problems).toEqual([])
  })

  test('the deleted tool is named nowhere agent-facing', () => {
    // Named explicitly as well as caught by the sweep above, because this is
    // the one the sweep was written for: `playbook.ts` instructed the agent to
    // call it, and `tools.ts` routed the call.
    for (const file of AGENT_FACING) {
      expect(namedIn(file).has('tighten_engagement_roe'), file).toBe(false)
    }
  })

  test('no agent-facing string still claims a one-way rule', () => {
    // The tool-name sweep above would NOT have caught this, and did not: the
    // onboarding pack told an agent "you can never loosen the rules of
    // engagement... a rate ceiling may fall and never rise" long after nothing
    // enforced it. A stale CLAIM is worse than a stale tool name, because the
    // tool name produces an error the agent can see and the claim produces
    // confident inaction.
    const STALE_CLAIMS = [
      /may (only )?move in the safe direction/i,
      /never loosen/i,
      /may fall and never rise/i,
      /may grow and never shrink/i,
      /tighten[- ]only/i,
      // Mute and unmute went from "cannot" to "can, with triage:mute".
      /nothing (on this surface|here) can (mute|unmute)/i,
      /no mute here/i,
      // The verdict stopped being the only write when reviews arrived, and a
      // live triage run stopped refusing verdicts once publishes were layered.
      /one durable write/i,
      /only durable write/i,
      /one write on this surface/i,
      /refused while a triage run is in progress/i,
      /cannot mute or unmute/i,
      // Muting lost its daily cap. "Daily budget" alone still names the
      // question budget, so these match the mute's wording only.
      /daily mute budget/i,
      /within a daily budget/i,
      /MCP_MUTE_DAILY_BUDGET/,
      // update_project_scope edits a batch's host list, and create_project
      // honours settings.targetGuardrailEnabled.
      /domain-batch configuration.*outside what any token may write/i,
      /cannot change what RedAmon points at/i,
      // Nested wildcards shipped: a deeper wildcard is a scan root of its own,
      // and a subdomain list names EXACT hosts, never seeds beside discovery.
      /A wildcard must name a registrable domain, not a deeper name/i,
      /Hosts seeded in addition to whatever discovery finds/i,
      // A label absent from the census stopped meaning "never scanned" alone:
      // it is also "scanned and clean" or "all of it muted", and graph_summary's
      // coverage block now says which hosts a module looked at (plan 09.2).
      /(missing|absent|entirely)[^.]*that surface was never scanned/i,
      /missing from the census means \*\*never scanned/i,
      /absent entirely was never scanned/i,
      // The registry decides which rate fields the RoE ceiling caps (roe_capped),
      // and a count copied into prose said 17 long after it was 20.
      /\b\d+ rate fields\b/i,
    ]
    const problems: string[] = []
    for (const file of AGENT_FACING) {
      const text = readFileSync(fileURLToPath(new URL(`./${file}`, import.meta.url)), 'utf8')
      for (const [i, line] of stripComments(text).split('\n').entries()) {
        for (const claim of STALE_CLAIMS) {
          if (claim.test(line)) problems.push(`${file}:${i + 1}: ${line.trim().slice(0, 110)}`)
        }
      }
    }
    expect(problems).toEqual([])
  })

  test('the sweep would actually catch one', () => {
    // A regex that matched nothing would make every assertion above vacuous.
    const found = namedIn('playbook.ts')
    expect(found.has('update_recon_settings')).toBe(true)
    expect(found.has('preflight_scope_check')).toBe(true)
  })
})
