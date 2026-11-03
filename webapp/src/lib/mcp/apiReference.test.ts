/**
 * The generated MCP API reference, and the scope declarations it publishes.
 *
 * Two things can silently lie here:
 *
 *  - a tool's `_meta` scope declaration disagreeing with the `requireScope`
 *    call in its body. The page (and any client reading `_meta`) would then
 *    promise a permission model the code does not enforce. Every tool is called
 *    through a real MCP client with each declared scope withheld, and must be
 *    refused naming exactly that scope; with only the declared scopes, the
 *    documented example call must get all the way to the backend.
 *  - the wiki page going stale after a tool changes. When the wiki checkout is
 *    present the page is compared byte for byte with a fresh render.
 *
 * `npm run docs:mcp` runs this file with MCP_DOCS_WRITE=1, which writes the
 * page instead of comparing it.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync, writeFileSync } from 'fs'
import { wikiCheckoutPresent } from '@/lib/wikiCheckout.testUtils'
import path from 'path'
import { fileURLToPath } from 'url'
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

// Every model is absent, so a call that passes every check fails on its first
// database or graph read (REACHED_THE_BACKEND). touchTokenUsage runs before a
// tool's try block, so it must not throw.
vi.mock('@/lib/prisma', () => ({
  default: { mcpAccessToken: { update: () => Promise.resolve() } },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))
vi.mock('@/lib/mcp/graphClient', () => ({
  execCypher: () => Promise.reject(new Error('no graph in tests')),
  nlQuery: () => Promise.reject(new Error('no graph in tests')),
  graphSchemaDoc: () => Promise.reject(new Error('no graph in tests')),
}))
vi.mock('@/lib/mcp/kaliClient', () => ({
  kaliToolboxDoc: () => Promise.reject(new Error('no agent in tests')),
}))

import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import type { Tool } from '@modelcontextprotocol/sdk/types.js'

import { MCP_SCOPES, McpScopeError, __resetRateLimiter, type McpScope } from '@/lib/mcpAuth'
import { buildMcpServer } from './server'
import { API_REFERENCE_PAGE, exampleArgs, listAdvertisedTools, renderApiReference, toolScopes } from './apiReference'

const WIKI_DIR = process.env.MCP_DOCS_WIKI_DIR
  || fileURLToPath(new URL('../../../../redamon.wiki/', import.meta.url))
const WRITE = process.env.MCP_DOCS_WRITE === '1'

/** A real wiki checkout; an empty one fails unless allowed (wikiCheckout.testUtils.ts). */
const hasWikiCheckout = () => wikiCheckoutPresent(WIKI_DIR)

/**
 * Arguments that make a conditional scope apply, merged over the example call.
 * A new conditional scope needs an entry. `undefined` removes an example
 * argument: query_graph refuses `question` and `cypher` together.
 */
const CONDITIONAL_TRIGGERS: Record<string, Record<string, unknown>> = {
  'query_graph/graph:cypher': { question: undefined, cypher: 'MATCH (n) RETURN n LIMIT 1' },
  'start_recon/recon:overwrite': { mode: 'overwrite' },
  'update_project_scope/engagement:authorize': {
    authorization: {
      documentSha256: '0'.repeat(64),
      documentKind: 'hackerone_program',
      issuedAt: '2026-01-01T00:00:00.000Z',
    },
  },
}

/**
 * What a call that got past scope, argument validation and the tool's own
 * argument checks returns here: every model is absent, so it fails on its first
 * database or graph read with the generic message.
 */
const REACHED_THE_BACKEND = 'The request could not be completed.'

/**
 * Tools that SUCCEED with every backend absent.
 *
 * `describe_recon_settings` is a projection of frozen constants - the same
 * property that makes it answer when Neo4j and Postgres are down.
 * `list_recon_presets` reads the user's presets from Postgres too, but it lists
 * the built-ins without it and reports the user presets as "unavailable" rather
 * than failing. So "it got past every check" shows up here as a SUCCESS rather
 * than as the generic database failure, and asserting the generic message for
 * them would be asserting that they are broken.
 *
 * Listed explicitly, not detected: a tool that stopped reading tenant data by
 * accident must fail this file, not quietly join the exemption.
 */
const BACKEND_FREE_TOOLS = new Set(['describe_recon_settings', 'list_recon_presets'])

/** Got past scope and argument validation, whichever of the two shapes it takes. */
function expectAllowed(tool: string, r: { isError: boolean; text: string }) {
  if (BACKEND_FREE_TOOLS.has(tool)) {
    expect(r.isError, `${tool} should answer without a backend`).toBe(false)
    expect(r.text.length, `${tool} returned nothing`).toBeGreaterThan(0)
    return
  }
  expect(r.text, `${tool} with only its declared scopes`).toBe(REACHED_THE_BACKEND)
}

async function callAs(scopes: McpScope[], name: string, args: Record<string, unknown>) {
  const server = buildMcpServer({
    token: { tokenId: `t-${scopes.join(',')}`, userId: 'owner', tokenPrefix: 'rdmn_mcp_aaaaaaaa', name: 'test', scopes },
  })
  const client = new Client({ name: 'scope-test', version: '1.0.0' }, { capabilities: {} })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  try {
    const result = await client.callTool({ name, arguments: args })
    const content = result.content as { type: string; text?: string }[]
    return { isError: Boolean(result.isError), text: content.map(c => c.text ?? '').join('\n') }
  } finally {
    await client.close()
    await server.close()
  }
}

const denial = (scope: McpScope) => new McpScopeError(scope).message
const without = (scope: McpScope) => MCP_SCOPES.filter(s => s !== scope)

let tools: Tool[]

beforeEach(async () => {
  __resetRateLimiter()
  // The exec tools are behind a deployment switch that refuses BEFORE the
  // backend is reached. This file is about scopes matching what each tool
  // enforces, so the switch is turned on; kaliTools.test.ts owns the off case.
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  // The same for the Agent in the Loop tools, off by default.
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  // One test calls every write tool with the same token, which is more than the
  // real 10-a-minute write bucket allows. This file is about scopes, not rates.
  vi.stubEnv('MCP_RATE_WRITE_PER_MIN', '1000')
  vi.stubEnv('MCP_RATE_LOOP_PER_MIN', '1000')
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
  tools = await listAdvertisedTools()
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllEnvs()
})

describe('every tool declares its scopes and behaviour', () => {
  test('each tool carries a scope declaration and MCP annotations', () => {
    for (const tool of tools) {
      expect(toolScopes(tool), `${tool.name} has no scope declaration`).not.toBeNull()
      expect(toolScopes(tool)!.required.length, `${tool.name} requires no scope`).toBeGreaterThan(0)
      expect(tool.annotations?.readOnlyHint, `${tool.name} has no readOnlyHint`).toBeTypeOf('boolean')
    }
  })

  test('every scope a token can hold is used by some tool', () => {
    const used = new Set(tools.flatMap(t => {
      const s = toolScopes(t)!
      return [...s.required, ...(s.conditional ?? []).map(c => c.scope)]
    }))
    expect([...MCP_SCOPES].filter(s => !used.has(s))).toEqual([])
  })
})

describe('declared scopes match what each tool enforces', () => {
  test('withholding a required scope is refused, naming that scope', async () => {
    for (const tool of tools) {
      for (const scope of toolScopes(tool)!.required) {
        const r = await callAs(without(scope), tool.name, exampleArgs(tool))
        expect(r.isError, `${tool.name} ran without ${scope}`).toBe(true)
        expect(r.text, `${tool.name} without ${scope}`).toBe(denial(scope))
      }
    }
  })

  test('the declared required scopes are enough to reach the backend', async () => {
    for (const tool of tools) {
      const r = await callAs(toolScopes(tool)!.required, tool.name, exampleArgs(tool))
      expectAllowed(tool.name, r)
    }
  })

  test('a conditional scope is enforced only when its argument is used', async () => {
    for (const tool of tools) {
      for (const c of toolScopes(tool)!.conditional ?? []) {
        const trigger = CONDITIONAL_TRIGGERS[`${tool.name}/${c.scope}`]
        expect(trigger, `add a CONDITIONAL_TRIGGERS entry for ${tool.name}/${c.scope}`).toBeDefined()
        const args = { ...exampleArgs(tool), ...trigger }

        const denied = await callAs(without(c.scope), tool.name, args)
        expect(denied.text, `${tool.name} with ${JSON.stringify(trigger)}`).toBe(denial(c.scope))

        const allowed = await callAs([...toolScopes(tool)!.required, c.scope], tool.name, args)
        expectAllowed(tool.name, allowed)
      }
    }
  })
})

describe('the rendered reference', () => {
  test('every documented example call is accepted by the server', async () => {
    for (const tool of tools) {
      const r = await callAs([...MCP_SCOPES], tool.name, exampleArgs(tool))
      expectAllowed(tool.name, r)
    }
  })

  test('documents every tool with its permission and arguments', () => {
    const page = renderApiReference(tools)
    for (const tool of tools) expect(page).toContain(`### \`${tool.name}\``)
    expect(page).toContain('`recon:scan`, plus `recon:overwrite` when `mode` is "overwrite"')
    expect(page).toContain('| `projectId` | `string` | yes |')
  })

  test('is deterministic', () => {
    expect(renderApiReference(tools)).toBe(renderApiReference(tools))
  })
})

describe(`the wiki page (${API_REFERENCE_PAGE})`, () => {
  const pagePath = path.join(WIKI_DIR, API_REFERENCE_PAGE)

  test.runIf(WRITE)('is written', () => {
    if (!hasWikiCheckout()) {
      throw new Error(`No wiki checkout at ${WIKI_DIR}. Clone redamon.wiki there or set MCP_DOCS_WIKI_DIR.`)
    }
    writeFileSync(pagePath, renderApiReference(tools))
    console.info(`[docs:mcp] wrote ${pagePath}`)
  })

  // Without a wiki checkout there is nothing to compare: this skips rather than passes.
  test.skipIf(WRITE || !hasWikiCheckout())('matches a fresh render', () => {
    const current = existsSync(pagePath) ? readFileSync(pagePath, 'utf8') : ''
    expect(current, `${pagePath} is stale: run \`npm run docs:mcp\` in webapp/`).toBe(renderApiReference(tools))
  })
})
