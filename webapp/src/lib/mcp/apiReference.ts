/**
 * Renders the MCP API reference page for the wiki (redamon.wiki/MCP-API-Reference.md).
 *
 * The page is built from the server's own `tools/list` answer, the same bytes a
 * connected client receives, rather than from the source. Arguments, types,
 * constraints and descriptions therefore cannot be documented one way and
 * served another. The only hand-written text is the page frame below.
 *
 * Output is deterministic (no dates, no version) so the drift test in
 * apiReference.test.ts can compare it byte for byte.
 */
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ListToolsResultSchema, type Tool } from '@modelcontextprotocol/sdk/types.js'

import {
  DEFAULT_MCP_SCOPES,
  MCP_DEFAULT_EXPIRY_DAYS,
  MCP_EXPIRY_PRESET_DAYS,
  MCP_SCOPES,
  MCP_TOKEN_PREFIX,
  McpScopeError,
  type McpScope,
} from '@/lib/mcpAuth'
import { MCP_SCOPE_COPY } from '@/lib/mcp/scopeCopy'
import { buildMcpServer, SCOPES_META_KEY, type ToolScopes } from '@/lib/mcp/server'

export const API_REFERENCE_PAGE = 'MCP-API-Reference.md'

/**
 * Must stay byte-identical to what DevergoLabs/scripts/add-wiki-canonical.mjs
 * writes, or re-running that script rewrites this page and the drift test fails.
 */
const CANONICAL_URL = 'https://www.redamon.org/docs/mcp-api-reference'
const CANONICAL_BANNER =
  '<!-- canonical-banner -->\n' +
  `> 📖 **Canonical version:** read this page on the official docs site — **[${CANONICAL_URL}](${CANONICAL_URL})**. The GitHub wiki is a mirror.\n` +
  '<!-- canonical-banner -->\n\n'

/** Ask a real server for its tool list over the SDK's in-memory transport. */
export async function listAdvertisedTools(): Promise<Tool[]> {
  // tools/list does not depend on the token, so any well-formed context will do.
  const server = buildMcpServer({
    token: { tokenId: 'docs', userId: 'docs', tokenPrefix: 'rdmn_mcp_docs', name: 'docs', scopes: [] },
  })
  const client = new Client({ name: 'redamon-api-reference', version: '1.0.0' }, { capabilities: {} })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  try {
    return (await client.request({ method: 'tools/list' }, ListToolsResultSchema)).tools
  } finally {
    await client.close()
    await server.close()
  }
}

export function toolScopes(tool: Tool): ToolScopes | null {
  const raw = tool._meta?.[SCOPES_META_KEY] as ToolScopes | undefined
  return raw && Array.isArray(raw.required) ? raw : null
}

type JsonSchema = {
  type?: string | string[]
  enum?: unknown[]
  const?: unknown
  anyOf?: JsonSchema[]
  description?: string
  pattern?: string
  minLength?: number
  maxLength?: number
  properties?: Record<string, JsonSchema>
  required?: string[]
}

/** A table cell: one line, and a literal pipe must not end the cell. */
function cell(text: string): string {
  return text.replace(/\r?\n+/g, ' ').replace(/\|/g, '\\|').trim()
}

function typeOf(schema: JsonSchema): string {
  if (schema.enum) return schema.enum.map(v => `\`${JSON.stringify(v)}\``).join(' or ')
  // A literal branch of a union. Rendered as the value, because `string` would
  // say nothing about the one string it actually accepts.
  if (schema.const !== undefined) return `\`${JSON.stringify(schema.const)}\``
  // A union ("a version id, or the word current") rendered as `any` understated
  // a constrained argument: the JSON Schema below carried the real contract
  // while the table told a reader anything would do.
  if (schema.anyOf?.length) return schema.anyOf.map(typeOf).join(' or ')
  const t = Array.isArray(schema.type) ? schema.type.join(' or ') : schema.type
  return t ? `\`${t}\`` : 'any'
}

function constraintsOf(schema: JsonSchema): string {
  const parts: string[] = []
  if (schema.minLength !== undefined && schema.maxLength !== undefined) {
    parts.push(`${schema.minLength} to ${schema.maxLength} characters.`)
  } else if (schema.maxLength !== undefined) {
    parts.push(`At most ${schema.maxLength} characters.`)
  } else if (schema.minLength !== undefined) {
    parts.push(`At least ${schema.minLength} characters.`)
  }
  if (schema.pattern) parts.push(`Must match \`${schema.pattern}\`.`)
  return parts.join(' ')
}

/**
 * A placeholder that still passes the argument's schema. `<projectId>` read
 * well but broke the projectId pattern, so a copied example was rejected by
 * input validation before it reached the tool.
 */
function placeholderFor(name: string, schema: JsonSchema): unknown {
  if (schema.enum?.length) return schema.enum[0]
  if (schema.type === 'object') return {}
  if (schema.type === 'number' || schema.type === 'integer') return 0
  if (schema.type === 'boolean') return false
  return `YOUR_${name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`
}

/**
 * Arguments a tool needs that its JSON Schema cannot express. query_graph
 * requires exactly one of `question` or `cypher`, a rule enforced in the tool
 * body, so its required-only example would be refused.
 */
const EXAMPLE_EXTRA_ARGS: Record<string, Record<string, unknown>> = {
  query_graph: { question: 'Which subdomains expose an admin panel?' },
  // `YOUR_COMMAND` would be run verbatim by a shell and fail as "command not
  // found". Nothing refuses it any more - there is no allowlist and no target
  // check on this path - so the reason for a real example is now pedagogical
  // rather than mechanical: the reader must see that this takes a SHELL command
  // and that choosing an in-scope target is their own responsibility.
  kali_exec: { command: 'curl -sI https://YOUR_TARGET/' },
  // Exactly one targeting mode is required, and the rule lives in the tool body
  // rather than the schema because "one of these three" is not expressible
  // there. A required-only example would be refused for naming none of them.
  // A real-looking domain: the tool refuses a name that is not a hostname or is
  // a public suffix, and the page should show a call that would be accepted.
  create_project: {
    targetDomain: 'example.com',
    engagementKind: 'third_party',
    settings: { roeGlobalMaxRps: 3 },
    authorization: {
      documentSha256: '0'.repeat(64),
      documentKind: 'hackerone_program',
      programHandle: 'YOUR_PROGRAM_HANDLE',
      issuedAt: '2026-01-01T00:00:00.000Z',
      summary: '428 in-scope, 28 excluded, 3 rps ceiling',
    },
    idempotencyKey: 'YOUR_PROGRAM_HANDLE-0000000000000000',
  },
  // Both refuse a call that names no finding, and `placeholderFor` has no array
  // branch, so a required-only example would name none.
  mute_findings: { findingIds: ['YOUR_FINDING_ID'] },
  // The hash must be 40 hex, which a YOUR_* placeholder is not.
  submit_finding_review: { evidenceHash: '0'.repeat(40) },
  unmute_findings: { findingIds: ['YOUR_FINDING_ID'] },
  // The digest must be 64 hex and issuedAt a real timestamp, neither of which a
  // YOUR_* placeholder satisfies.
  attach_engagement_authorization: {
    documentSha256: '0'.repeat(64),
    documentKind: 'hackerone_program',
    issuedAt: '2026-01-01T00:00:00.000Z',
  },
  // Exactly one of three optional sources is required, a rule the schema cannot
  // express. Copying a built-in also proves a built-in passes validation.
  create_recon_preset: { fromPresetId: 'stealth-recon' },
  // A call that changes nothing is refused before it reaches the backend.
  update_recon_preset: { settings: { katanaDepth: 3 } },
  // `changes` is required but an empty object changes nothing.
  update_project_scope: { changes: { gvmScanTargets: 'ips_only' } },
  // A step id is 32 hex, which a YOUR_* placeholder is not; submit needs exactly
  // one of answer or declined, neither of which the schema can require.
  loop_get_step: { stepId: 'f'.repeat(32) },
  loop_submit_step: { stepId: 'f'.repeat(32), answer: '{"thought": "...", "action": "complete"}' },
}

/** The example `arguments` for a tool. apiReference.test.ts calls every one of these. */
export function exampleArgs(tool: Tool): Record<string, unknown> {
  const schema = tool.inputSchema as JsonSchema
  const args: Record<string, unknown> = {}
  for (const name of schema.required ?? []) {
    args[name] = placeholderFor(name, schema.properties?.[name] ?? {})
  }
  return { ...args, ...EXAMPLE_EXTRA_ARGS[tool.name] }
}

function scopeLine(scopes: ToolScopes | null): string {
  if (!scopes) return 'not declared'
  const required = scopes.required.map(s => `\`${s}\``).join(' and ')
  const extra = (scopes.conditional ?? []).map(c => `\`${c.scope}\` when ${c.when}`)
  return extra.length ? `${required}, plus ${extra.join('; ')}` : required
}

function behaviourLine(tool: Tool): string {
  const a = tool.annotations ?? {}
  const parts: string[] = []
  if (a.readOnlyHint) {
    parts.push('read-only')
  } else {
    // The spec's destructiveHint: false means "only additive updates", so
    // anything that overwrites or aborts is destructive, not just deletion.
    parts.push(a.destructiveHint ? 'changes state, may overwrite or discard existing state' : 'changes state, additive only')
    if (a.idempotentHint) parts.push('idempotent')
  }
  if (a.openWorldHint) parts.push('reaches third-party targets')
  return parts.join(', ')
}

function renderArguments(tool: Tool): string {
  const schema = tool.inputSchema as JsonSchema
  const props = Object.entries(schema.properties ?? {})
  if (props.length === 0) return 'None.\n'
  const required = new Set(schema.required ?? [])
  const rows = props.map(([name, p]) => {
    const desc = [p.description ?? '', constraintsOf(p)].filter(Boolean).join(' ')
    return `| \`${name}\` | ${cell(typeOf(p))} | ${required.has(name) ? 'yes' : 'no'} | ${cell(desc) || ' '} |`
  })
  return ['| Name | Type | Required | Description |', '|---|---|---|---|', ...rows].join('\n') + '\n'
}

function renderExample(tool: Tool): string {
  const call = {
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: tool.name, arguments: exampleArgs(tool) },
  }
  return '```json\n' + JSON.stringify(call, null, 2) + '\n```\n'
}

function renderTool(tool: Tool): string {
  const out: string[] = []
  out.push(`### \`${tool.name}\``)
  out.push('')
  if (tool.title) out.push(`**${tool.title}**`, '')
  out.push(`**Permission:** ${scopeLine(toolScopes(tool))}  `)
  out.push(`**Behaviour:** ${behaviourLine(tool)}`)
  out.push('')
  // Descriptions are written for the model with single newlines between lines;
  // Markdown would fold those into one paragraph, so keep them as line breaks.
  out.push((tool.description ?? '').trim().replace(/([^\n])\n(?!\n)/g, '$1  \n'))
  out.push('')
  out.push('#### Arguments')
  out.push('')
  out.push(renderArguments(tool))
  out.push('#### Example call')
  out.push('')
  out.push(renderExample(tool))
  out.push('<details>')
  out.push('<summary>Input JSON Schema</summary>')
  out.push('')
  out.push('```json')
  out.push(JSON.stringify(tool.inputSchema, null, 2))
  out.push('```')
  out.push('')
  out.push('</details>')
  out.push('')
  return out.join('\n')
}

const TOKEN_EXAMPLE = `${MCP_TOKEN_PREFIX}...`

function renderAuthentication(): string {
  const presets = MCP_EXPIRY_PRESET_DAYS.map(d => (d === 365 ? '1 year' : `${d} days`))
  const clientConfig = {
    mcpServers: {
      redamon: {
        url: 'https://your-redamon-host/api/mcp-server',
        headers: { Authorization: `Bearer ${TOKEN_EXAMPLE}` },
      },
    },
  }
  return [
    '## Authentication',
    '',
    `Every request carries a personal access token in the \`Authorization\` header. That is the only way in: this endpoint ignores the browser session cookie and RedAmon's internal service keys, and it never reads a token from the URL. A token acts as the user who created it, inside that user's own projects (and, if it opts in, the projects shared with that user), limited to the permissions ticked on it.`,
    '',
    'A local install has the server on: `./redamon.sh` writes `MCP_SERVER_ENABLED=true` into `.env` (a single-host server deploy keeps it off until you enable it). While the switch is off, every request answers `404`, whatever the token, with an error message that says the server is disabled and names that variable. After changing it, recreate the webapp container with `docker compose up -d webapp`: a plain `docker compose restart` keeps the old environment.',
    '',
    '### 1. Create a token',
    '',
    '1. Open **Global Settings → MCP Server → New token**.',
    `2. Name it after the agent that will hold it, and pick an expiry: ${presets.join(', ')}, or none. The default is ${MCP_DEFAULT_EXPIRY_DAYS} days.`,
    `3. Tick the [permissions](#permissions) it needs. Only ${DEFAULT_MCP_SCOPES.map(s => `\`${s}\``).join(' and ')} ${DEFAULT_MCP_SCOPES.length === 1 ? 'is' : 'are'} ticked by default.`,
    '4. Confirm your password, then copy the token.',
    '',
    `The token is shown **once**. It starts with \`${MCP_TOKEN_PREFIX}\`, and RedAmon stores only a SHA-256 hash of it, so a lost token cannot be shown again, only replaced. Treat it like a password: anyone holding it can do everything its permissions allow.`,
    '',
    '### 2. Send it with every request',
    '',
    '```http',
    `Authorization: Bearer ${TOKEN_EXAMPLE}`,
    '```',
    '',
    'Most MCP clients take it as a header in their server config. This is the snippet the token screen gives you:',
    '',
    '```json',
    JSON.stringify(clientConfig, null, 2),
    '```',
    '',
    'For Claude Code:',
    '',
    '```bash',
    'claude mcp add --transport http redamon https://your-redamon-host/api/mcp-server \\',
    `  --header "Authorization: Bearer ${TOKEN_EXAMPLE}"`,
    '```',
    '',
    '### 3. Check it',
    '',
    '```bash',
    'curl -s https://your-redamon-host/api/mcp-server \\',
    "  -H 'Content-Type: application/json' \\",
    "  -H 'Accept: application/json, text/event-stream' \\",
    `  -H 'Authorization: Bearer ${TOKEN_EXAMPLE}' \\`,
    `  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'`,
    '```',
    '',
    'A working token returns the tool list below.',
    '',
    '### When it fails',
    '',
    'A missing, wrong, revoked or expired token all get the same answer, on purpose, so a caller cannot probe which tokens exist:',
    '',
    '```text',
    'HTTP/1.1 401 Unauthorized',
    '{"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized"},"id":null}',
    '```',
    '',
    'The token is checked again on every call, so revoking it or letting it expire takes effect on the very next request, not at the next reconnect. The token list in the tab shows which tokens are revoked or expired: an expired one can be extended with **Edit**, a revoked one has to be replaced.',
    '',
    `Being authenticated is not the same as being allowed. A valid token that lacks a permission gets a normal response whose tool result is an error, \`${new McpScopeError('<permission>' as McpScope).message}\`, and a project that does not exist or belongs to someone else is always \`Project not found\`.`,
    '',
    'A token never does more than the person who owns it. With per-person permissions switched on (`RBAC_PERMISSIONS_ENABLED`), each permission ticked on a token works only while its owner holds the RedAmon permissions it maps to: one the owner loses (a permission set changed, a permission denied, the account disabled) fails with that same error from the next call, and works again when the permission comes back. The token itself is not changed; the token screen marks such a permission as limited by your permissions.',
    '',
    'With project sharing on (`RBAC_SHARING_ENABLED` and the instance sharing policy), a token reaches the projects other people shared with its owner only when it was created or edited with **Include projects shared with me** (asking for your password, like any change that widens a token), optionally limited to the shared projects it names. A token without that option keeps reaching only its owner\'s own projects. On a shared project `list_projects` shows `myAccess`. On a Read share only the read tools answer: a tool that changes the project, starts work on it or asks a natural-language question (which spends the owner\'s model key) returns an error that says so, and raw Cypher and saved views need a share that includes raw data. On a Read + Write share the tools that change settings, findings and mutes answer too, each at the level the app asks: a scan start or queue needs Run scans, a scope change or the engagement authorizations Manage, and the owner\'s own tools (engagement authorization, triage runs, the Kali sandbox) stay refused, with an error naming what is missing. A revoked or expired share answers `Project not found` from the next call. An administrator\'s oversight never opens a project to a token.',
  ].join('\n')
}

function renderPermissions(tools: Tool[]): string {
  const rows = MCP_SCOPES.map((scope: McpScope) => {
    const unlocks: string[] = []
    for (const t of tools) {
      const s = toolScopes(t)
      if (!s) continue
      if (s.required.includes(scope)) unlocks.push(`\`${t.name}\``)
      for (const c of s.conditional ?? []) {
        if (c.scope === scope) unlocks.push(`\`${t.name}\` when ${c.when}`)
      }
    }
    const copy = MCP_SCOPE_COPY[scope]
    return `| \`${scope}\` | ${cell(copy.label)} | ${cell(copy.blurb)} | ${cell(unlocks.join(', ')) || ' '} |`
  })
  return ['| Permission | Checkbox in the UI | What it allows | Tools |', '|---|---|---|---|', ...rows].join('\n')
}

export function renderApiReference(tools: Tool[]): string {
  const deniedExample = new McpScopeError('<permission>' as McpScope).message
  const glance = tools.map(t =>
    `| [\`${t.name}\`](#${t.name}) | ${cell(t.title ?? '')} | ${cell(scopeLine(toolScopes(t)))} | ${cell(behaviourLine(t))} |`
  )

  return [
    CANONICAL_BANNER +
    '<!-- GENERATED by `npm run docs:mcp` in webapp/ from the live tools/list. Do not edit by hand. -->',
    '',
    '# MCP API Reference',
    '',
    `Every tool the RedAmon [MCP Server](MCP-Server) advertises: what it does, the arguments it takes, the permission its token needs and how it behaves. This page covers the tools only. Turning the server on, minting a token, connecting a client and the security model are in [MCP Server](MCP-Server).`,
    '',
    `> **Generated, not written.** This page is produced from the tool list the server itself returns, so it cannot describe a tool differently from how the server serves it. Do not edit it by hand: the next run overwrites it, and a unit test fails while it is out of date. See [Regenerating the API reference](MCP-Server#regenerating-the-api-reference).`,
    '',
    `> **It describes a build, not a deployment.** It is rendered with no tool withdrawn, so a deployment using \`MCP_DISABLED_TOOLS\`, or with \`MCP_KALI_EXEC_ENABLED=false\` (which withdraws \`kali_toolbox\`, \`kali_exec\`, \`kali_output\` and \`kali_cancel\`), serves FEWER tools than are listed here. So does a deployment with \`AGENT_IN_THE_LOOP_ENABLED\` off, the default, which withdraws \`loop_wait_step\`, \`loop_get_step\` and \`loop_submit_step\`. Ask the server itself with \`tools/list\` for the authoritative set on one host.`,
    '',
    '---',
    '',
    renderAuthentication(),
    '',
    '## Calling a tool',
    '',
    `The server speaks JSON-RPC 2.0 over Streamable HTTP in stateless mode, at \`POST /api/mcp-server\`. Besides the \`Authorization\` header, every request needs \`Content-Type: application/json\` and \`Accept: application/json, text/event-stream\`. An MCP client handles all of this for you; the example calls below show the raw \`tools/call\` body for anyone calling it by hand, and each one is exercised against the server by the test that guards this page.`,
    '',
    `Every tool below is listed by \`tools/list\` whatever permissions the token holds, unless the deployment has withdrawn it with \`MCP_DISABLED_TOOLS\`, switched the sandbox off with \`MCP_KALI_EXEC_ENABLED=false\` or left Agent in the Loop off - a withdrawn tool is absent from the list rather than present and refusing. A call without the needed permission fails with \`${deniedExample}\`. Each tool also advertises its permissions in \`tools/list\` under \`_meta["${SCOPES_META_KEY}"]\`, and its behaviour in the standard MCP \`annotations\` (\`readOnlyHint\`, \`destructiveHint\`, \`idempotentHint\`, \`openWorldHint\`), which clients use to decide when to ask you before running it.`,
    '',
    '## Tools at a glance',
    '',
    '| Tool | Title | Permission | Behaviour |',
    '|---|---|---|---|',
    ...glance,
    '',
    '## Permissions',
    '',
    renderPermissions(tools),
    '',
    '## Tools',
    '',
    ...tools.map(renderTool),
  ].join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'
}
