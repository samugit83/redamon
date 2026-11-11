/**
 * Shared MCP server schema (zod) - used by both client form validation and
 * server-side API route validation.
 *
 * Mirrors the agentic/mcp_registry.py pydantic schema. Single source of truth
 * for both ends of the wire.
 */

import { z } from 'zod'

export const PHASES = ['informational', 'exploitation', 'post_exploitation'] as const
export type Phase = (typeof PHASES)[number]

export const TRANSPORTS = ['sse', 'streamable_http', 'stdio'] as const
export type Transport = (typeof TRANSPORTS)[number]

/**
 * Tool names reserved by built-in / system tools - user MCP tools must not use these.
 *
 * Must equal what the agent rejects at manifest load: `_builtin_tool_names()` in
 * agentic/mcp_registry.py (the TOOL_REGISTRY keys, `tradecraft_lookup`, and every
 * tool a system MCP server exposes, SYSTEM_MCP_TOOL_NAMES).
 * A name missing here is accepted by the form and then refused by the agent.
 * agentic/tests/test_reserved_tool_names_parity.py compares the two sets.
 */
export const BUILTIN_RESERVED_TOOL_NAMES: ReadonlySet<string> = new Set([
  // graph_summary and graph_schema ship on BOTH the agent and the inbound MCP
  // server from one definition; omitting them here let a user-registered plugin
  // shadow a built-in graph tool with its own.
  'query_graph', 'graph_summary', 'graph_schema',
  'web_search', 'cve_intel', 'shodan', 'google_dork',
  'execute_code', 'tradecraft_lookup', 'proxy_brain',
  'execute_osv_scanner', 'execute_guarddog',
  // System MCP-backed tools (the 5 baseline kali-sandbox servers)
  'execute_curl', 'execute_naabu', 'execute_httpx', 'execute_subfinder',
  'execute_amass', 'execute_arjun', 'execute_ffuf', 'execute_gau',
  'execute_jsluice', 'execute_katana', 'execute_wpscan',
  'execute_nmap', 'execute_nuclei', 'kali_shell', 'execute_playwright',
  'execute_hydra', 'metasploit_console', 'msf_restart', 'execute_masscan',
  // Workspace filesystem tools
  'fs_read', 'fs_read_many', 'fs_stat', 'fs_write', 'fs_edit', 'fs_multi_edit',
  'fs_undo_edit', 'fs_delete', 'fs_move', 'fs_copy', 'fs_mkdir', 'fs_chmod',
  'fs_symlink_create', 'fs_grep', 'fs_glob', 'fs_find', 'fs_list', 'fs_tree',
  'fs_symbols', 'fs_symlink_read', 'fs_hash', 'fs_diff', 'fs_extract', 'fs_archive',
  // Background-job tools
  'job_spawn', 'job_status', 'job_wait', 'job_cancel', 'job_list',
])

/** Server IDs reserved by system MCP servers - user IDs must not collide. */
export const SYSTEM_SERVER_IDS: ReadonlySet<string> = new Set([
  'network_recon', 'nmap', 'nuclei', 'metasploit', 'playwright',
])

const ID_RE = /^[a-zA-Z0-9_][a-zA-Z0-9_-]*$/

export const toolSpecSchema = z.object({
  name: z.string().min(1, 'tool name is required').regex(
    /^[a-zA-Z_][a-zA-Z0-9_]*$/,
    'tool name must be a valid identifier (letters, digits, underscore; no leading digit)',
  ),
  purpose: z.string().min(1, 'purpose is required'),
  when_to_use: z.string().min(1, 'when_to_use is required'),
  args_format: z.string().min(1, 'args_format is required'),
  description: z.string().min(1, 'description is required'),
  default_phases: z.array(z.enum(PHASES)).optional(),
})

export const MASK_PREFIX = '••••'

/**
 * A stdio server runs its `command` as root inside the agent, which holds every
 * tenant's data and the master secrets (NF-14, OQ-48): only an administrator's
 * are saved, tested or loaded. A member's saved ones stay in their settings.
 */
export const STDIO_ADMIN_ONLY_CODE = 'stdio_admin_only'
export const STDIO_ADMIN_ONLY_MESSAGE =
  "stdio servers run inside the agent with every user's data; ask an administrator"

/**
 * `auth.token_env_var` names one of the agent's own environment variables, so a
 * server naming INTERNAL_API_KEY sent the master key to its own URL (OQ-R1): no
 * user's server may carry it. The agent ignores it on a saved one too.
 */
export const TOKEN_ENV_VAR_CODE = 'token_env_var_refused'
export const TOKEN_ENV_VAR_MESSAGE =
  "auth.token_env_var names one of the agent's own environment variables and is not accepted: paste the token instead"

export function isStdioServer(srv: unknown): boolean {
  return !!srv && typeof srv === 'object' && (srv as { transport?: unknown }).transport === 'stdio'
}

export function namesTokenEnvVar(srv: unknown): boolean {
  const auth = srv && typeof srv === 'object' ? (srv as { auth?: unknown }).auth : undefined
  return !!auth && typeof auth === 'object' && !!(auth as { token_env_var?: unknown }).token_env_var
}

export const bearerAuthSchema = z.object({
  type: z.literal('bearer'),
  token: z.string().optional(),
  token_env_var: z.string().optional(),
})
  .refine(
    v => !!(v.token && v.token.length > 0) || !!(v.token_env_var && v.token_env_var.length > 0),
    { message: "auth requires a non-empty 'token' (bearer token)" },
  )

export const mcpServerSchema = z.object({
  id: z.string()
    .min(1, 'id is required')
    .regex(ID_RE, 'id must start with a letter, digit, or underscore and contain only letters, digits, underscores, and hyphens')
    .refine(v => !SYSTEM_SERVER_IDS.has(v), {
      message: 'this id is reserved for a system MCP server',
    }),
  name: z.string().min(1, 'name is required'),
  description: z.string().default(''),
  enabled: z.boolean().default(true),
  transport: z.enum(TRANSPORTS),
  default_phases: z.array(z.enum(PHASES)).default([...PHASES]),
  tags: z.array(z.string()).default([]),

  // HTTP-only
  url: z.string().url('must be a valid URL').optional().or(z.literal('')),
  headers: z.record(z.string(), z.string()).default({}),
  auth: bearerAuthSchema.optional(),
  connect_timeout: z.number().int().positive().default(60),
  read_timeout: z.number().int().positive().default(600),

  // stdio-only
  command: z.string().optional().or(z.literal('')),
  args: z.array(z.string()).default([]),
  env: z.record(z.string(), z.string()).default({}),
  cwd: z.string().optional().or(z.literal('')),
  encoding: z.string().default('utf-8'),

  tools: z.array(toolSpecSchema).default([]),
})
  .superRefine((srv, ctx) => {
    if (srv.transport === 'sse' || srv.transport === 'streamable_http') {
      if (!srv.url) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['url'], message: 'url is required for HTTP transports' })
      }
    } else if (srv.transport === 'stdio') {
      if (!srv.command) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['command'], message: 'command is required for stdio transport' })
      }
    }

    // Tool name uniqueness within server
    const seen = new Set<string>()
    srv.tools.forEach((t, i) => {
      if (seen.has(t.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['tools', i, 'name'],
          message: `duplicate tool name '${t.name}' within this server`,
        })
      }
      seen.add(t.name)

      if (BUILTIN_RESERVED_TOOL_NAMES.has(t.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['tools', i, 'name'],
          message: `tool name '${t.name}' collides with a built-in tool`,
        })
      }
    })
  })

export type MCPServer = z.infer<typeof mcpServerSchema>
export type ToolSpec = z.infer<typeof toolSpecSchema>

/** Validate the full mcpServers array, including cross-server uniqueness checks. */
export function validateMcpServers(servers: unknown): {
  valid: MCPServer[]
  errors: { serverId: string; path: string[]; message: string }[]
} {
  if (!Array.isArray(servers)) {
    return { valid: [], errors: [{ serverId: '<root>', path: [], message: 'mcpServers must be an array' }] }
  }

  const errors: { serverId: string; path: string[]; message: string }[] = []
  const valid: MCPServer[] = []
  const seenIds = new Set<string>()
  const seenToolNames = new Set<string>()

  servers.forEach((entry, idx) => {
    const sid = (entry && typeof entry === 'object' && 'id' in entry && typeof (entry as { id: unknown }).id === 'string')
      ? (entry as { id: string }).id
      : `<index ${idx}>`

    const parsed = mcpServerSchema.safeParse(entry)
    if (!parsed.success) {
      for (const issue of parsed.error.issues) {
        errors.push({ serverId: sid, path: issue.path.map(String), message: issue.message })
      }
      return
    }

    const srv = parsed.data
    if (seenIds.has(srv.id)) {
      errors.push({ serverId: srv.id, path: ['id'], message: `duplicate server id '${srv.id}'` })
      return
    }

    let collision = false
    for (const t of srv.tools) {
      if (seenToolNames.has(t.name)) {
        errors.push({
          serverId: srv.id, path: ['tools', t.name],
          message: `tool name '${t.name}' is already declared by another server`,
        })
        collision = true
      }
    }
    if (collision) return

    seenIds.add(srv.id)
    for (const t of srv.tools) seenToolNames.add(t.name)
    valid.push(srv)
  })

  return { valid, errors }
}
