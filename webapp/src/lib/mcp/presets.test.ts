/**
 * The Quick add presets: a preset that needs no key saves as it is, and the
 * tools a preset declares are the ones its server really takes, in the shape
 * the agent's planner reads.
 */
import { describe, test, expect } from 'vitest'
import { MCP_PRESETS } from './presets'
import { mcpServerSchema } from './schema'

/** The planner's own parse of args_format (agentic/orchestrator_helpers/lats.py
 * `_tool_arg_keys`): every quoted key, the first one required in a probe. */
const argKeys = (argsFormat: string) =>
  [...argsFormat.matchAll(/"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:/g)].map(m => m[1])

describe('MCP presets', () => {
  test('every preset that needs no key passes the save schema unedited', () => {
    const free = MCP_PRESETS.filter(p => !p.authRequired)
    expect(free.length).toBeGreaterThan(0)
    for (const preset of free) {
      const parsed = mcpServerSchema.safeParse(preset.template)
      expect(parsed.success ? [] : parsed.error.issues, preset.key).toEqual([])
    }
  })

  test('SecurityContext declares its two read tools, with exactly the arguments the server takes', () => {
    const preset = MCP_PRESETS.find(p => p.key === 'securitycontext')!
    expect(preset.template.url).toBe('https://mcp.securitycontext.com')
    expect(preset.template.auth).toBeUndefined()

    // inputSchema properties from the server's tools/list (securitycontext 2.0.0,
    // 2026-11-25). `type` comes first: the server's default type (repository)
    // reads a product id as a repository.
    const serverArgs: Record<string, string[]> = {
      get_security_context: ['type', 'id', 'section', 'include', 'fields', 'filters', 'format'],
      search_security_context: ['type', 'filters', 'sort', 'limit', 'cursor', 'fields', 'facets', 'format'],
    }
    // create_security_context stays out: it adds the repository it scans to a
    // public index, so a client's repository would be listed for anyone.
    expect(preset.template.tools.map(t => t.name)).toEqual(Object.keys(serverArgs))
    for (const tool of preset.template.tools) {
      expect(argKeys(tool.args_format), tool.name).toEqual(serverArgs[tool.name])
    }
  })
})
