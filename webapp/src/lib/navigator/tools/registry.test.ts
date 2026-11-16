/**
 * The AI Navigator tool catalogue (plan §7.8, §7.9) checked against the code, not by reading: every
 * MCP-backed tool, called through a Navigator context holding exactly its declared scopes, passes
 * the function's own scope check (and reaches the project check); with any one scope removed it is
 * refused. When an MCP function changes its requireScope, this fails and the row is fixed with it.
 * Also: no write tool, the schema-driven argument validator, and `question` never accepted.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import path from 'node:path'

class ProjectCheckReached extends Error {}

vi.mock('@/lib/prisma', () => ({ default: {}, prisma: {} }))
vi.mock('@/lib/mcpAuth', async (importOriginal) => {
  const real = await importOriginal<typeof import('@/lib/mcpAuth')>()
  return {
    ...real,
    mcpProjectAccess: async () => { throw new ProjectCheckReached() },
    assertMcpProjectAccess: async () => { throw new ProjectCheckReached() },
  }
})

import { McpScopeError } from '@/lib/mcpAuth'
import { PERMISSIONS } from '@/lib/authz/permissions'
import { navigatorTools, navigatorTool } from './registry'
import { navigatorMcpContext } from './sessionContext'
import { validateArgs } from './validate'

const SAMPLE_ARGS: Record<string, Record<string, unknown>> = {
  run_cypher: { cypher: 'MATCH (n:IP) RETURN n LIMIT 1' },
  scan_status: { scanner: 'gvm' },
  compare_scan_versions: { from: 'v1', to: 'v2' },
}

async function call(name: string, scopes: readonly string[]): Promise<unknown> {
  const tool = navigatorTool(name)!
  const mcp = navigatorMcpContext({ personId: 'p1', projectId: 'P1', actorId: null, scopes: scopes as never })
  try {
    await tool.handler({ mcp, projectId: 'P1', tenantId: 'owner' }, (SAMPLE_ARGS[name] ?? {}) as never)
    return 'ran'
  } catch (err) {
    return err
  }
}

const MCP_BACKED = navigatorTools().filter((t) => t.mcpScopes.length > 0)

describe('declared scopes equal the functions\' requireScope', () => {
  test.each(MCP_BACKED.map((t) => [t.name]))('%s passes with exactly its scopes', async (name) => {
    const tool = navigatorTool(name)!
    const out = await call(name, tool.mcpScopes)
    // describe_recon_settings is static (no project): it runs to completion.
    if (name === 'describe_recon_settings') expect(out).toBe('ran')
    else expect(out).toBeInstanceOf(ProjectCheckReached)
  })

  test.each(MCP_BACKED.flatMap((t) => t.mcpScopes.map((s) => [t.name, s])))('%s without %s is refused', async (name, scope) => {
    const tool = navigatorTool(name)!
    const out = await call(name, tool.mcpScopes.filter((s) => s !== scope))
    expect(out).toBeInstanceOf(McpScopeError)
  })
})

describe('the catalogue', () => {
  test('read-only: every permission a tool needs reaches at most Read (R or R*)', () => {
    for (const tool of navigatorTools()) {
      for (const p of tool.permissions) expect(['R', 'R*'], `${tool.name} ${p}`).toContain(PERMISSIONS[p].level)
      expect(['R', 'R*']).toContain(tool.level)
    }
  })

  test('every tool schema forbids unknown arguments', () => {
    for (const tool of navigatorTools()) expect(tool.parameters.additionalProperties, tool.name).toBe(false)
  })

  test('the workspace tools need Raw data & files', () => {
    for (const name of ['workspace_tree', 'workspace_list', 'workspace_read']) {
      expect(navigatorTool(name)!.level).toBe('R*')
      expect(navigatorTool(name)!.permissions).toEqual(['workspace:read'])
    }
  })

  test('no tool spends the owner\'s model: run_cypher refuses `question`', () => {
    const tool = navigatorTool('run_cypher')!
    expect(validateArgs(tool.parameters, { question: 'which hosts?' })).toMatchObject({ ok: false })
    expect(validateArgs(tool.parameters, { cypher: 'MATCH (n:IP) RETURN n', question: 'x' })).toMatchObject({ ok: false })
  })

  test('compare_scan_versions takes two stored versions only', () => {
    const tool = navigatorTool('compare_scan_versions')!
    expect(validateArgs(tool.parameters, { from: 'v1' })).toMatchObject({ ok: false })
    const both = validateArgs(tool.parameters, { from: 'v1', to: 'current' })
    expect(both.ok && tool.check!(both.args)).toMatch(/stored versions/)
    const ok = validateArgs(tool.parameters, { from: 'v1', to: 'v2' })
    expect(ok.ok && tool.check!(ok.args)).toBeNull()
  })

  test.each([' current', 'current ', '\tcurrent', 'CURRENT', '   '])(
    'compare_scan_versions: %j is the live graph to the MCP function (it trims), so it is refused', (side) => {
      const tool = navigatorTool('compare_scan_versions')!
      for (const args of [{ from: 'v1', to: side }, { from: side, to: 'v2' }]) {
        const parsed = validateArgs(tool.parameters, args)
        expect(parsed.ok && tool.check!(parsed.args)).toMatch(/stored versions/)
      }
    })

  test('no Navigator module takes a graph snapshot slot (version activation waits on them)', () => {
    const roots = ['src/lib/navigator', 'src/app/api/navigator', 'src/app/api/internal/navigator']
    const files = roots.flatMap((r) => readdirSync(r, { recursive: true, encoding: 'utf8' })
      .filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f)).map((f) => path.join(r, f)))
    expect(files.length).toBeGreaterThan(10)
    for (const f of files) expect(readFileSync(f, 'utf8'), f).not.toMatch(/tryWithSnapshotSlot|captureGraphSnapshot|withSnapshotSlot/)
  })
})

describe('validateArgs', () => {
  const schema = navigatorTool('list_findings')!.parameters
  test.each([
    [{ limit: 5 }, true],
    [{ limit: 500 }, false],
    [{ limit: 1.5 }, false],
    [{ severity: 'critical' }, true],
    [{ severity: 'catastrophic' }, false],
    [{ unknown: 1 }, false],
    [[1], false],
    ['x', false],
    [undefined, true],
  ])('%j → %s', (args, ok) => {
    expect(validateArgs(schema, args).ok).toBe(ok)
  })
})
