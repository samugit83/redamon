/**
 * The scope copy and its presentation grouping.
 *
 * The control here is fail-closed: every scope must appear in exactly one group.
 * A scope added next month is ungrouped, this goes red, and nobody can ship a
 * checkbox that renders nowhere.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'fs'
import { wikiCheckoutPresent } from '@/lib/wikiCheckout.testUtils'
import path from 'path'
import { fileURLToPath } from 'url'
import { describe, test, expect, beforeAll, vi } from 'vitest'

// Only tools/list is exercised here, so nothing reaches a model; these keep the
// server importable.
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import type { Tool } from '@modelcontextprotocol/sdk/types.js'

import { MCP_SCOPES, type McpScope } from '@/lib/mcpAuth'
import { listAdvertisedTools, toolScopes } from './apiReference'
import { MCP_SCOPE_COPY, SCOPE_GROUPS, type ScopeAccess } from './scopeCopy'

describe('the copy', () => {
  test('every scope has a label and a blurb', () => {
    for (const s of MCP_SCOPES) {
      expect(MCP_SCOPE_COPY[s], `no copy for ${s}`).toBeDefined()
      expect(MCP_SCOPE_COPY[s].label.length, `${s} has no label`).toBeGreaterThan(0)
      expect(MCP_SCOPE_COPY[s].blurb.length, `${s} has no blurb`).toBeGreaterThan(20)
    }
  })

  test('a blurb stays table-safe, because it becomes one markdown cell', () => {
    // The generated API reference prints each blurb into a single table cell.
    // A newline or a raw pipe would break the table.
    for (const s of MCP_SCOPES) {
      expect(MCP_SCOPE_COPY[s].blurb, `${s} blurb has a newline`).not.toMatch(/\r?\n/)
      expect(MCP_SCOPE_COPY[s].blurb, `${s} blurb has a raw pipe`).not.toContain('|')
    }
  })

  test('the mute copy names what bounds it: a reason, the per-call cap, and undo', () => {
    const copy = MCP_SCOPE_COPY['triage:mute']
    expect(copy.access).toBe('write')
    expect(copy.blurb).toMatch(/up to 5,000 findings/)
    // The operator ticking this must be told nothing caps the total.
    expect(copy.blurb).toMatch(/no daily limit/)
    expect(copy.blurb).toMatch(/can be undone/)
    expect(copy.blurb).toMatch(/needs a reason/)
    expect(copy.blurb).toMatch(/never hides a confirmed finding/)
    expect(copy.detail).toMatch(/MCP_RATE_MUTE_PER_MIN/)
    expect(copy.detail).not.toMatch(/MCP_MUTE_DAILY_BUDGET/)
    expect(SCOPE_GROUPS.find(g => g.id === 'write')!.scopes).toContain('triage:mute')
  })

  test('detail is UI-only, so it may be as long as it needs to be', () => {
    // Nothing asserts its length; this asserts it EXISTS where the UI needs it.
    expect(MCP_SCOPE_COPY['kali:exec'].detail).toBeDefined()
    expect(MCP_SCOPE_COPY['kali:exec'].detail!.length).toBeGreaterThan(300)
  })

  test('the exec copy states what it really grants: a shell, unscoped', () => {
    // This used to promise "a fixed allowlist of read-only tools" and "not a
    // shell". kali_exec is now at parity with the in-app agent - bash -c, full
    // toolset, no allowlist, no per-command scope check - so that copy was
    // understating the permission an operator ticks, which is the dangerous
    // direction for a consent screen.
    const c = MCP_SCOPE_COPY['kali:exec']
    expect(c.blurb).toContain('SHELL')
    expect(c.blurb).toContain('no allowlist')
    expect(c.detail!).toContain('no human clicking a confirmation')
    expect(c.detail!).toContain('NOT checked against this')
    expect(c.detail!).toContain('not sufficient on its own')
    expect(c.detail!).not.toContain('read-only tools')
    expect(c.learnMore).toHaveLength(2)
  })

  test('every learnMore link points at the wiki over https', () => {
    for (const s of MCP_SCOPES) {
      for (const link of MCP_SCOPE_COPY[s].learnMore ?? []) {
        expect(link.text.length, `${s} has an unlabelled link`).toBeGreaterThan(0)
        expect(link.href, `${s} link is not an https wiki URL`).toMatch(/^https:\/\/github\.com\/.+\/wiki\//)
      }
    }
  })
})

describe('the grouping', () => {
  test('every scope appears in EXACTLY one group', () => {
    const seen = new Map<string, number>()
    for (const g of SCOPE_GROUPS) {
      for (const s of g.scopes) seen.set(s, (seen.get(s) ?? 0) + 1)
    }
    for (const s of MCP_SCOPES) {
      expect(
        seen.get(s) ?? 0,
        `${s} appears in ${seen.get(s) ?? 0} groups. Add it to exactly one SCOPE_GROUPS entry.`
      ).toBe(1)
    }
  })

  test('no group names a scope that does not exist', () => {
    const known = new Set<string>(MCP_SCOPES)
    for (const g of SCOPE_GROUPS) {
      for (const s of g.scopes) {
        expect(known.has(s), `group ${g.id} names unknown scope ${s}`).toBe(true)
      }
    }
  })

  test('every group has a label and a hint', () => {
    for (const g of SCOPE_GROUPS) {
      expect(g.label.length, `${g.id} has no label`).toBeGreaterThan(0)
      expect(g.hint.length, `${g.id} has no hint`).toBeGreaterThan(0)
      expect(g.scopes.length, `${g.id} is empty`).toBeGreaterThan(0)
    }
  })

  test('the read group changes nothing, so every scope in it badges read', () => {
    // Its header promises "Nothing here changes any state". A write scope filed
    // under it would make that header a lie for every operator who reads the
    // group instead of the row.
    const read = SCOPE_GROUPS.find(g => g.id === 'read')!
    expect(read.tone).toBe('neutral')
    for (const s of read.scopes) {
      expect(MCP_SCOPE_COPY[s].access, `${s} can write, in the group that says nothing does`).toBe('read')
    }
  })

  test('agent:loop is a write scope in its own group', () => {
    // Every loop tool claims a lease or resolves a step, so none is read-only.
    expect(MCP_SCOPE_COPY['agent:loop'].access).toBe('write')
    const group = SCOPE_GROUPS.find(g => g.scopes.includes('agent:loop'))!
    expect(group.scopes).toEqual(['agent:loop'])
    expect(group.tone).toBe('action')
  })

  test('kali:exec is set apart in its own tier, not treated as a ninth checkbox', () => {
    const exec = SCOPE_GROUPS.find(g => g.tone === 'exec')!
    expect(exec.scopes).toEqual(['kali:exec'])
    // And it is last, so it reads as a different kind of thing.
    expect(SCOPE_GROUPS[SCOPE_GROUPS.length - 1].id).toBe(exec.id)
  })

  test('MCP_SCOPES itself is NOT reordered to match the groups', () => {
    // That array is the enforcement list and drives the generated reference's
    // permission table; the grouping is presentation beside it.
    const flattened = SCOPE_GROUPS.flatMap(g => g.scopes)
    expect(flattened).not.toEqual([...MCP_SCOPES])
    expect([...flattened].sort()).toEqual([...MCP_SCOPES].sort() as McpScope[])
  })
})

/**
 * The read / write badge on each checkbox.
 *
 * The badge is the only place the consent screen answers "does ticking this let
 * an agent CHANGE something" without the operator reading a paragraph, so it is
 * derived from the live `tools/list` rather than trusted as editorial. A scope
 * that gains a state-changing tool - or a tool that loses `readOnlyHint` - goes
 * red here instead of quietly under-stating the permission.
 */
describe('the access badge matches what the tools do', () => {
  let tools: Tool[]

  beforeAll(async () => {
    // The build's full surface. Unset reads as off and withdraws the sandbox
    // tools, while docker-compose.yml defaults the switch on.
    vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
    // Agent in the Loop is off by default; the loop tools are part of the build.
    vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
    tools = await listAdvertisedTools()
  })

  /** What the tools gated by this scope actually are, required or conditional. */
  const observed = (scope: McpScope): ScopeAccess | null => {
    let reads = false
    let writes = false
    for (const t of tools) {
      const s = toolScopes(t)
      if (!s) continue
      const gated = s.required.includes(scope) || (s.conditional ?? []).some(c => c.scope === scope)
      if (!gated) continue
      if (t.annotations?.readOnlyHint) reads = true
      else writes = true
    }
    if (!reads && !writes) return null
    if (reads && writes) return 'read-write'
    return reads ? 'read' : 'write'
  }

  test('every scope badges what its own tools do', () => {
    for (const scope of MCP_SCOPES) {
      const real = observed(scope)
      expect(real, `${scope} unlocks no tool at all`).not.toBeNull()
      expect(
        MCP_SCOPE_COPY[scope].access,
        `${scope} badges "${MCP_SCOPE_COPY[scope].access}" but its tools are "${real}"`
      ).toBe(real)
    }
  })

  test('the shell scope is the only one that both reads and writes', () => {
    // kali_output and kali_toolbox read; kali_exec and kali_cancel do not. Every
    // other scope is one or the other, which is why the badge can stay one chip.
    const both = MCP_SCOPES.filter(s => MCP_SCOPE_COPY[s].access === 'read-write')
    expect(both).toEqual(['kali:exec'])
  })
})

/**
 * Every `learnMore` link points into the wiki by heading anchor, and NOTHING
 * connects the two. Renaming a heading in MCP-Server.md silently 404s a link in
 * the consent screen - the one place an operator goes to understand what they
 * are granting.
 *
 * Found for real: `kali_toolbox`'s section was renamed from "what is installed,
 * not what is permitted" to "what the sandbox carries" when the allowlist was
 * removed, and the link kept pointing at the old slug. Nothing failed.
 */
describe('wiki anchors resolve', () => {
  const WIKI_DIR =
    process.env.MCP_DOCS_WIKI_DIR ||
    fileURLToPath(new URL('../../../../redamon.wiki/', import.meta.url))

  /** A real wiki checkout; an empty one fails unless allowed (wikiCheckout.testUtils.ts). */
  const hasWiki = () => wikiCheckoutPresent(WIKI_DIR)

  /** GitHub's heading -> anchor rule: lowercase, drop punctuation, spaces to -. */
  const slug = (heading: string) =>
    heading
      .replace(/^#+\s*/, '')
      .trim()
      .toLowerCase()
      .replace(/`/g, '')
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-')

  const anchorsIn = (page: string) =>
    new Set(
      readFileSync(path.join(WIKI_DIR, page), 'utf8')
        .split('\n')
        .filter(l => l.startsWith('#'))
        .map(slug)
    )

  test.skipIf(!hasWiki())('every scope learnMore anchor exists in its wiki page', () => {
    const byPage = new Map<string, Set<string>>()
    const broken: string[] = []

    for (const scope of MCP_SCOPES) {
      for (const link of MCP_SCOPE_COPY[scope].learnMore ?? []) {
        const m = /\/wiki\/([A-Za-z0-9._-]+)#([^"'`\s]+)$/.exec(link.href)
        if (!m) continue
        const [, page, anchor] = m
        const file = `${page}.md`
        if (!existsSync(path.join(WIKI_DIR, file))) {
          broken.push(`${scope}: ${file} does not exist`)
          continue
        }
        if (!byPage.has(file)) byPage.set(file, anchorsIn(file))
        if (!byPage.get(file)!.has(anchor)) {
          broken.push(`${scope}: ${file}#${anchor} matches no heading`)
        }
      }
    }
    expect(broken, 'a consent-screen link points at a heading that no longer exists').toEqual([])
  })
})
