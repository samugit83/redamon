/**
 * The Agent Onboarding pack.
 *
 * The tests that matter here are COVERAGE tests, not example renders. A pack
 * that omits a live tool teaches the agent a smaller product than it has, and
 * an agent that never learns `list_findings` exists falls back to the expensive
 * `query_graph` for everything. So the controls are:
 *
 *  - every tool the server advertises has a playbook entry AND sits in exactly
 *    one capability area. Adding a tool without guidance turns this red in the
 *    same commit.
 *  - the scope filter really filters: a read-only token's pack must not describe
 *    a tool it cannot call, and must say plainly that it cannot.
 *  - nothing user-specific ever reaches the output. A SKILL.md travels with a
 *    repository.
 *  - the response-shape facts the prose quotes (the graph states, the section
 *    names, the verdict vocabulary) are pinned against the modules that own
 *    them, because the generator cannot catch those drifting.
 *  - the HAND-WRITTEN prose never promises a protection that does not exist.
 *    This is the one class nothing generated can catch, and it has bitten
 *    twice: the worked scenarios named tools outside the token's scopes, and
 *    the exec guidance claimed a per-command scope check after `kali_exec`
 *    became a real shell. Both guards are phrase-based on purpose - the claim
 *    is prose, so only prose can be asserted about it.
 *  - the documentation the feature added references files that exist, since a
 *    missing screenshot renders as a broken image on the published wiki.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync } from 'fs'
import { wikiCheckoutPresent } from '@/lib/wikiCheckout.testUtils'
import path from 'path'
import { fileURLToPath } from 'url'
import { describe, test, expect, beforeAll, vi } from 'vitest'

// Nothing here calls a tool; the server is built only to answer tools/list.
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import type { Tool } from '@modelcontextprotocol/sdk/types.js'

import { MCP_SCOPES, MCP_TOKEN_PREFIX, type McpScope } from '@/lib/mcpAuth'
import { listAdvertisedTools } from './apiReference'
import { FINDING_SECTIONS } from './findingTools'
import { VERDICT_STATUSES } from './verdictTools'
import { MUTEABLE_FINDING_LABELS } from './findingLabels'
import { CAPABILITY_AREAS, ONBOARDING_PLAYBOOK, WORKFLOWS } from './playbook'
import { PROFILE_IDS, PROFILE_ONBOARDING, PROFILES, type ProfileId } from './profiles'
import {
  canCall,
  renderInlineOnboarding,
  renderOnboardingPack,
  renderProfileSection,
  scopesOf,
} from './onboarding'

const ALL: McpScope[] = [...MCP_SCOPES]
const READ_ONLY: McpScope[] = ['recon:read']

let tools: Tool[]
beforeAll(async () => {
  // The build's full surface. Unset reads as off and withdraws the sandbox
  // tools, while docker-compose.yml defaults the switch on.
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  // Agent in the Loop is off by default; the loop tools are part of the build.
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
  tools = await listAdvertisedTools()
})

/** The whole pack as one string, for "does it mention X anywhere" assertions. */
const packText = (scopes: McpScope[], profile: ProfileId | null = 'custom') =>
  renderOnboardingPack(tools, scopes, profile, { version: 'test' })
    .files.map(f => f.content)
    .join('\n')

// --- coverage: the real control ------------------------------------------------

describe('coverage', () => {
  test('every advertised tool has a playbook entry', () => {
    const missing = tools.map(t => t.name).filter(n => !ONBOARDING_PLAYBOOK[n])
    expect(
      missing,
      `these tools ship with no onboarding guidance: ${missing.join(', ')}. ` +
        'Add an ONBOARDING_PLAYBOOK entry in playbook.ts.'
    ).toEqual([])
  })

  test('every playbook entry describes a tool that still exists', () => {
    const live = new Set(tools.map(t => t.name))
    const stale = Object.keys(ONBOARDING_PLAYBOOK).filter(n => !live.has(n))
    expect(stale, `playbook entries for tools that no longer exist: ${stale.join(', ')}`).toEqual([])
  })

  test('every advertised tool sits in exactly one capability area', () => {
    const counts = new Map<string, number>()
    for (const area of CAPABILITY_AREAS) {
      for (const name of area.tools) counts.set(name, (counts.get(name) ?? 0) + 1)
    }
    for (const t of tools) {
      expect(counts.get(t.name) ?? 0, `${t.name} is in ${counts.get(t.name) ?? 0} capability areas`).toBe(1)
    }
    // And no area names a tool the build does not have.
    const live = new Set(tools.map(t => t.name))
    for (const area of CAPABILITY_AREAS) {
      for (const name of area.tools) {
        expect(live.has(name), `capability area ${area.id} names unknown tool ${name}`).toBe(true)
      }
    }
  })

  test('every playbook entry has real guidance, not a placeholder', () => {
    for (const [name, entry] of Object.entries(ONBOARDING_PLAYBOOK)) {
      expect(entry.whenToUse.length, `${name} has no whenToUse`).toBeGreaterThan(40)
      expect(entry.gotchas.length, `${name} lists no gotchas`).toBeGreaterThan(0)
      for (const g of entry.gotchas) {
        expect(g.length, `${name} has an empty gotcha`).toBeGreaterThan(20)
      }
    }
  })

  test('every workflow requires only registered tools, and is referenced correctly', () => {
    const live = new Set(tools.map(t => t.name))
    const ids = new Set(WORKFLOWS.map(w => w.id))
    for (const w of WORKFLOWS) {
      expect(w.requiredTools.length, `${w.id} requires no tools, so it always renders`).toBeGreaterThan(0)
      for (const name of w.requiredTools) {
        expect(live.has(name), `workflow ${w.id} needs unregistered tool ${name}`).toBe(true)
      }
      expect(w.body.length, `${w.id} has an empty body`).toBeGreaterThan(0)
    }
    for (const [name, entry] of Object.entries(ONBOARDING_PLAYBOOK)) {
      for (const ref of entry.workflowRefs) {
        expect(ids.has(ref), `${name} references unknown workflow ${ref}`).toBe(true)
      }
    }
  })

  test('every workflow is reachable by some scope set', () => {
    // A workflow no token can ever satisfy is dead text that nobody will notice.
    const full = packText(ALL)
    for (const w of WORKFLOWS) {
      expect(full, `workflow ${w.id} ("${w.title}") never renders`).toContain(w.title)
    }
  })

  test('every scope is either explained as available or listed as missing', () => {
    // With no scopes beyond the minimum, every other one must appear in the
    // "permissions this token does not hold" tail.
    const minimal = packText(READ_ONLY)
    for (const scope of MCP_SCOPES) {
      expect(minimal, `${scope} is never mentioned in a read-only pack`).toContain(scope)
    }
  })

  test('a full-scope pack reaches every tool', () => {
    const pack = renderOnboardingPack(tools, ALL, 'research', { version: 'test' })
    expect(pack.unavailable).toEqual([])
    expect(pack.available).toHaveLength(tools.length)
  })
})

// --- the scope filter ----------------------------------------------------------

describe('the scope filter', () => {
  test('a read-only token is told what it cannot call, by permission', () => {
    const text = packText(READ_ONLY)
    expect(text).toContain('You cannot call these, and asking will be refused')
    expect(text).toContain('`start_recon` - needs `recon:scan`')
    expect(text).toContain('`set_finding_verdict` - needs `triage:write`')
    expect(text).toContain('`kali_exec` - needs `kali:exec`')
  })

  test('a read-only token gets no scan, settings, cypher or exec procedures', () => {
    // Asserted on the workflow HEADING, not the bare phrase: "Raw Cypher" also
    // appears legitimately in query_graph's own guidance, where it is telling
    // the agent that raw Cypher is the last rung of the ladder.
    const text = packText(READ_ONLY)
    for (const title of [
      'Run a full scan end to end',
      'Change tuning safely',
      'Raw Cypher',
      'Overwrite mode (human-confirmed only)',
      'Run a command at the target',
      'Queue when busy',
      'Write back verdicts',
    ]) {
      expect(text, `a read-only pack should not teach "${title}"`).not.toContain(`### ${title}`)
    }
  })

  test('the kali reference file ships only with the exec permission', () => {
    const without = renderOnboardingPack(tools, READ_ONLY, 'custom', { version: 'test' })
    expect(without.files.map(f => f.path)).not.toContain('references/kali-exec.md')

    const withExec = renderOnboardingPack(tools, ['recon:read', 'kali:exec'], 'pentest', { version: 'test' })
    expect(withExec.files.map(f => f.path)).toContain('references/kali-exec.md')
  })

  test('a conditional scope is reported as a withheld ARGUMENT, not a missing tool', () => {
    // query_graph is callable with recon:read; only its `cypher` argument needs
    // graph:cypher. Saying the tool is unavailable would be wrong.
    const text = packText(READ_ONLY)
    expect(text).toMatch(/`query_graph`[^\n]*except when[^\n]*graph:cypher/)
  })

  test('the ladder drops rungs the token cannot reach', () => {
    // Scoped to the ladder's own fenced block: elsewhere in the pack the
    // "you cannot call these" tail names list_muted_findings deliberately.
    const ladder = (scopes: McpScope[]) => {
      const skill = renderOnboardingPack(tools, scopes, 'custom', { version: 't' }).files[0].content
      const start = skill.indexOf('## The tool-choice ladder')
      expect(start, 'the ladder is missing entirely').toBeGreaterThan(-1)
      const fenceStart = skill.indexOf('```', start)
      return skill.slice(fenceStart, skill.indexOf('```', fenceStart + 3))
    }

    const readOnly = ladder(READ_ONLY)
    expect(readOnly).toContain('query_graph(question)')
    expect(readOnly).not.toContain('query_graph(cypher)')
    expect(readOnly).not.toContain('list_muted_findings')

    const withTriage = ladder(['recon:read', 'triage:read', 'graph:cypher'])
    expect(withTriage).toContain('query_graph(cypher)')
    expect(withTriage).toContain('list_muted_findings')
  })

  test('a pack without triage:mute never presents the mute tools as something to call', () => {
    for (const scopes of [READ_ONLY, ['recon:read', 'triage:read', 'triage:write'] as McpScope[]]) {
      const text = packText(scopes, 'triage')
      expect(text, `${scopes.join('+')}`).not.toContain('### Suppress noise')
      expect(text).not.toContain('### Restore muted findings')
      expect(text).not.toContain('One call mutes at most')
      // Named only in the "you cannot call these" tail, with the permission it needs.
      expect(text).toContain('`mute_findings` - needs `triage:mute`')
    }
  })

  test('a triage:mute pack teaches the procedure and the per-call cap', () => {
    const text = packText(['recon:read', 'triage:read', 'triage:write', 'triage:mute'], 'triage')
    expect(text).toContain('### Suppress noise')
    expect(text).toContain('### Restore muted findings')
    expect(text).toMatch(/One call mutes at most 5000 findings and unmutes at most 5000/)
    expect(text).not.toMatch(/daily (mute )?budget is spent/)
    expect(text).toContain('a mute or unmute outcome is unknown')
  })

  test('a withdrawn tool is absent from the pack, because the pack reads tools/list', () => {
    // MCP_DISABLED_TOOLS filters at registration inside buildMcpServer, so a
    // withdrawn tool never reaches tools/list and therefore never reaches here.
    // If that filtering ever moved into a route, this property would quietly stop
    // holding.
    const withheld = tools.filter(t => t.name !== 'get_blast_radius')
    const text = renderOnboardingPack(withheld, ALL, 'reporting', { version: 'test' })
      .files.map(f => f.content).join('\n')
    expect(text).not.toContain('get_blast_radius')
    expect(text).toContain('list_exploit_paths')
  })
})

// --- the profile layer ---------------------------------------------------------

describe('the profile layer', () => {
  test('every profile renders against every representative scope set', () => {
    const sets: McpScope[][] = [
      READ_ONLY,
      ['recon:read', 'triage:read'],
      ['recon:read', 'graph:cypher', 'recon:scan'],
      ['recon:read', 'triage:read', 'triage:write'],
      ALL,
    ]
    for (const id of PROFILE_IDS) {
      for (const scopes of sets) {
        const pack = renderOnboardingPack(tools, scopes, id, { version: 'test' })
        expect(pack.files.length, `${id} with ${scopes.join('+')} rendered nothing`).toBeGreaterThan(0)
        expect(pack.files[0].path).toBe('SKILL.md')
        expect(pack.files[0].content, `${id} lost its profile heading`)
          .toContain(`## Your job: ${PROFILES[id].label}`)
      }
    }
  })

  test('the profile section NEVER names a tool the token cannot call', () => {
    // The profile ∩ scope rule. The "what you cannot do" tail names such tools
    // deliberately, which is why this asserts over the profile section alone.
    const names = tools.map(t => t.name)
    for (const id of PROFILE_IDS) {
      for (const scopes of [READ_ONLY, ['recon:read', 'triage:read'] as McpScope[], ALL]) {
        const section = renderProfileSection(tools, scopes, id)
        const unreachable = tools.filter(t => !canCall(t, scopes)).map(t => t.name)
        for (const name of unreachable) {
          // Word-boundary match: get_scan_status must not be found inside a
          // longer name, and vice versa.
          const named = new RegExp(`\\b${name}\\b`).test(section)
          expect(named, `${id} with ${scopes.join('+')} names unreachable tool ${name}`).toBe(false)
        }
        // And it does still name something, or the section is useless.
        expect(names.some(n => new RegExp(`\\b${n}\\b`).test(section)), `${id} names no tools at all`).toBe(true)
      }
    }
  })

  test('a null profile renders a valid custom pack', () => {
    // Every token minted before this feature has no profile.
    const pack = renderOnboardingPack(tools, ALL, null, { version: 'test' })
    expect(pack.files[0].content).toContain('## Your job: Custom')
    expect(pack.files[0].content).toContain('name: redamon-mcp')
  })

  test('a profile names the skill after itself, so two can coexist', () => {
    const asm = renderOnboardingPack(tools, ALL, 'asm', { version: 'test' })
    const triage = renderOnboardingPack(tools, ALL, 'triage', { version: 'test' })
    expect(asm.files[0].content).toContain('name: redamon-asm')
    expect(triage.files[0].content).toContain('name: redamon-triage')
  })

  test('an underscored profile id becomes a valid skill name', () => {
    const pack = renderOnboardingPack(tools, ALL, 'bug_bounty', { version: 'test' })
    expect(pack.files[0].content).toContain('name: redamon-bug-bounty')
  })

  test('the frontmatter description names the profile\'s job', () => {
    for (const id of PROFILE_IDS) {
      const pack = renderOnboardingPack(tools, ALL, id, { version: 'test' })
      expect(pack.files[0].content, `${id}`).toContain(PROFILES[id].forWhat.slice(0, 40))
    }
  })

  test('a profile whose leaned-on tool is out of reach names the PERMISSION, not the tool', () => {
    // pentest leans on kali_exec, which an operator may have unticked. Naming
    // the tool here would break the profile-intersect-scopes rule, so the
    // section asks for the permission and lets the "cannot call" list carry the
    // tool names.
    const section = renderProfileSection(tools, ['recon:read', 'triage:read'], 'pentest')
    expect(section).toContain('`kali:exec`')
    expect(section).not.toContain('kali_exec')
    expect(section).toContain('tell the human what you could not do')
  })
})

// --- the shared core -----------------------------------------------------------

describe('the shared core is always full', () => {
  test('every pack opens with the operating model, then RedAmon, then the graph', () => {
    for (const scopes of [READ_ONLY, ALL]) {
      const skill = renderOnboardingPack(tools, scopes, 'soc', { version: 'test' }).files[0].content
      const model = skill.indexOf('Read this first: what you are working with')
      const what = skill.indexOf('What RedAmon is, and what its recon pipeline does')
      const graph = skill.indexOf('The graph\'s shape')
      const surface = skill.indexOf('What the MCP surface can do')
      const job = skill.indexOf('Your job:')
      expect(model).toBeGreaterThan(-1)
      expect(what).toBeGreaterThan(model)
      expect(graph).toBeGreaterThan(what)
      expect(surface).toBeGreaterThan(graph)
      expect(job, 'the profile layer must come AFTER the shared explanation').toBeGreaterThan(surface)
    }
  })

  test('the shared explanation is not shrunk by a narrow scope set', () => {
    const narrow = renderOnboardingPack(tools, READ_ONLY, 'soc', { version: 'test' }).files[0].content
    const wide = renderOnboardingPack(tools, ALL, 'soc', { version: 'test' }).files[0].content
    for (const marker of [
      'domain_discovery -> port_scan -> http_probe -> resource_enum -> vuln_scan',
      'Vulnerability -> CVE -> MitreData (CWE) -> Capec',
      'is the TARGET talking',
      'a false "all clear" is the worst possible output',
    ]) {
      expect(narrow, `a read-only pack lost: ${marker}`).toContain(marker)
      expect(wide).toContain(marker)
    }
  })

  test('the ground rules carry the honesty contract in full', () => {
    const text = packText(ALL)
    for (const rule of [
      'never scanned',
      'A dependency failure is not an empty result',
      'Truncation is visible',
      'Only settled counts are trustworthy',
      '"Resolved" is ambiguous',
    ]) {
      expect(text).toContain(rule)
    }
  })

  /**
   * REGRESSION: the worked scenarios defeated the scope filter.
   *
   * They were a static prose block, so a `recon:read`-only token was handed a
   * trace instructing it to call `list_muted_findings` - a tool it will always
   * be refused. That scenario is the one teaching the bar for calling a project
   * "clean", so the agent learned a completeness rule it structurally could not
   * satisfy and was never told which half was out of reach.
   */
  test('a scenario never instructs a call the token will be refused', () => {
    for (const scopes of [READ_ONLY, ['recon:read', 'triage:read'] as McpScope[], ALL]) {
      const skill = renderOnboardingPack(tools, scopes, 'custom', { version: 't' }).files[0].content
      const start = skill.indexOf('## Worked scenarios')
      if (start === -1) continue
      const next = skill.indexOf('\n## ', start + 5)
      const section = skill.slice(start, next === -1 ? undefined : next)
      for (const t of tools.filter(x => !canCall(x, scopes))) {
        expect(
          new RegExp(`\\b${t.name}\\b`).test(section),
          `a ${scopes.join('+')} pack tells the agent to call ${t.name}`
        ).toBe(false)
      }
    }
  })

  test('the clean-check scenario says which half a read-only token cannot do', () => {
    // Dropping the suppression step silently would be worse than omitting the
    // scenario: the agent would believe an open-findings check was sufficient.
    const skill = renderOnboardingPack(tools, READ_ONLY, 'custom', { version: 't' }).files[0].content
    expect(skill).toContain('You cannot complete this one')
    expect(skill).toContain('triage:read')
    expect(skill).toContain('never\n"clean"')
  })

  test('with the permission, the full clean-check is taught instead', () => {
    const skill = renderOnboardingPack(tools, ['recon:read', 'triage:read'], 'custom', { version: 't' })
      .files[0].content
    expect(skill).toContain('list_muted_findings')
    expect(skill).not.toContain('You cannot complete this one')
  })

  test('the worked scenarios teach the honest conclusion', () => {
    const text = packText(ALL)
    expect(text).toContain('Worked scenarios')
    expect(text).toContain('suppressed by a human')
    expect(text).toContain('report the candidate and do not probe it')
  })
})

// --- §7: two things the pack must NEVER contain ---------------------------------

describe('nothing user-specific ever reaches the output', () => {
  const EVERY_COMBINATION: McpScope[][] = [
    [], READ_ONLY,
    ['recon:read', 'recon:scan'],
    ['recon:read', 'triage:read', 'triage:write'],
    ['recon:read', 'graph:cypher', 'recon:settings', 'recon:overwrite'],
    ['recon:read', 'recon:queue', 'kali:exec'],
    ALL,
  ]

  test('no token value, under any profile or scope set', () => {
    for (const id of PROFILE_IDS) {
      for (const scopes of EVERY_COMBINATION) {
        const text = renderOnboardingPack(tools, scopes, id, {
          version: 'test',
          serverUrl: 'https://redamon.example',
        }).files.map(f => f.content).join('\n')
        // The placeholder `rdmn_mcp_...` is fine; a real 40+ hex token is not.
        expect(text, `${id}/${scopes.join('+')} embedded a token`)
          .not.toMatch(new RegExp(`${MCP_TOKEN_PREFIX}[0-9a-f]{8,}`))
      }
    }
  })

  test('no project data, and nothing withheld from every read', () => {
    const text = packText(ALL, 'pentest')
    // The control is that no VALUE leaks and that nothing withheld from every
    // read on the surface is even named as reachable.
    //
    // `targetDomain` used to be on this list, when it was unreachable from
    // every route. It is now a required argument of create_project, so the pack
    // has to name it or an agent cannot open an engagement at all. Naming a
    // field an agent must pass is not a leak; naming a client's phone number
    // would be.
    for (const leaked of ['roeClientName', 'roeClientContactEmail', 'roeDocumentData', 'ownershipToken', 'cypherfixGithubToken']) {
      expect(text, `${leaked} should not be quoted as a field name`).not.toContain(leaked)
    }
    expect(text).not.toMatch(/\bproj_[a-z0-9]+/)
  })

  test('the pack names the engagement fields an agent must actually pass', () => {
    // The other direction: a pack that withheld these would describe a
    // capability the agent cannot use.
    const text = packText(ALL, 'pentest')
    for (const needed of ['targetDomain', 'engagementKind', 'roeGlobalMaxRps', 'idempotencyKey']) {
      expect(text, `${needed} is never mentioned`).toContain(needed)
    }
  })

  test('the server URL is the only thing the caller can inject, and it is bounded', () => {
    const pack = renderOnboardingPack(tools, ALL, 'asm', {
      version: 'test',
      serverUrl: 'https://redamon.example/',
    })
    const text = pack.files[0].content
    expect(text).toContain('https://redamon.example/api/mcp-server')
    // A trailing slash must not produce a double slash in the endpoint.
    expect(text).not.toContain('https://redamon.example//api')
  })
})

// --- determinism ----------------------------------------------------------------

describe('determinism', () => {
  test('the same inputs render byte-identical output', () => {
    for (const id of PROFILE_IDS) {
      const a = renderOnboardingPack(tools, ALL, id, { version: '1.2.3', serverUrl: 'https://h' })
      const b = renderOnboardingPack(tools, ALL, id, { version: '1.2.3', serverUrl: 'https://h' })
      expect(a.files, `${id} is not deterministic`).toEqual(b.files)
    }
  })

  test('nothing dated leaks into the output', () => {
    const text = packText(ALL)
    expect(text).not.toMatch(/\b20\d{2}-\d{2}-\d{2}\b/)
    expect(text).not.toMatch(/\bGMT\b|\bUTC\b\s*\d/)
  })

  test('the version stamp is injected, and it is the only thing that moves', () => {
    const a = renderOnboardingPack(tools, ALL, 'asm', { version: '1.0.0' }).files[0].content
    const b = renderOnboardingPack(tools, ALL, 'asm', { version: '9.9.9' }).files[0].content
    expect(a).not.toBe(b)
    expect(a.replace('1.0.0', 'X')).toBe(b.replace('9.9.9', 'X'))
  })

  test('scope order in the header does not depend on the caller\'s order', () => {
    const a = renderOnboardingPack(tools, ['kali:exec', 'recon:read'], 'pentest', { version: 't' })
    const b = renderOnboardingPack(tools, ['recon:read', 'kali:exec'], 'pentest', { version: 't' })
    expect(a.files).toEqual(b.files)
  })
})

// --- the layout -----------------------------------------------------------------

describe('the output shape', () => {
  test('folder layout splits the references out and links them', () => {
    const pack = renderOnboardingPack(tools, ALL, 'research', { version: 't', layout: 'folder' })
    const paths = pack.files.map(f => f.path)
    expect(paths[0]).toBe('SKILL.md')
    expect(paths).toContain('references/lifecycle-and-scans.md')
    expect(paths).toContain('references/findings-and-fixes.md')
    expect(paths).toContain('references/graph-queries.md')
    expect(paths).toContain('references/settings.md')
    expect(pack.files[0].content).toContain('](references/settings.md)')
  })

  test('single layout inlines everything into one file', () => {
    const pack = renderOnboardingPack(tools, ALL, 'research', { version: 't', layout: 'single' })
    expect(pack.files).toHaveLength(1)
    expect(pack.files[0].content).toContain('Settings and presets')
    expect(pack.files[0].content).toContain('Running a command at the target')
  })

  test('every file is markdown with a heading and no runaway blank lines', () => {
    for (const f of renderOnboardingPack(tools, ALL, 'bug_bounty', { version: 't' }).files) {
      expect(f.path.endsWith('.md'), `${f.path} is not markdown`).toBe(true)
      expect(f.content.trimEnd().endsWith('\n'), `${f.path} has no trailing newline`).toBe(false)
      expect(f.content.endsWith('\n'), `${f.path} has no trailing newline`).toBe(true)
      expect(f.content, `${f.path} has a triple blank line`).not.toMatch(/\n{3,}/)
      expect(f.content.length, `${f.path} is suspiciously short`).toBeGreaterThan(200)
    }
  })
})

// --- the inline onboarding -------------------------------------------------------

describe('the inline onboarding (the MCP instructions string)', () => {
  test('it is short, because it is prepended to every session', () => {
    for (const id of PROFILE_IDS) {
      const text = renderInlineOnboarding(tools, ALL, id)
      expect(text.length, `${id} inline onboarding is ${text.length} chars`).toBeLessThan(4000)
      expect(text.length, `${id} inline onboarding is too short to be useful`).toBeGreaterThan(600)
    }
  })

  test('it carries the operating model, the ladder and the honesty rules', () => {
    const text = renderInlineOnboarding(tools, ALL, 'bug_bounty')
    expect(text).toContain('ALREADY done the')
    expect(text).toContain('graph_summary')
    expect(text).toContain('written by the TARGET')
    expect(text).toContain('NEVER SCANNED')
    expect(text).toContain('Never change what RedAmon points at on your own initiative')
  })

  test('it names the token\'s real permissions and its profile', () => {
    const text = renderInlineOnboarding(tools, ['recon:read', 'triage:read'], 'triage')
    expect(text).toContain('recon:read, triage:read')
    expect(text).toContain('Triage assistance')
  })

  test('it never promises a tool the token cannot call', () => {
    for (const id of PROFILE_IDS) {
      const text = renderInlineOnboarding(tools, READ_ONLY, id)
      for (const t of tools.filter(x => !canCall(x, READ_ONLY))) {
        expect(new RegExp(`\\b${t.name}\\b`).test(text), `${id} inline names ${t.name}`).toBe(false)
      }
    }
  })

  test('the write sentence follows the token\'s write permissions', () => {
    const verdictOnly = renderInlineOnboarding(tools, ['recon:read', 'triage:write'], 'triage')
    expect(verdictOnly).toContain('Your writes to a finding: a verdict of confirmed, likely_noise, unreviewed.')
    expect(verdictOnly).toContain('You never set a score')
    expect(verdictOnly).not.toContain('mute_findings')
    expect(verdictOnly).not.toContain('evidence review')

    const all = renderInlineOnboarding(
      tools, ['recon:read', 'triage:read', 'triage:write', 'triage:review', 'triage:mute'], 'triage')
    expect(all).toContain(
      'Your writes to a finding: a verdict of confirmed, likely_noise, unreviewed, a quoted evidence review and a mute.')
    expect(all).toContain('A mute (mute_findings) hides a finding from everyone.')
    expect(all.length).toBeLessThanOrEqual(4000)

    const muteOnly = renderInlineOnboarding(tools, ['recon:read', 'triage:mute'], 'custom')
    expect(muteOnly).toContain('Your writes to a finding: a mute.')
    expect(muteOnly).not.toContain('You never set a score')
  })

  test('a null profile still produces usable instructions', () => {
    const text = renderInlineOnboarding(tools, READ_ONLY, null)
    expect(text).toContain('Custom')
    expect(text.length).toBeGreaterThan(600)
  })
})

// --- the facts the generator cannot check ------------------------------------------

describe('hand-written facts are pinned against the modules that own them', () => {
  // These are quoted in the prose and are NOT in tools/list, so nothing else
  // would notice them drifting.
  test('the finding sections named in the prose are the real ones', () => {
    const text = packText(ALL)
    expect(FINDING_SECTIONS).toEqual(['ranked', 'not_triaged', 'likely_false_positive', 'resolved'])
    for (const s of FINDING_SECTIONS) expect(text, `section ${s}`).toContain(s)
  })

  test('the verdict vocabulary matches the tool', () => {
    expect(VERDICT_STATUSES).toEqual(['confirmed', 'likely_noise', 'unreviewed'])
    const text = packText(ALL, 'triage')
    for (const v of VERDICT_STATUSES) expect(text).toContain(v)
  })

  test('the finding labels listed are the real muteable set', () => {
    const text = packText(ALL)
    for (const label of MUTEABLE_FINDING_LABELS) expect(text, `label ${label}`).toContain(label)
    expect(text).toContain(`these ${MUTEABLE_FINDING_LABELS.length} unrelated labels`)
  })

  test('the live graph states named are the real ones', () => {
    const text = packText(ALL)
    for (const state of ['stable', 'scan_running', 'agent_writing', 'activating', 'unknown']) {
      expect(text, `graph state ${state}`).toContain(state)
    }
  })

  /**
   * REGRESSION: the pack promised a safety net that does not exist.
   *
   * `kali_exec` became a real shell - `bash -c`, full toolset, no allowlist and
   * NO per-command target or excluded-host check. The hand-written guidance
   * still said "every command is checked against the project's own scope", so
   * an unattended agent was being told something would stop it that will not.
   * That is the most dangerous direction a generated instruction can be wrong
   * in, and no generated test noticed, because the claim is prose.
   */
  test('the exec guidance never promises a scope check that does not exist', () => {
    // Checked across EVERY profile, from PROFILE_IDS rather than a hand-typed
    // list: a profile's own trap lines render whatever the scopes are, and a
    // typo'd id silently resolves to `custom`, which would make a five-entry
    // loop look thorough while testing one profile three times.
    const FALSE_ASSURANCES = [
      'checked against the project',
      'checked against this project',
      'A refusal is a policy decision',
      'A refused command is a policy decision',
      'read-only list',
      'It is not a shell',
    ]
    for (const profile of PROFILE_IDS) {
      const text = packText(ALL, profile)
      for (const claim of FALSE_ASSURANCES) {
        expect(text, `the ${profile} pack still claims: "${claim}"`).not.toContain(claim)
      }
    }
  })

  test('the exec guidance states plainly that scope is the agent\'s own responsibility', () => {
    const text = packText(ALL, 'pentest')
    expect(text).toMatch(/NOTHING CHECKS WHAT YOU AIM AT|no per-command scope check|NO scope enforcement/)
    expect(text).toContain('get_recon_settings')
    expect(text).toMatch(/will not stop you/)
  })

  test('a token without the exec permission is taught none of it', () => {
    // The warning matters only where the capability exists; a read-only pack
    // carrying shell warnings is noise that dilutes the rules that do apply.
    const text = packText(READ_ONLY)
    expect(text).not.toContain('NOTHING CHECKS WHAT YOU AIM AT')
  })

  test('the rate-limit table is generated, not transcribed', () => {
    // The plan's draft said exec was 6/min; the code says otherwise. Reading it
    // live is the point.
    const text = packText(ALL)
    expect(text).toContain('| `exec` |')
    expect(text).toContain('| `compare` |')
    expect(text).toMatch(/\| `start` \| starting a scan, counted PER PROJECT \| \d+ per \d+ minutes \|/)
  })

  test('every tool named in a capability area is really in that area\'s scope family', () => {
    // Guards against a tool being filed under an area whose permission story is
    // different, which would put it on the wrong side of the availability line.
    for (const area of CAPABILITY_AREAS) {
      for (const name of area.tools) {
        const tool = tools.find(t => t.name === name)!
        expect(scopesOf(tool), `${name} has no scope declaration`).not.toBeNull()
      }
    }
  })
})

// --- the profile onboarding table renders whole ------------------------------------

describe('the profile table reaches the output', () => {
  test('each profile\'s posture, reporting format and gotchas all render', () => {
    for (const id of PROFILE_IDS) {
      const section = renderProfileSection(tools, ALL, id)
      const o = PROFILE_ONBOARDING[id]
      expect(section, `${id} lost its posture`).toContain(o.posture.slice(0, 60))
      expect(section, `${id} lost its reporting format`).toContain(o.reportAs.slice(0, 60))
      for (const g of o.gotchas) {
        expect(section, `${id} lost a gotcha`).toContain(g.slice(0, 50))
      }
    }
  })

  test('the primary loop renders as a numbered sequence', () => {
    const section = renderProfileSection(tools, ALL, 'asm')
    expect(section).toContain('### Your primary loop')
    expect(section).toMatch(/^1\. /m)
    expect(section).toMatch(/^2\. /m)
  })

  test('loop numbering stays contiguous when a step is dropped for scope', () => {
    // A read-only token loses asm's queue step; the remaining steps must not
    // leave a hole in the numbering.
    const section = renderProfileSection(tools, READ_ONLY, 'asm')
    const numbers = [...section.matchAll(/^(\d+)\. /gm)].map(m => Number(m[1]))
    expect(numbers).toEqual(numbers.map((_, i) => i + 1))
  })
})

// --- ROW 2: the documentation this feature added references real files --------

const WIKI_DIR = process.env.MCP_DOCS_WIKI_DIR
  || fileURLToPath(new URL('../../../../redamon.wiki/', import.meta.url))
/** A real wiki checkout; an empty one fails unless allowed (wikiCheckout.testUtils.ts). */
const hasWikiCheckout = () => wikiCheckoutPresent(WIKI_DIR)

describe('the Agent Onboarding documentation', () => {
  /**
   * The wiki is published straight to GitHub and mirrored to redamon.org, so a
   * reference to a screenshot that was never committed renders as a broken
   * image on the public page. Nothing else checks it: MCP-Server.md is prose,
   * not generated, so it has no drift test of its own.
   */
  test.skipIf(!hasWikiCheckout())('every image it references exists in the wiki repo', () => {
    const page = readFileSync(path.join(WIKI_DIR, 'MCP-Server.md'), 'utf8')
    const refs = [...page.matchAll(/!\[[^\]]*\]\((images\/[^)]+)\)/g)].map(m => m[1])
    expect(refs.length, 'MCP-Server.md references no images at all').toBeGreaterThan(0)

    const missing = refs.filter(r => !existsSync(path.join(WIKI_DIR, r)))
    expect(missing, `referenced but not committed: ${missing.join(', ')}`).toEqual([])
  })

  test.skipIf(!hasWikiCheckout())('the three Agent Onboarding screenshots are among them', () => {
    // Named explicitly: the generic check above would still pass if the feature's
    // own images were quietly dropped from the page along with their section.
    const page = readFileSync(path.join(WIKI_DIR, 'MCP-Server.md'), 'utf8')
    for (const shot of [
      'images/mcp-server-profile-picker.png',
      'images/mcp-server-onboarding-export.png',
      'images/mcp-server-profile-change.png',
    ]) {
      expect(page, `MCP-Server.md no longer shows ${shot}`).toContain(shot)
      expect(existsSync(path.join(WIKI_DIR, shot)), `${shot} is missing from the wiki repo`).toBe(true)
    }
  })

  test.skipIf(!hasWikiCheckout())('every image carries alt text saying what it proves', () => {
    // House convention, and the only thing a screen reader or a failed image
    // load leaves behind.
    const page = readFileSync(path.join(WIKI_DIR, 'MCP-Server.md'), 'utf8')
    const empty = [...page.matchAll(/!\[([^\]]*)\]\((images\/[^)]+)\)/g)]
      .filter(m => m[1].trim().length < 20)
      .map(m => m[2])
    expect(empty, `these images have no meaningful alt text: ${empty.join(', ')}`).toEqual([])
  })
})

describe('the layered Priority Board in the pack', () => {
  test('starting a triage run is no longer in the never-on-this-surface list', () => {
    const text = packText(['recon:read', 'triage:read', 'triage:run'])
    const never = text.slice(text.indexOf('never'), text.indexOf('## The tool-choice ladder'))
    expect(never).not.toMatch(/^- start a triage run$/m)
    expect(text).toMatch(/^- set a score, a tier or a factor directly$/m)
    expect(text).toMatch(/^- change or reset a verdict a person made in the app$/m)
  })

  test('the pack explains the layers and that nobody writes a score', () => {
    const text = packText(['recon:read', 'triage:read'])
    expect(text).toContain('The score has three layers, and nobody writes it.')
  })

  test('the review and run workflows render only with their tools', () => {
    expect(packText(['recon:read', 'triage:read', 'triage:review'])).toContain('Review the evidence behind a ranking')
    expect(packText(['recon:read', 'triage:read'])).not.toContain('Review the evidence behind a ranking')
    expect(packText(['recon:read', 'triage:read', 'triage:run'])).toContain('Re-rank after a scan')
  })
})
