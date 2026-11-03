/**
 * Agent Profiles: the invariants that make a profile safe to act on.
 *
 * Most of these are safety controls rather than unit tests. Two in particular:
 *
 *  - **no profile auto-ticks `recon:overwrite`.** Irreversible graph
 *    destruction must never arrive as a side effect of choosing from a
 *    dropdown. `kali:exec` is the deliberate opposite: every profile ticks it,
 *    and the tests below pin that too, so neither direction drifts silently.
 *  - **`profile` is never an authorization input.** It is a label and a starting
 *    point; scopes alone are enforced. A second, weaker authorization path is
 *    the one genuinely dangerous thing this feature could introduce, so the
 *    authorization modules are scanned for any read of it.
 *
 * @vitest-environment node
 */
import { existsSync, readFileSync, readdirSync } from 'fs'
import { wikiCheckoutPresent } from '@/lib/wikiCheckout.testUtils'
import path from 'path'
import { fileURLToPath } from 'url'
import { describe, test, expect, beforeAll, vi } from 'vitest'

// tools/list needs a server, and a server imports the Prisma-touching tool
// bodies. Nothing here calls a tool, so an absent client is enough.
vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import { DEFAULT_MCP_SCOPES, MCP_SCOPES, isTokenWidening, type McpScope } from '@/lib/mcpAuth'
import { listAdvertisedTools } from './apiReference'
import {
  DEFAULT_PROFILE,
  NEVER_AUTO_TICKED,
  PROFILES,
  PROFILE_IDS,
  PROFILE_LIST,
  PROFILE_ONBOARDING,
  isKnownProfile,
  profileOrDefault,
  profileScopeDiff,
  scopesForProfile,
  validateProfile,
} from './profiles'

beforeAll(() => {
  // The build's full surface. Unset reads as off and withdraws the sandbox
  // tools, while docker-compose.yml defaults the switch on.
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  // Agent in the Loop is off by default; the loop tools are part of the build.
  vi.stubEnv('AGENT_IN_THE_LOOP_ENABLED', 'true')
})

const LIB_MCP_DIR = fileURLToPath(new URL('.', import.meta.url))
const MCP_AUTH = fileURLToPath(new URL('../mcpAuth.ts', import.meta.url))

const WIKI_DIR = process.env.MCP_DOCS_WIKI_DIR
  || fileURLToPath(new URL('../../../../redamon.wiki/', import.meta.url))
/** A real wiki checkout; an empty one fails unless allowed (wikiCheckout.testUtils.ts). */
const hasWikiCheckout = () => wikiCheckoutPresent(WIKI_DIR)

const known = new Set<string>(MCP_SCOPES)

describe('the registry', () => {
  test('every profile id has an entry, keyed by itself', () => {
    for (const id of PROFILE_IDS) {
      expect(PROFILES[id], `no entry for ${id}`).toBeDefined()
      expect(PROFILES[id].id, `${id} is keyed under the wrong id`).toBe(id)
    }
    expect(PROFILE_LIST).toHaveLength(PROFILE_IDS.length)
  })

  test('every profile has operator-facing copy', () => {
    for (const p of PROFILE_LIST) {
      expect(p.label.length, `${p.id} has no label`).toBeGreaterThan(0)
      expect(p.blurb.length, `${p.id} has no blurb`).toBeGreaterThan(0)
      expect(p.forWhat.length, `${p.id} has no forWhat`).toBeGreaterThan(0)
    }
  })

  test('recommended and opt-in scopes are real scopes', () => {
    // A renamed scope must not leave a profile silently granting nothing.
    for (const p of PROFILE_LIST) {
      for (const s of p.recommendedScopes) {
        expect(known.has(s), `${p.id} recommends unknown scope ${s}`).toBe(true)
      }
      for (const s of p.optInScopes) {
        expect(known.has(s), `${p.id} offers unknown opt-in scope ${s}`).toBe(true)
      }
    }
  })

  test('recommended and opt-in never overlap', () => {
    for (const p of PROFILE_LIST) {
      const overlap = p.optInScopes.filter(s => p.recommendedScopes.includes(s))
      expect(overlap, `${p.id} both ticks and opt-ins ${overlap.join(', ')}`).toEqual([])
    }
  })

  test('every profile includes recon:read', () => {
    // Without it the agent cannot discover a project id, so the token is inert.
    for (const p of PROFILE_LIST) {
      expect(p.recommendedScopes, `${p.id} cannot discover a project`).toContain('recon:read')
    }
  })

  test('NO profile auto-ticks recon:overwrite', () => {
    // It may appear ONLY in optInScopes, where the form renders it unchecked
    // behind a danger callout.
    for (const p of PROFILE_LIST) {
      for (const forbidden of NEVER_AUTO_TICKED) {
        expect(
          p.recommendedScopes.includes(forbidden),
          `${p.id} auto-ticks ${forbidden}, which no profile may ever do`
        ).toBe(false)
      }
    }
  })

  test('the never-auto-ticked list is exactly recon:overwrite, triage:mute and project:rescope', () => {
    // Guards against the list being quietly emptied, which would turn the
    // assertion above into a tautology.
    expect([...NEVER_AUTO_TICKED]).toEqual(['recon:overwrite', 'triage:mute', 'project:rescope'])
  })

  test('project:rescope is an opt-in on the monitoring profile only, and recommended by none', () => {
    // It reopens scope on an existing project. It may be offered, never ticked.
    for (const p of PROFILE_LIST) {
      expect(p.recommendedScopes, `${p.id} recommends project:rescope`).not.toContain('project:rescope')
      if (p.id !== 'asm') expect(p.optInScopes, `${p.id} offers project:rescope`).not.toContain('project:rescope')
    }
    expect(PROFILES.asm.optInScopes).toContain('project:rescope')
  })

  test('the preset scopes are ticked by research alone, and apply is offered to the engagement jobs', () => {
    // Writing the library is a stored instruction a person applies later, so
    // only the throwaway-project profile ticks it.
    for (const scope of ['preset:write', 'preset:apply'] as const) {
      const ticking = PROFILE_LIST.filter(p => p.recommendedScopes.includes(scope)).map(p => p.id)
      expect(ticking, scope).toEqual(['research'])
    }
    for (const id of ['pentest', 'bug_bounty', 'asm'] as const) {
      expect(PROFILES[id].optInScopes, id).toContain('preset:apply')
      expect(PROFILES[id].optInScopes, id).not.toContain('preset:write')
    }
  })

  test('triage:mute is an opt-in on the Triage profile only, and recommended by none', () => {
    // A mute hides a finding from every read. It may be offered, never ticked.
    for (const p of PROFILE_LIST) {
      expect(p.recommendedScopes, `${p.id} recommends triage:mute`).not.toContain('triage:mute')
      if (p.id !== 'triage') expect(p.optInScopes, `${p.id} offers triage:mute`).not.toContain('triage:mute')
    }
    expect(PROFILES.triage.optInScopes).toContain('triage:mute')
  })

  test('EVERY profile auto-ticks kali:exec, and none offers it as opt-in', () => {
    // Sandbox access is on by default: a new token reaches the shell unless the
    // operator unticks it. A profile that dropped it would silently mint tokens
    // that cannot use the sandbox.
    for (const p of PROFILE_LIST) {
      expect(p.recommendedScopes, `${p.id} does not tick kali:exec`).toContain('kali:exec')
      expect(p.optInScopes, `${p.id} still offers kali:exec as opt-in`).not.toContain('kali:exec')
    }
  })

  test('the blank form ticks exactly what Custom recommends', () => {
    // The create form opens as Custom with DEFAULT_MCP_SCOPES ticked. If the two
    // differ, an untouched form reads as hand-edited and the first profile pick
    // asks the operator to confirm discarding choices they never made.
    expect([...DEFAULT_MCP_SCOPES].sort()).toEqual([...scopesForProfile(DEFAULT_PROFILE)].sort())
    expect(DEFAULT_MCP_SCOPES).toContain('kali:exec')
  })

  test('scopesForProfile returns the recommendation in checklist order', () => {
    for (const p of PROFILE_LIST) {
      const resolved = scopesForProfile(p.id)
      expect([...resolved].sort()).toEqual([...p.recommendedScopes].sort())
      const positions = resolved.map(s => MCP_SCOPES.indexOf(s))
      expect(positions, `${p.id} is not in MCP_SCOPES order`).toEqual([...positions].sort((a, b) => a - b))
    }
  })

  test('the profile that wants recon:overwrite offers it as opt-in', () => {
    // If research loses its opt-in the UI silently stops recommending a
    // permission the job genuinely needs.
    expect(PROFILES.research.optInScopes).toContain('recon:overwrite')
  })

  test('the read-only profiles grant no write of any kind', () => {
    // Read-only by default wherever the job allows it. These seven jobs never
    // need to change anything, so a write scope appearing here is a regression.
    // kali:exec is not counted: every profile carries it by design (see above).
    const WRITES: McpScope[] = [
      'recon:scan', 'recon:queue', 'recon:overwrite', 'recon:settings', 'triage:write', 'triage:mute',
      'triage:review', 'triage:run', 'preset:write', 'preset:apply', 'project:rescope',
    ]
    for (const id of ['vuln_mgmt', 'inventory', 'compliance', 'reporting', 'threat_intel', 'soc', 'custom'] as const) {
      const granted = PROFILES[id].recommendedScopes.filter(s => WRITES.includes(s))
      expect(granted, `${id} should be read-only but grants ${granted.join(', ')}`).toEqual([])
    }
  })

  test('the unattended profiles can queue rather than only start', () => {
    // asm and ci_gating run with nobody watching: a direct start just fails when
    // the project is busy, so queueing is what makes them work at all.
    expect(PROFILES.asm.recommendedScopes).toContain('recon:queue')
    expect(PROFILES.ci_gating.recommendedScopes).toContain('recon:queue')
    expect(PROFILES.ci_gating.recommendedScopes).not.toContain('recon:scan')
  })

  test('the durable finding write goes to exactly one profile', () => {
    const withWrite = PROFILE_LIST.filter(p => p.recommendedScopes.includes('triage:write')).map(p => p.id)
    expect(withWrite).toEqual(['triage'])
  })

  test('settings tuning goes to exactly one profile', () => {
    const withSettings = PROFILE_LIST.filter(p => p.recommendedScopes.includes('recon:settings')).map(p => p.id)
    expect(withSettings).toEqual(['research'])
  })

  test('the engagement profiles offer settings tuning, unticked', () => {
    // Tuning an engagement's scans is part of those jobs, but it changes what
    // reaches a third party, so the operator ticks it rather than the dropdown.
    for (const id of ['pentest', 'bug_bounty'] as const) {
      expect(PROFILES[id].optInScopes, id).toContain('recon:settings')
      expect(PROFILES[id].recommendedScopes, id).not.toContain('recon:settings')
    }
  })
})

describe('validation', () => {
  test('a known profile is accepted', () => {
    for (const id of PROFILE_IDS) {
      expect(validateProfile(id)).toEqual({ profile: id })
    }
  })

  test('null, undefined and empty all mean no profile', () => {
    expect(validateProfile(null)).toEqual({ profile: null })
    expect(validateProfile(undefined)).toEqual({ profile: null })
    expect(validateProfile('')).toEqual({ profile: null })
  })

  test('an unknown profile is REJECTED, never coerced to custom', () => {
    // Mirrors validateScopes: silently storing something the caller did not ask
    // for is how a typo becomes a token labelled as a job it was never for.
    for (const bad of ['bugbounty', 'BUG_BOUNTY', 'admin', 'pentest ', 42, {}, []]) {
      const result = validateProfile(bad)
      expect('error' in result, `${JSON.stringify(bad)} was accepted`).toBe(true)
    }
  })

  test('isKnownProfile does not accept a prototype key', () => {
    expect(isKnownProfile('toString')).toBe(false)
    expect(isKnownProfile('constructor')).toBe(false)
  })

  test('a stored null reads as custom', () => {
    // Every token minted before this feature has no profile.
    expect(profileOrDefault(null)).toBe('custom')
    expect(profileOrDefault(undefined)).toBe('custom')
    expect(profileOrDefault('nonsense')).toBe('custom')
    expect(profileOrDefault('pentest')).toBe('pentest')
    expect(DEFAULT_PROFILE).toBe('custom')
  })
})

describe('divergence from the profile', () => {
  test('the recommendation itself is not modified', () => {
    for (const p of PROFILE_LIST) {
      expect(profileScopeDiff(p.id, scopesForProfile(p.id)).modified, `${p.id}`).toBe(false)
    }
  })

  test('ticking an extra scope reads as added, unticking as removed', () => {
    const base = scopesForProfile('soc')
    const added = profileScopeDiff('soc', [...base, 'triage:write'])
    expect(added.added).toEqual(['triage:write'])
    expect(added.removed).toEqual([])
    expect(added.modified).toBe(true)

    const removed = profileScopeDiff('soc', base.filter(s => s !== 'graph:cypher'))
    expect(removed.removed).toEqual(['graph:cypher'])
    expect(removed.added).toEqual([])
    expect(removed.modified).toBe(true)
  })
})

describe('a profile switch is judged by the existing widening check', () => {
  // The profile must not become a second authorization path, so a switch that
  // adds a scope has to be caught by isTokenWidening exactly like a hand tick.
  const at = (scopes: McpScope[]) => ({ scopes, expiresAt: null as Date | null })

  test('switching to a profile that adds a scope widens the token', () => {
    // soc (read + cypher) -> research (adds scan and settings).
    expect(isTokenWidening(at(scopesForProfile('soc')), at(scopesForProfile('research')))).toBe(true)
  })

  test('switching to a narrower profile does not widen it', () => {
    // research -> vuln_mgmt drops scan, settings and cypher.
    expect(isTokenWidening(at(scopesForProfile('research')), at(scopesForProfile('vuln_mgmt')))).toBe(false)
  })

  test('a profile change with no scope change never widens', () => {
    // vuln_mgmt and compliance recommend the same set: the label changes, the
    // power does not, so this must not demand a password.
    expect(scopesForProfile('vuln_mgmt')).toEqual(scopesForProfile('compliance'))
    expect(isTokenWidening(at(scopesForProfile('vuln_mgmt')), at(scopesForProfile('compliance')))).toBe(false)
  })

  test('every pair of profiles is judged the same way by set comparison', () => {
    for (const from of PROFILE_IDS) {
      for (const to of PROFILE_IDS) {
        const before = scopesForProfile(from)
        const after = scopesForProfile(to)
        const addsSomething = after.some(s => !before.includes(s))
        expect(isTokenWidening(at(before), at(after)), `${from} -> ${to}`).toBe(addsSomething)
      }
    }
  })
})

describe('the onboarding table', () => {
  test('every profile has an entry with all five slots filled', () => {
    for (const id of PROFILE_IDS) {
      const o = PROFILE_ONBOARDING[id]
      expect(o, `no onboarding entry for ${id}`).toBeDefined()
      expect(o.posture.length, `${id} has no posture`).toBeGreaterThan(40)
      expect(o.primaryLoop.length, `${id} has no primary loop`).toBeGreaterThan(0)
      expect(o.leansOn.length, `${id} leans on nothing`).toBeGreaterThan(0)
      expect(o.reportAs.length, `${id} has no reporting format`).toBeGreaterThan(20)
      // `ignore` is allowed to be empty (custom has no job to narrow), but
      // gotchas never are: every job has at least one trap of its own.
      expect(o.gotchas.length, `${id} has no gotchas`).toBeGreaterThan(0)
    }
  })

  test('leansOn names 3 to 5 tools, each with a reason', () => {
    for (const id of PROFILE_IDS) {
      const o = PROFILE_ONBOARDING[id]
      if (id === 'custom') continue // the generic loop, deliberately shorter
      expect(o.leansOn.length, `${id} leans on ${o.leansOn.length} tools`).toBeGreaterThanOrEqual(3)
      expect(o.leansOn.length, `${id} leans on ${o.leansOn.length} tools`).toBeLessThanOrEqual(5)
      for (const l of o.leansOn) {
        expect(l.why.length, `${id}/${l.tool} has no reason`).toBeGreaterThan(20)
      }
    }
  })

  test('a loop step names its tools in a list, never in its prose', () => {
    // The renderer filters the `tools` arrays against the token's scopes. A tool
    // named in the prose would slip past that filter and promise a call the
    // token cannot make.
    for (const id of PROFILE_IDS) {
      for (const s of PROFILE_ONBOARDING[id].primaryLoop) {
        expect(s.step.length, `${id} has an empty loop step`).toBeGreaterThan(0)
        expect(s.step, `${id} loop step names a tool in prose: ${s.step}`).not.toMatch(/_[a-z]+\b/)
      }
    }
  })

  test('every tool a profile names is a real registered tool', async () => {
    // A renamed tool must not leave a profile pointing at nothing, and the loop
    // steps drive the rendered call sequence.
    const registered = new Set((await listAdvertisedTools()).map(t => t.name))
    for (const id of PROFILE_IDS) {
      const o = PROFILE_ONBOARDING[id]
      for (const l of o.leansOn) {
        expect(registered.has(l.tool), `${id} leans on unregistered tool ${l.tool}`).toBe(true)
      }
      for (const s of o.primaryLoop) {
        for (const name of s.tools) {
          expect(registered.has(name), `${id} loop names unregistered tool ${name}`).toBe(true)
        }
      }
    }
  })

  test('a profile never leans on a tool its own recommendation cannot reach', async () => {
    // An opt-in scope counts as reachable: recommended by the profile, ticked
    // only by a human.
    const tools = await listAdvertisedTools()
    const scopesOf = new Map(tools.map(t => {
      const meta = t._meta?.['org.redamon/scopes'] as { required: McpScope[] } | undefined
      return [t.name, meta?.required ?? []]
    }))
    for (const p of PROFILE_LIST) {
      const reachable = new Set<McpScope>([...p.recommendedScopes, ...p.optInScopes])
      for (const l of PROFILE_ONBOARDING[p.id].leansOn) {
        const needed = scopesOf.get(l.tool) ?? []
        const missing = needed.filter(s => !reachable.has(s))
        expect(missing, `${p.id} leans on ${l.tool}, which needs ${missing.join(', ')}`).toEqual([])
      }
    }
  })
})

describe('profile is never an authorization input', () => {
  /**
   * The dangerous failure this feature could introduce is a second, weaker
   * authorization path. Scopes are the only enforcement, so the modules that DO
   * the enforcing are scanned for any read of the field.
   */
  test('mcpAuth.ts, which owns resolution and rate limiting, never mentions a profile', () => {
    const source = readFileSync(MCP_AUTH, 'utf8')
    expect(source, 'mcpAuth.ts reads a profile; scopes must be the only enforcement').not.toMatch(/profile/i)
  })

  test('no tool body or server module reads a profile off the token', () => {
    // The generator and the registry are the only modules allowed to know about
    // profiles at all; everything else in src/lib/mcp/ is request-path code.
    const ALLOWED = new Set(['profiles.ts', 'onboarding.ts'])
    const offenders: string[] = []
    for (const file of readdirSync(LIB_MCP_DIR)) {
      if (!file.endsWith('.ts') || file.endsWith('.test.ts') || ALLOWED.has(file)) continue
      const source = readFileSync(path.join(LIB_MCP_DIR, file), 'utf8')
      // Any read of a profile off a token or context, however it is spelled.
      if (/\b(token|ctx|ctx\.token|row|t)\s*\.\s*profile\b/.test(source)) offenders.push(file)
    }
    expect(offenders, `these modules read a token profile: ${offenders.join(', ')}`).toEqual([])
  })
})

// --- ROW 1: the wiki's profile table is hand-written and drifts silently ------

describe('the published profile table matches the registry', () => {
  /**
   * `MCP-Server.md` lists every profile and the permissions it ticks, by hand.
   * It is the only place an operator can see the recommended set for their job,
   * so a registry change that does not reach it publishes a permission model
   * RedAmon does not implement. Nothing else notices: the page is prose, not
   * generated like MCP-API-Reference.md.
   */
  test.skipIf(!hasWikiCheckout())('every documented row equals scopesForProfile(id)', () => {
    const page = readFileSync(path.join(WIKI_DIR, 'MCP-Server.md'), 'utf8')

    for (const p of PROFILE_LIST) {
      const row = page.split('\n').find(l => l.startsWith(`| **${p.label}** |`))
      expect(row, `MCP-Server.md documents no row for "${p.label}"`).toBeDefined()

      const documented = [...row!.matchAll(/`([a-z]+:[a-z]+)`/g)].map(m => m[1])
      expect(
        [...documented].sort(),
        `MCP-Server.md lists the wrong permissions for "${p.label}". ` +
          'Update the Agent Profile table in the wiki repo.'
      ).toEqual([...scopesForProfile(p.id)].sort())
    }
  })

  test.skipIf(!hasWikiCheckout())('the table documents no profile the registry dropped', () => {
    const page = readFileSync(path.join(WIKI_DIR, 'MCP-Server.md'), 'utf8')
    const start = page.indexOf('### The Agent Profile')
    const section = page.slice(start, page.indexOf('###', start + 10))
    const labels = [...section.matchAll(/^\| \*\*(.+?)\*\* \|/gm)].map(m => m[1])
    const known = new Set(PROFILE_LIST.map(p => p.label))
    expect(labels.filter(l => !known.has(l)), 'wiki documents a profile that no longer exists').toEqual([])
    expect(labels).toHaveLength(PROFILE_LIST.length)
  })

  test.skipIf(!hasWikiCheckout())('the page names the permission no profile may tick', () => {
    // The wiki is where an operator learns this guarantee; losing the sentence
    // loses the only published statement of the feature's core safety rule.
    const page = readFileSync(path.join(WIKI_DIR, 'MCP-Server.md'), 'utf8')
    for (const scope of NEVER_AUTO_TICKED) {
      expect(page, `the wiki never mentions that ${scope} is left unticked`)
        .toMatch(new RegExp(`\`${scope.replace(':', ':')}\`[^\n]*`))
    }
    expect(page).toContain('always left unticked')
  })
})
