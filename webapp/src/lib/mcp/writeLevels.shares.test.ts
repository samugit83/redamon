/**
 * MCP write tools on a project shared at Read + Write (step 5.2; SH-42 write part, PE-20): each tool asks
 * the level of the registry permission behind it, as the app's route does, through
 * `mcpProjectAccess(token, projectId, level)`:
 *   - W: update_recon_settings (project:settings), apply_recon_preset (preset:apply), set_finding_verdict
 *     (triage:verdict), submit_finding_review (triage:review), mute_findings / unmute_findings (triage:mute);
 *   - W+S: start_recon / stop_recon (recon:scan), queue_recon / cancel_queued_scan (recon:schedule);
 *   - M: update_project_scope (project:rescope), list_engagement_authorizations (the app's list asks M);
 *   - W+A: start/stop_triage_run (triage:run; the run names its person, step 5.10);
 *   - W+X: the Kali sandbox tools kali_exec / kali_output / kali_cancel (agent:kali_exec, step 5.10);
 *   - the owner's alone: attach_engagement_authorization and capturing a project into a preset.
 * A shortfall on a reached project is `McpLevelDenied` naming the toggle the share lacks; a read share's
 * refusal and the owner's reach are unchanged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'

const h = vi.hoisted(() => ({ access: null as unknown }))
vi.mock('@/lib/authz/projectAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/projectAccess')>()),
  projectAccess: async () => h.access,
}))

import { McpAccessDenied, McpLevelDenied, mcpProjectAccess } from '@/lib/mcpAuth'
import type { ProjectLevel } from '@/lib/authz/permissions'

const P = { id: 'p1', userId: 'owner' }
const write = (toggles: Partial<Record<'runScans' | 'useAgent' | 'exploit' | 'manage', boolean>> = {}) => ({
  project: P, level: 'write', via: 'share',
  toggles: { rawData: true, runScans: false, useAgent: false, exploit: false, manage: false, ...toggles },
})
const TOKEN = { userId: 'collab', sharedProjects: { allowlist: [] } }

async function reach(access: unknown, level: ProjectLevel): Promise<'ok' | string> {
  h.access = access
  try {
    await mcpProjectAccess(TOKEN, 'p1', level)
    return 'ok'
  } catch (e) {
    expect(e).toBeInstanceOf(McpAccessDenied)
    return (e as Error).message
  }
}

describe('mcpProjectAccess on a Read + Write share (step 5.2)', () => {
  test('an editor reaches W (and the reads); every toggled level is refused naming its toggle', async () => {
    expect(await reach(write(), 'W')).toBe('ok')
    expect(await reach(write(), 'R*')).toBe('ok')
    expect(await reach(write(), 'W+S')).toMatch(/at Read \+ Write without Run scans, which this tool needs/)
    expect(await reach(write(), 'W+A')).toMatch(/without Use AI agent/)
    expect(await reach(write(), 'W+X')).toMatch(/without Exploitation & shells/)
    expect(await reach(write(), 'M')).toMatch(/without Manage/)
  })

  test('toggle required: a co-owner reaches M, never a run level through Manage, never the owner\'s', async () => {
    expect(await reach(write({ manage: true }), 'M')).toBe('ok')
    expect(await reach(write({ manage: true }), 'W+S')).toMatch(/without Run scans/)
    expect(await reach(write({ manage: true }), 'O')).toMatch(/owner's alone/)
  })

  test('a shortfall is McpLevelDenied (the token reaches the project), never "not found"', async () => {
    h.access = write()
    await expect(mcpProjectAccess(TOKEN, 'p1', 'M')).rejects.toBeInstanceOf(McpLevelDenied)
  })

  test("a read share's refusal and the owner's reach are unchanged", async () => {
    expect(await reach({ project: P, level: 'read', toggles: { rawData: false }, via: 'share' }, 'W')).toBe(
      'This project is shared with your account at Read access, so this tool, which changes it or acts on it, ' +
      "is not available. Only the project's owner can use it.",
    )
    h.access = { project: P, level: 'owner', toggles: { rawData: true }, via: 'owner' }
    await expect(mcpProjectAccess({ userId: 'owner' }, 'p1', 'O')).resolves.toMatchObject({ project: P })
  })
})

/** The level literal the access check inside `fn` (in `file`) passes; 'O' when it names none. */
function levelAsked(file: string, fn: string): string {
  const src = readFileSync(path.join(__dirname, file), 'utf8')
  const start = src.indexOf(`function ${fn}(`)
  expect([fn, start]).not.toEqual([fn, -1])
  const next = src.indexOf('\nexport ', start + 1)
  const body = src.slice(start, next === -1 ? undefined : next)
  const call = body.match(/(?:assertMcpProjectAccess|mcpProjectAccess|assertJobInProject)\(([^)]*)\)/)
  expect([fn, call]).not.toEqual([fn, null])
  const level = call![1].match(/'(R\*?|W(?:\+[SAX])?|M|O)'\s*$/)
  return level ? level[1] : 'O'
}

describe('each write tool asks its permission\'s level (the map above)', () => {
  test.each([
    ['writeTools.ts', 'updateReconSettings', 'W'],
    ['presetTools.ts', 'applyReconPreset', 'W'],
    ['verdictTools.ts', 'setFindingVerdict', 'W'],
    ['triageTools.ts', 'submitFindingReview', 'W'],
    ['muteTools.ts', 'muteFindings', 'W'],
    ['muteTools.ts', 'unmuteFindings', 'W'],
    ['writeTools.ts', 'startRecon', 'W+S'],
    ['writeTools.ts', 'stopRecon', 'W+S'],
    ['queueTools.ts', 'queueRecon', 'W+S'],
    ['queueTools.ts', 'cancelQueuedScan', 'W+S'],
    ['scopeTools.ts', 'updateProjectScope', 'M'],
    ['engagementTools.ts', 'listEngagementAuthorizations', 'M'],
    ['engagementTools.ts', 'attachEngagementAuthorization', 'O'],
    ['triageTools.ts', 'startTriageRun', 'W+A'],
    ['triageTools.ts', 'stopTriageRun', 'W+A'],
    ['kaliTools.ts', 'execCommand', 'W+X'],
    ['kaliTools.ts', 'readCommandOutput', 'W+X'],
    ['kaliTools.ts', 'cancelCommand', 'W+X'],
  ])('%s %s asks %s', (file, fn, level) => {
    expect(levelAsked(file, fn)).toBe(level)
  })
})
