/**
 * GET /api/plugins/contributions: the UI a plugin contributes, as the host reads it on a
 * page load (design §6, F-10/F-11/D-36). Only plugins that `showsContributions` (enabled,
 * ready or updating, not revoked) and declare at least one UI point appear; an updating one
 * is flagged.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({ db: null as unknown as Record<string, unknown>, eff: null as unknown }))
vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/prisma', () => ({ default: new Proxy({}, { get: (_t, k) => h.db[k as string] }) }))
vi.mock('@/lib/access', () => ({ requireEffectiveUser: async () => h.eff }))

import { createFakePrisma, type FakePrisma } from '@/lib/plugins/__testing__/fakePrisma'
import { GET } from './route'

let db: FakePrisma

const echoManifest = {
  id: 'echo',
  displayName: 'Echo',
  permissions: [],
  actions: [
    { id: 'list_items', timeoutSeconds: 30 },
    { id: 'save_item', timeoutSeconds: 30, resultScreen: 'ui/detail.json' },
    { id: 'echo_skill', timeoutSeconds: 3600, async: true },
  ],
  contributes: {
    nav: { label: 'Echo', icon: 'puzzle', screen: 'ui/home.json' },
    'chat.session.actions': [{ label: 'Echo this session', action: 'list_items' }],
    'project.skills.row': [{ label: 'Echo skill', action: 'echo_skill' }],
  },
}

const skillerManifest = {
  id: 'skiller',
  displayName: 'Skiller',
  permissions: ['session:read', 'llm:invoke', 'override:skill.text'],
  actions: [{ id: 'analyze_session', timeoutSeconds: 600, async: true, llm: true }],
  contributes: {
    'chat.session.actions': [
      { label: 'Improve skill from this session', icon: 'sparkles', action: 'analyze_session' },
      { label: 'Skill versions', icon: 'history', coreScreen: 'skill.text.versions' },
    ],
  },
}

function row(pluginId: string, over: Record<string, unknown> = {}, manifest: Record<string, unknown> | null = {}) {
  return {
    pluginId,
    enabled: true,
    status: 'ready',
    activeVersion: '1.0.0',
    grantedPermissions: [],
    manifest,
    ...over,
  }
}

beforeEach(() => {
  db = createFakePrisma()
  h.db = db as unknown as Record<string, unknown>
  h.eff = { userId: 'user-1' }
})

test('no session: 401', async () => {
  h.eff = NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  expect((await GET(new NextRequest('http://localhost/api/plugins/contributions'))).status).toBe(401)
})

describe('the list', () => {
  test('echo: every point, keyed, with llm/async pulled from the matching action', async () => {
    db.seed('pluginInstall', [row('echo', {}, echoManifest)])
    const res = await GET(new NextRequest('http://localhost/api/plugins/contributions'))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual([
      {
        pluginId: 'echo',
        displayName: 'Echo',
        updating: false,
        nav: { label: 'Echo', icon: 'puzzle', screen: 'ui/home.json' },
        chatSessionActions: [
          { key: 'list_items', label: 'Echo this session', action: 'list_items', llm: false, async: false },
        ],
        projectSkillsRow: [{ key: 'echo_skill', label: 'Echo skill', action: 'echo_skill' }],
      },
    ])
  })

  test('skiller: an llm async action and a coreScreen item, icons kept', async () => {
    db.seed('pluginInstall', [row('skiller', {}, skillerManifest)])
    const [c] = await (await GET(new NextRequest('http://localhost/api/plugins/contributions'))).json()
    expect(c.nav).toBeUndefined()
    expect(c.projectSkillsRow).toEqual([])
    expect(c.chatSessionActions).toEqual([
      { key: 'analyze_session', label: 'Improve skill from this session', icon: 'sparkles', action: 'analyze_session', llm: true, async: true },
      { key: 'skill.text.versions', label: 'Skill versions', icon: 'history', coreScreen: 'skill.text.versions', llm: false, async: false },
    ])
  })

  test('only plugins that show contributions, by id; updating is flagged', async () => {
    db.seed('pluginInstall', [
      row('echo', {}, echoManifest),
      row('skiller', { status: 'updating' }, skillerManifest),
      row('disabled', { enabled: false }, echoManifest),
      row('revoked', { revokedReason: 'revoked' }, echoManifest),
      row('failed', { status: 'failed' }, echoManifest),
      row('available', { status: 'available', enabled: false }, echoManifest),
      row('nomanifest', {}, null),
    ])
    const list = await (await GET(new NextRequest('http://localhost/api/plugins/contributions'))).json()
    expect(list.map((c: { pluginId: string }) => c.pluginId)).toEqual(['echo', 'skiller'])
    expect(list.find((c: { pluginId: string }) => c.pluginId === 'skiller').updating).toBe(true)
    expect(list.find((c: { pluginId: string }) => c.pluginId === 'echo').updating).toBe(false)
  })

  test('a qualifying plugin with no UI contributions is left out', async () => {
    db.seed('pluginInstall', [
      row('behaviouronly', {}, { id: 'behaviouronly', displayName: 'B', permissions: ['override:skill.text'], actions: [] }),
    ])
    expect(await (await GET(new NextRequest('http://localhost/api/plugins/contributions'))).json()).toEqual([])
  })

  test('none installed: an empty list', async () => {
    expect(await (await GET(new NextRequest('http://localhost/api/plugins/contributions'))).json()).toEqual([])
  })
})
