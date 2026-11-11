/**
 * Scan Timeline — the OTHER direction of the activation lock (Section 4A.3).
 *
 * activate/route.test.ts proves activation is refused while a scan/partial/agent
 * holds the graph. This file proves the converse for each holder: while an
 * activation is swapping the live graph, none of them may start.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const h = vi.hoisted(() => ({
  nodeFilterWriter: vi.fn(async (..._a: unknown[]) => null as string | null),
  activating: vi.fn(),
  isActivating: vi.fn(),
  orchestratorFetch: vi.fn(),
  prepare: vi.fn(),
  createTicket: vi.fn(),
}))

vi.mock('@/lib/activationLock', () => ({
  assertGraphNotActivating: (...a: unknown[]) => h.activating(...a),
  // The scan-start path checks the lock through the shared startFullScan helper,
  // which asks the boolean form.
  isActivationInProgress: async () => h.isActivating(),
}))
vi.mock('@/lib/access', () => ({
  guardProject: async () => null,
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
  requireEffectiveUser: async () => ({ userId: 'owner' }),
}))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'owner' }) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
// "is something already scanning?" is covered in graphWriters.test.ts and
// startFullScan.test.ts; here the graph is free so only the LOCK can refuse.
vi.mock('@/lib/graphWriters', () => ({ describeScanWriters: async () => null }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: (...a: unknown[]) => h.nodeFilterWriter(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: async () => ({ id: 'p1', userId: 'owner', targetDomain: 'x.tld', ipMode: false, targetIps: [] }),
    },
    // TruffleHog starts from a per-source profile; without one the route 404s
    // before the lock has anything to say. A valid docker profile keeps the
    // activation lock the only thing that can refuse the start here.
    trufflehogScanProfile: {
      findFirst: async () => ({ id: 'prof1', source: 'docker', config: { images: ['nginx:1.25'] } }),
      findUnique: async () => ({ id: 'prof1', source: 'docker', config: { images: ['nginx:1.25'] } }),
    },
    userSettings: { findUnique: async () => ({}) },
  },
}))
vi.mock('@/lib/scanTimeline', async orig => ({
  ...(await orig<typeof import('@/lib/scanTimeline')>()),
  prepareVersionsForFullScan: (...a: unknown[]) => h.prepare(...a),
  createScanJob: async () => ({ id: 'job1' }),
}))
vi.mock('@/lib/auth', () => ({ createWsTicket: (...a: unknown[]) => h.createTicket(...a) }))
// GVM/GitHub-Hunt/TruffleHog start routes gate on a recon-output file; make it present
// so the only thing that can refuse them here is the activation lock.
vi.mock('fs', async orig => ({ ...(await orig<typeof import('fs')>()), existsSync: () => true }))
// The old-model graph check has its own tests; here the graph is current.
vi.mock('@/lib/legacyGraph', async orig => ({
  ...(await orig<typeof import('@/lib/legacyGraph')>()),
  legacyGraphDomains: async () => [],
}))
vi.mock('@/lib/orchestratorError', () => ({
  normalizeOrchestratorStartError: (d: { error?: string }, fb: string) => ({ error: d?.error ?? fb }),
}))

import { POST as startScan } from '@/app/api/recon/[projectId]/start/route'
import { POST as startPartial } from '@/app/api/recon/[projectId]/partial/route'
import { POST as wsTicket } from '@/app/api/agent/ws-ticket/route'
import { POST as startGvm } from '@/app/api/gvm/[projectId]/start/route'
import { POST as startGithubHunt } from '@/app/api/github-hunt/[projectId]/start/route'
import { POST as startTrufflehog } from '@/app/api/trufflehog/[projectId]/start/route'

const CONFLICT = () => NextResponse.json(
  { error: 'A version activation is in progress', activationInProgress: true },
  { status: 409 }
)
const params = { params: Promise.resolve({ projectId: 'p1' }) }

beforeEach(() => {
  vi.clearAllMocks()
  h.activating.mockResolvedValue(null)
  h.isActivating.mockReturnValue(false)
  h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'starting' }) })
  h.prepare.mockResolvedValue({ currentVersion: { id: 'v1', seq: 1, label: 'Scan 1' }, frozenVersionId: null, frozenNodeCount: 0 })
  h.createTicket.mockResolvedValue('ticket123')
})

function scanReq() {
  return new NextRequest('http://x/api/recon/p1/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"mode":"new"}',
  })
}
function partialReq() {
  return new NextRequest('http://x/api/recon/p1/partial', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"tool_id":"katana","graph_inputs":{"domains":["alpha.test"]}}',
  })
}
function ticketReq() {
  return new NextRequest('http://x/api/agent/ws-ticket', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: '{"projectId":"p1","sessionId":"s1"}',
  })
}

describe('full scan start', () => {
  test('refused while an activation is swapping the graph', async () => {
    h.isActivating.mockReturnValue(true)
    const res = await startScan(scanReq(), params)
    expect(res.status).toBe(409)
    expect((await res.json()).activationInProgress).toBe(true)
    // Neither a snapshot nor a container spawn may happen.
    expect(h.prepare).not.toHaveBeenCalled()
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('allowed when the graph is free', async () => {
    const res = await startScan(scanReq(), params)
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })
})

describe('partial recon start', () => {
  test('refused while an activation is swapping the graph', async () => {
    h.activating.mockResolvedValue(CONFLICT())
    const res = await startPartial(partialReq(), params)
    expect(res.status).toBe(409)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('allowed when the graph is free', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ run_id: 'r1' }) })
    const res = await startPartial(partialReq(), params)
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })

  test('refused while mute rules are being applied to the graph', async () => {
    h.nodeFilterWriter.mockResolvedValueOnce('mute rules are being applied to the graph')
    const res = await startPartial(partialReq(), params)
    expect(res.status).toBe(409)
    expect((await res.json()).error).toMatch(/mute rules are being applied/)
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })
})

describe('agent session start (ws ticket)', () => {
  test('no ticket is minted while an activation is swapping the graph', async () => {
    h.activating.mockResolvedValue(CONFLICT())
    const res = await wsTicket(ticketReq())
    expect(res.status).toBe(409)
    expect(h.createTicket).not.toHaveBeenCalled()
  })

  test('a ticket is minted when the graph is free', async () => {
    const res = await wsTicket(ticketReq())
    expect(res.status).toBe(200)
    expect((await res.json()).ticket).toBe('ticket123')
  })
})

// GVM / GitHub-Hunt / TruffleHog write finding nodes into the live graph, so they
// must also refuse to start into an in-flight swap (the alignment gap this fixes).
describe.each([
  { name: 'GVM scan', run: startGvm, path: 'gvm' },
  { name: 'GitHub Secret Hunt', run: startGithubHunt, path: 'github-hunt' },
  { name: 'Secret Multiscanner scan', run: startTrufflehog, path: 'trufflehog' },
])('$name start', ({ run, path }) => {
  const req = () => new NextRequest(`http://x/api/${path}/p1/start`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    // TruffleHog is run-keyed: the body names which source to start.
    body: JSON.stringify(path === 'trufflehog' ? { source: 'docker' } : {}),
  })

  test('refused while an activation is swapping the graph', async () => {
    h.activating.mockResolvedValue(CONFLICT())
    const res = await run(req(), params)
    expect(res.status).toBe(409)
    expect((await res.json()).activationInProgress).toBe(true)
    // No spawn request may reach the orchestrator.
    expect(h.orchestratorFetch).not.toHaveBeenCalled()
  })

  test('allowed when the graph is free', async () => {
    h.orchestratorFetch.mockResolvedValue({ ok: true, json: async () => ({ status: 'starting' }) })
    const res = await run(req(), params)
    expect(res.status).toBe(200)
    expect(h.orchestratorFetch).toHaveBeenCalled()
  })
})
