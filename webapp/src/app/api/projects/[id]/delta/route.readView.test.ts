/**
 * GET /api/projects/[id]/delta for a reader below R* (4.9 review, OQ-R7 coverage): the delta is
 * `recon:read` (R), and it answers the nodes added, removed and changed between two versions with
 * their whole properties, a changed node's previous ones, and the overlay. It goes through the same
 * graph read view as the graph itself (`stripStepContent` on both sides before the comparison):
 * step content never reaches a reader below R*, and the OQ-R7 switch reaches the delta too.
 *
 *   - option (b), the pinned choice: chain-step content is stripped, the recon-found secret values
 *     stay;
 *   - option (a): with the helper switched to OQ_R7_OPTION_A (doubled here), the display-only values
 *     and a Secret's matched_text are gone from every part of the answer, and a change in them alone
 *     is no change;
 *   - the owner and a share with Raw data & files read the delta whole.
 *
 * Runs the real route, delta and overlay; the guard answers the access under test, the snapshots
 * and the version selector are doubles.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'

const h = vi.hoisted(() => ({ access: null as unknown, optionA: false }))

vi.mock('@/lib/authz/guards', async (orig) => ({
  ...(await orig<typeof import('@/lib/authz/guards')>()),
  requirePermission: async (_r: unknown, permission: string) => ({ permission, effective: { userId: 'reader' }, access: h.access }),
}))
vi.mock('@/lib/authz/stepContent', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/stepContent')>()
  return {
    ...real,
    stripStepContent: (nodes: Parameters<typeof real.stripStepContent>[0], access: Parameters<typeof real.stripStepContent>[1]) =>
      h.optionA && !real.readsStepContent(access) ? real.withoutRawProps(nodes, real.OQ_R7_OPTION_A) : real.stripStepContent(nodes, access),
  }
})
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: async () => ({ targetDomain: 'rbac.test', subdomainList: [] }) } },
}))
vi.mock('@/lib/scanVersionAccess', async (orig) => ({
  ...(await orig<typeof import('@/lib/scanVersionAccess')>()),
  resolveVersionSelector: async (_pid: string, sel: string | null) => (!sel || sel === 'current'
    ? { current: true }
    : { id: 'v1', projectId: 'p1', seq: 1, label: 'Scan 1', isCurrent: false, pinned: false, nodeCount: 3, linkCount: 1, createdAt: new Date(), hasSnapshot: true }),
}))
vi.mock('@/lib/graphWriters', () => ({ describeLiveGraphWriters: async () => null }))

const STEP_BEFORE = { thought: 'rbac-fake-thought-1', tool_args_summary: 'curl -u admin:rbac-fake-pass http://app.rbac.test' }
const STEP_AFTER = { thought: 'rbac-fake-thought-2', tool_args_summary: 'curl -u admin:rbac-fake-pass2 http://app.rbac.test' }
const SECRET_BEFORE = { secret_value: 'rbac-fake-secret-1', matched_text: 'key = "rbac-fake-secret-1"', raw_context: 'k=rbac-fake-secret-1' }
const SECRET_AFTER = { secret_value: 'rbac-fake-secret-2', matched_text: 'key = "rbac-fake-secret-2"', raw_context: 'k=rbac-fake-secret-2' }

const secret = (values: Record<string, string>, severity: string) =>
  ({ labels: ['Secret'], properties: { id: 'sec-1', masked_url: 'https://app.rbac.test/main.js', secret_type: 'api_key', sample: 'rbac…', severity, ...values } })
const step = (content: Record<string, string>) =>
  ({ labels: ['ChainStep'], properties: { step_id: 'st-1', iteration: 1, tool_name: 'curl', ...content } })
const ip = (address: string) => ({ labels: ['IP'], properties: { address } })

vi.mock('@/lib/scanSnapshot', async (orig) => ({
  ...(await orig<typeof import('@/lib/scanSnapshot')>()),
  loadSnapshot: async () => ({
    nodes: [
      { ...secret(SECRET_BEFORE, 'low'), _exportId: 'n1' },
      { ...step(STEP_BEFORE), _exportId: 'n2' },
      { ...ip('10.0.0.1'), _exportId: 'n3' },
      { labels: ['Secret'], properties: { id: 'sec-gone', masked_url: 'https://app.rbac.test/old.js', secret_type: 'token', ...SECRET_BEFORE }, _exportId: 'n4' },
    ],
    relationships: [{ type: 'STEP_TARGETED', startExportId: 'n2', endExportId: 'n3', properties: {} }],
  }),
  captureGraphSnapshot: async () => ({
    nodes: [
      { ...secret(SECRET_AFTER, 'high'), _exportId: 'x1' },
      { ...step(STEP_AFTER), _exportId: 'x2' },
      { ...ip('10.0.0.2'), _exportId: 'x3' },
      { labels: ['Secret'], properties: { id: 'sec-new', masked_url: 'https://app.rbac.test/new.js', secret_type: 'token', ...SECRET_AFTER }, _exportId: 'x4' },
    ],
    relationships: [],
    nodeCount: 4, linkCount: 0, summary: {},
    liveNodeIds: new Map([['x1', '101'], ['x2', '102'], ['x3', '103'], ['x4', '104']]),
  }),
}))

import { GET } from './route'

const access = (level: string, rawData: boolean, via: string) => ({ project: { id: 'p1', userId: 'alice' }, level, toggles: { rawData }, via })
const READER = access('read', false, 'share')
const OVERSEER = access('read', false, 'oversight')

type DeltaNode = { key: string; type: string; properties: Record<string, unknown>; previousProperties?: Record<string, unknown> }

async function delta(): Promise<{ addedNodes: DeltaNode[]; removedNodes: DeltaNode[]; changedNodes: DeltaNode[]; overlay: { nodes: DeltaNode[] } }> {
  const res = await GET(new NextRequest('http://localhost:3000/api/projects/p1/delta?from=v1&to=current&overlay=1'), { params: Promise.resolve({ id: 'p1' }) })
  expect(res.status).toBe(200)
  return res.json()
}
const changedOf = (body: Awaited<ReturnType<typeof delta>>, type: string) => body.changedNodes.find(n => n.type === type)

beforeEach(() => {
  h.optionA = false
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('the delta below R*: step content never, on every part of the answer', () => {
  test.each([['a read share without Raw data', READER], ['an overseer', OVERSEER]])('%s: no chain-step content in nodes, previous properties or overlay', async (_who, a) => {
    h.access = a
    const body = await delta()
    expect(JSON.stringify(body)).not.toMatch(/rbac-fake-(thought|pass)/)
    // A change in the step's content alone is no change for a reader who may not read it.
    expect(changedOf(body, 'ChainStep')).toBeUndefined()
    const overlayStep = body.overlay.nodes.find(n => n.type === 'ChainStep')!
    expect(overlayStep.properties).toMatchObject({ step_id: 'st-1', tool_name: 'curl' })
    expect(overlayStep.properties).not.toHaveProperty('thought')
  })

  test('option (b), the pinned choice: the recon-found secret values and the full match stay', async () => {
    h.access = READER
    const body = await delta()
    const changed = changedOf(body, 'Secret')!
    expect(changed.properties).toMatchObject({ secret_value: 'rbac-fake-secret-2', matched_text: 'key = "rbac-fake-secret-2"' })
    expect(changed.previousProperties).toMatchObject({ secret_value: 'rbac-fake-secret-1' })
  })
})

describe('OQ-R7 option (a) reaches the delta (the helper switched to OQ_R7_OPTION_A)', () => {
  test.each([['a read share without Raw data', READER], ['an overseer', OVERSEER]])('%s: no secret value or matched_text in added, removed, changed, previous or overlay', async (_who, a) => {
    h.access = a
    h.optionA = true
    const body = await delta()
    expect(JSON.stringify(body)).not.toMatch(/rbac-fake/)
    const changed = changedOf(body, 'Secret')!
    expect(changed.properties).toMatchObject({ severity: 'high', sample: 'rbac…' })
    expect(changed.previousProperties).toMatchObject({ severity: 'low' })
    expect(body.addedNodes.some(n => n.type === 'Secret')).toBe(true)
    expect(body.removedNodes.some(n => n.type === 'Secret')).toBe(true)
  })
})

describe('the delta at R*', () => {
  test.each([['the owner', access('owner', true, 'owner')], ['a share with Raw data & files', access('read', true, 'share')]])('%s: whole', async (_who, a) => {
    h.access = a
    h.optionA = true
    const body = await delta()
    expect(changedOf(body, 'ChainStep')!.properties).toMatchObject(STEP_AFTER)
    expect(changedOf(body, 'ChainStep')!.previousProperties).toMatchObject(STEP_BEFORE)
    expect(changedOf(body, 'Secret')!.properties).toMatchObject(SECRET_AFTER)
  })
})
