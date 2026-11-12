/**
 * S-4: a full-scan start, a partial-recon start, "save current as a version" and
 * a version activation hold one per-project lock (projectGraphLock.ts).
 *
 * Each path checks the others before it acts: the start checks the activation
 * row, then freezes, rotates and calls the orchestrator; activation asks the
 * orchestrator whether a scan runs, then takes its row lock; save-version checks
 * both, then freezes and rotates. A check holds only until the next await, so
 * each path holds the lock from its check through its last write.
 *
 * The real startFullScan, prepareVersionsForFullScan / rotateToNextVersion, the
 * activation route, the save-version route, the partial-recon route and the
 * queue's dispatchStart, the activation lock and the writer checks run here.
 * Only I/O is faked: Postgres (an in-memory row store), Neo4j (one array of
 * nodes) and the orchestrator (an idle project until a start is posted). Gates
 * hold one path between its check and its act while the other runs, which is
 * the window a real freeze of a large graph (seconds) leaves open.
 *
 * The control cases pin that the harness drives the real guards: run one after
 * the other, a pair either refuses or leaves the timeline consistent. The S-4
 * cases interleave them; they failed before the paths shared the lock.
 *
 * The GVM, GitHub-hunt, TruffleHog, supply-chain and AI-attack-surface starts
 * (their routes and their dispatchStart kinds) run here too: each writes
 * findings into the live graph, so each raced an activation and a save the same
 * way the partial recon did.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import type { NextRequest } from 'next/server'

type Node = { labels: string[]; properties: Record<string, unknown>; _exportId: string }
type Version = {
  id: string; projectId: string; seq: number; label: string; isCurrent: boolean; pinned: boolean
  nodeCount: number | null; linkCount: number | null; summary: unknown; snapshot: Uint8Array | null
  createdAt: Date
}

const w = vi.hoisted(() => ({
  project: {} as Record<string, unknown>,
  versions: [] as Version[],
  graph: [] as Node[],
  scanRunning: false,
  partialRunning: false,
  /** The other scanners the orchestrator accepted a start for, by URL segment. */
  othersRunning: new Set<string>(),
  startsWhileActivating: 0,
  restoring: false,
  engagementHold: Promise.resolve() as Promise<unknown>,
  engagementReached: false,
  saveBodyReached: false,
  swapHold: Promise.resolve() as Promise<unknown>,
  captureHolds: [] as Array<Promise<unknown>>,
  jobs: 0,
}))

const fakePrisma = vi.hoisted(() => {
  const matches = (row: Record<string, unknown>, where: Record<string, unknown> = {}) =>
    Object.entries(where).every(([k, v]) => v === undefined || row[k] === v)
  const client = {
    project: {
      findUnique: async () => ({ ...w.project }),
      // acquireActivationLock's conditional UPDATE: idle, never stamped, or stale.
      updateMany: async ({ where, data }: { where: { id: string; OR: Array<Record<string, unknown>> }; data: Record<string, unknown> }) => {
        const row = w.project
        if (where.id !== row.id) return { count: 0 }
        const free = where.OR.some(c => {
          if ('activationState' in c) return row.activationState === c.activationState
          const cond = c.activationStartedAt as null | { lt: Date }
          if (cond === null) return row.activationStartedAt === null
          return row.activationStartedAt instanceof Date && row.activationStartedAt < cond.lt
        })
        if (!free) return { count: 0 }
        Object.assign(row, data)
        return { count: 1 }
      },
      update: async ({ data }: { data: Record<string, unknown> }) => {
        Object.assign(w.project, data)
        return { ...w.project }
      },
    },
    scanVersion: {
      findFirst: async ({ where, orderBy }: { where: Record<string, unknown>; orderBy?: { seq: 'desc' } }) => {
        const rows = w.versions.filter(v => matches(v, where))
        if (orderBy) rows.sort((a, b) => b.seq - a.seq)
        return rows[0] ? { ...rows[0] } : null
      },
      findUnique: async ({ where }: { where: { id: string } }) => {
        const row = w.versions.find(v => v.id === where.id)
        return row ? { ...row } : null
      },
      update: async ({ where, data }: { where: { id: string }; data: Partial<Version> }) => {
        const row = w.versions.find(v => v.id === where.id)
        if (!row) throw Object.assign(new Error('Record to update not found'), { code: 'P2025' })
        Object.assign(row, data)
        return { ...row }
      },
      updateMany: async ({ where, data }: { where: Record<string, unknown>; data: Partial<Version> }) => {
        const rows = w.versions.filter(v => matches(v, where))
        for (const r of rows) Object.assign(r, data)
        return { count: rows.length }
      },
      create: async ({ data }: { data: Partial<Version> & { projectId: string; seq: number } }) => {
        if (w.versions.some(v => v.projectId === data.projectId && v.seq === data.seq)) {
          throw Object.assign(new Error('Unique constraint failed'), { code: 'P2002' })
        }
        const row: Version = {
          id: `v${data.seq}`, projectId: data.projectId, seq: data.seq, label: data.label ?? '',
          isCurrent: !!data.isCurrent, pinned: false, nodeCount: null, linkCount: null,
          summary: null, snapshot: null, createdAt: new Date(),
        }
        w.versions.push(row)
        return { ...row }
      },
      delete: async ({ where }: { where: { id: string } }) => {
        w.versions = w.versions.filter(v => v.id !== where.id)
        return {}
      },
    },
    scanJob: { create: async () => ({ id: `job${++w.jobs}` }) },
    // A filesystem source needs no target and no credential.
    trufflehogScanProfile: {
      findFirst: async () => ({ id: 'prof1', source: 'filesystem', config: {} }),
      findUnique: async () => ({ id: 'prof1', source: 'filesystem', config: {} }),
    },
    userSettings: { findUnique: async () => null },
    $transaction: async (fn: (tx: unknown) => unknown) => fn(client),
  }
  return client
})

vi.mock('@/lib/prisma', () => ({ default: fakePrisma }))

vi.mock('@/lib/orchestrator', () => ({
  orchestratorFetch: async (url: string, init?: { method?: string }) => {
    const reply = (body: unknown) => ({ ok: true, status: 200, json: async () => body })
    if (init?.method === 'POST' && url.endsWith('/recon/p1/start')) {
      if (w.project.activationState === 'activating') w.startsWhileActivating += 1
      w.scanRunning = true
      return reply({ project_id: 'p1', status: 'starting' })
    }
    if (init?.method === 'POST' && url.endsWith('/recon/p1/partial')) {
      if (w.project.activationState === 'activating') w.startsWhileActivating += 1
      w.partialRunning = true
      return reply({ run_id: 'r1', status: 'starting', roots: ['example.com'] })
    }
    const other = /\/(gvm|github-hunt|supply-chain|trufflehog|ai-attack-surface)\/p1\/start$/.exec(url)
    if (init?.method === 'POST' && other) {
      if (w.project.activationState === 'activating') w.startsWhileActivating += 1
      w.othersRunning.add(other[1])
      return reply({ run_id: 'r2', status: 'starting' })
    }
    if (url.endsWith('/recon/p1/status')) return reply({ status: w.scanRunning ? 'running' : 'idle' })
    if (url.endsWith('/recon/p1/partial/all')) {
      return reply({ runs: w.partialRunning ? [{ run_id: 'r1', status: 'running' }] : [] })
    }
    const status = /\/(gvm|github-hunt|supply-chain)\/p1\/status$/.exec(url)
    if (status) return reply({ status: w.othersRunning.has(status[1]) ? 'running' : 'idle' })
    const runs = /\/(trufflehog|ai-attack-surface)\/p1\/all$/.exec(url)
    if (runs) return reply({ runs: w.othersRunning.has(runs[1]) ? [{ run_id: 'r2', status: 'running' }] : [] })
    if (url.endsWith('/all')) return reply({ runs: [] })
    return reply({ status: 'idle' })
  },
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: async () => ({ userId: 'owner' }),
  requireProjectAccess: async () => ({ project: { id: 'p1', userId: 'owner' } }),
  guardProject: async () => null,
}))
vi.mock('@/lib/session', () => ({ getEffectiveUser: async () => ({ userId: 'owner' }) }))
vi.mock('@/lib/scanVersionAccess', () => ({
  requireVersionInProject: async (_projectId: string, versionId: string) => {
    const row = w.versions.find(v => v.id === versionId)!
    return { ...row, hasSnapshot: !!row.snapshot }
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: async () => undefined }))
vi.mock('@/lib/scanRetention', () => ({ applyRetentionSafe: async () => null }))
vi.mock('@/lib/nodeFilterRun', () => ({ describeNodeFilterWriter: async () => null }))
vi.mock('@/lib/triageRun', () => ({ findLiveTriageRun: async () => null }))
vi.mock('@/lib/agentSessions', () => ({
  checkAgentSessions: async () => 'idle',
  describeAgentSessionState: () => null,
}))
// Every start reads the engagement after its activation and writer checks and
// before it freezes or calls the orchestrator: holding it here parks the start
// inside its window.
vi.mock('@/lib/engagement', async orig => ({
  ...(await orig<typeof import('@/lib/engagement')>()),
  loadEngagement: async () => {
    w.engagementReached = true
    await w.engagementHold
    return { blockers: [], warnings: [], documentTextSha256: null }
  },
  currentAuthorization: async () => null,
}))
// The GVM and GitHub-hunt buttons refuse a project without a recon output file.
vi.mock('fs', async orig => {
  const real = await orig<typeof import('fs')>()
  const existsSync = (p: import('fs').PathLike) => String(p).endsWith('/recon_p1.json') || real.existsSync(p)
  return { ...real, default: { ...real, existsSync }, existsSync }
})
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: () => ({ run: async () => ({ records: [] }), close: async () => undefined }) }))
vi.mock('@/app/api/graph/cache', () => ({ invalidateCache: () => undefined }))
// Neo4j: the capture reads whatever the live graph holds when it runs, inside
// the real snapshot semaphore (a cross-project cap, not a project lock).
vi.mock('@/lib/scanSnapshot', async orig => {
  const real = await orig<typeof import('@/lib/scanSnapshot')>()
  return {
    ...real,
    captureGraphSnapshot: async () => {
      const hold = w.captureHolds.shift()
      if (hold) await hold
      return real.withSnapshotSlot(async () => {
        const nodes = w.graph.map(n => ({ ...n }))
        return { nodes, relationships: [], nodeCount: nodes.length, linkCount: 0, summary: {}, liveNodeIds: new Map() }
      })
    },
  }
})
// The activation's restore writes the target in two halves; `swapHold` parks it
// half-way, which is where a concurrent reader or writer does its damage.
vi.mock('@/lib/graphRestore', () => ({
  clearProjectGraph: async () => { w.graph = [] },
  restoreGraph: async (_s: unknown, nodes: Node[]) => {
    w.restoring = true
    w.graph = nodes.slice(0, Math.ceil(nodes.length / 2))
    await w.swapHold
    w.graph = nodes.map(n => ({ ...n }))
    w.restoring = false
    return { nodes: nodes.length, relationships: 0 }
  },
  sweepOrphanReferenceNodes: async () => undefined,
}))

import { startFullScan } from './startFullScan'
import { serializeSnapshot, deserializeSnapshot } from './scanSnapshot'
import { POST as activateRoute } from '@/app/api/projects/[id]/versions/[versionId]/activate/route'
import { POST as saveVersionRoute } from '@/app/api/projects/[id]/versions/route'
import { POST as partialRoute } from '@/app/api/recon/[projectId]/partial/route'
import { POST as gvmRoute } from '@/app/api/gvm/[projectId]/start/route'
import { POST as githubHuntRoute } from '@/app/api/github-hunt/[projectId]/start/route'
import { POST as trufflehogRoute } from '@/app/api/trufflehog/[projectId]/start/route'
import { POST as supplyChainRoute } from '@/app/api/supply-chain/[projectId]/start/route'
import { POST as aiAttackRoute } from '@/app/api/ai-attack-surface/[projectId]/start/route'
import { dispatchStart, type DispatchStartResult } from './startScan'

const graphOf = (prefix: string, n: number): Node[] =>
  Array.from({ length: n }, (_, i) => ({
    labels: ['Subdomain'], properties: { name: `${prefix}-${i}.example.com`, project_id: 'p1' }, _exportId: `${prefix}${i}`,
  }))
const V1_GRAPH = graphOf('v1', 4)
const V2_GRAPH = graphOf('v2', 3)
const names = (nodes: Node[]) => nodes.map(n => n.properties.name)
const storedNames = (id: string) => {
  const row = w.versions.find(v => v.id === id)
  return row?.snapshot ? names(deserializeSnapshot(row.snapshot).nodes as Node[]) : null
}
const currentVersions = () => w.versions.filter(v => v.isCurrent).map(v => v.id)

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(r => { resolve = r })
  return { promise, resolve }
}

/** Never throws: a gate a fixed lock never reaches must not hang or fail the run. */
async function until(pred: () => boolean, ms = 500): Promise<boolean> {
  const end = Date.now() + ms
  while (!pred() && Date.now() < end) await new Promise(r => setTimeout(r, 2))
  return pred()
}

function track<T>(p: Promise<T>) {
  const t = { done: false, promise: p }
  p.then(() => { t.done = true }, () => { t.done = true })
  return t
}

const activate = () => activateRoute(
  {} as NextRequest, { params: Promise.resolve({ id: 'p1', versionId: 'v1' }) })
const saveVersion = (body: Promise<unknown> = Promise.resolve()) => saveVersionRoute(
  { json: async () => { w.saveBodyReached = true; await body; return {} } } as unknown as NextRequest,
  { params: Promise.resolve({ id: 'p1' }) })
const start = () => startFullScan({ projectId: 'p1', mode: 'new', trigger: 'manual' })
const PARTIAL_BODY = { tool_id: 'Naabu', graph_inputs: {}, user_inputs: [] }
/** The partial-recon start's two entry points, answering whether it was accepted. */
const partialStarts: Array<[string, () => Promise<boolean>]> = [
  ['the button', async () => (await partialRoute(
    { json: async () => PARTIAL_BODY } as unknown as NextRequest,
    { params: Promise.resolve({ projectId: 'p1' }) })).status === 200],
  ['the queue', async () => (await dispatchStart('partial_recon', 'p1', { payload: PARTIAL_BODY })).ok],
]

type StartAnswer = { accepted: boolean; status: number; busy?: string }
const fromRoute = async (res: Response): Promise<StartAnswer> => {
  const body = (await res.json().catch(() => ({}))) as { busy?: unknown }
  return { accepted: res.status === 200, status: res.status, ...(typeof body.busy === 'string' ? { busy: body.busy } : {}) }
}
const fromQueue = (r: DispatchStartResult): StartAnswer =>
  ({ accepted: r.ok, status: r.status, ...(r.busy ? { busy: r.busy } : {}) })
const routeArgs = (body: unknown = {}) => [
  { json: async () => body } as unknown as NextRequest,
  { params: Promise.resolve({ projectId: 'p1' }) },
] as const
const AI_BODY = { tool: 'garak', targets: [] }
/**
 * The other scanners' starts, from the button and from the queue, with the
 * phrase the activation's writer check names once the orchestrator has the run.
 */
const otherStarts: Array<[string, () => Promise<StartAnswer>, string]> = [
  ['GVM from the button', async () => fromRoute(await gvmRoute(...routeArgs())), 'a GVM vulnerability scan is running'],
  ['GVM from the queue', async () => fromQueue(await dispatchStart('gvm', 'p1')), 'a GVM vulnerability scan is running'],
  ['the GitHub hunt from the button', async () => fromRoute(await githubHuntRoute(...routeArgs())), 'a GitHub Secret Hunt is running'],
  ['the GitHub hunt from the queue', async () => fromQueue(await dispatchStart('github_hunt', 'p1')), 'a GitHub Secret Hunt is running'],
  ['TruffleHog from the button', async () => fromRoute(await trufflehogRoute(...routeArgs({ source: 'filesystem' }))),
    'a Secret Multiscanner scan is running'],
  ['TruffleHog from the queue', async () => fromQueue(await dispatchStart('trufflehog', 'p1', { payload: { source: 'filesystem' } })),
    'a Secret Multiscanner scan is running'],
  ['the supply-chain scan from the button', async () => fromRoute(await supplyChainRoute(...routeArgs())), 'a supply-chain scan is running'],
  ['the supply-chain scan from the queue', async () => fromQueue(await dispatchStart('supply_chain', 'p1')), 'a supply-chain scan is running'],
  ['an org-batch supply-chain item from the queue', async () => fromQueue(await dispatchStart('supply_chain_repo', 'p1', {
    payload: { repo_url: 'https://github.com/example/app' } })), 'a supply-chain scan is running'],
  ['the AI attack surface from the button', async () => fromRoute(await aiAttackRoute(...routeArgs(AI_BODY))),
    'an AI attack-surface scan is running'],
  ['the AI attack surface from the queue', async () => fromQueue(await dispatchStart('ai_attack', 'p1', { payload: AI_BODY })),
    'an AI attack-surface scan is running'],
]

beforeEach(() => {
  w.project = {
    id: 'p1', userId: 'owner', targetDomain: 'example.com', ipMode: false, targetIps: [],
    domainBatchMode: false, domainBatchHosts: [], subdomainList: [],
    supplyChainInputMode: 'upload', supplyChainSbomFile: 'package-lock.json',
    activationState: 'idle', activationStartedAt: null, activationVersionId: null,
  }
  const at = new Date('2026-11-01T00:00:00Z')
  w.versions = [
    { id: 'v1', projectId: 'p1', seq: 1, label: 'Scan 1', isCurrent: false, pinned: false, nodeCount: 4,
      linkCount: 0, summary: null, createdAt: at,
      snapshot: new Uint8Array(serializeSnapshot({ nodes: V1_GRAPH, relationships: [] })) },
    { id: 'v2', projectId: 'p1', seq: 2, label: 'Scan 2', isCurrent: true, pinned: false, nodeCount: 3,
      linkCount: 0, summary: null, createdAt: at, snapshot: null },
  ]
  w.graph = V2_GRAPH.map(n => ({ ...n }))
  w.scanRunning = false
  w.partialRunning = false
  w.othersRunning = new Set()
  w.startsWhileActivating = 0
  w.restoring = false
  w.engagementHold = Promise.resolve()
  w.engagementReached = false
  w.saveBodyReached = false
  w.swapHold = Promise.resolve()
  w.captureHolds = []
  w.jobs = 0
  vi.spyOn(console, 'info').mockImplementation(() => undefined)
  vi.spyOn(console, 'warn').mockImplementation(() => undefined)
  vi.spyOn(console, 'error').mockImplementation(() => undefined)
})

describe('control: one after the other, every pair refuses (the real guards, the faked I/O)', () => {
  test('a start that arrives while an activation swaps the graph is refused', async () => {
    const swap = deferred()
    w.swapHold = swap.promise
    const act = track(activate())
    expect(await until(() => w.restoring)).toBe(true)

    const res = await start()
    expect(res.ok).toBe(false)
    expect(res.ok === false && res.activationInProgress).toBe(true)
    expect(w.scanRunning).toBe(false)

    swap.resolve()
    expect((await act.promise).status).toBe(200)
    expect(currentVersions()).toEqual(['v1'])
  })

  test('an activation after a start the orchestrator accepted is refused', async () => {
    expect((await start()).ok).toBe(true)
    const res = await activate()
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe('a full recon scan is running')
  })

  test('a save-version that arrives while an activation swaps the graph is refused', async () => {
    const swap = deferred()
    w.swapHold = swap.promise
    const act = track(activate())
    expect(await until(() => w.restoring)).toBe(true)

    expect((await saveVersion()).status).toBe(409)

    swap.resolve()
    await act.promise
    expect(storedNames('v2')).toEqual(names(V2_GRAPH))
  })

  test('a save-version and a start one after the other leave exactly one current version', async () => {
    expect((await saveVersion()).status).toBe(200)
    expect((await start()).ok).toBe(true)
    expect(currentVersions()).toHaveLength(1)
  })

  test.each(partialStarts)('an activation after a partial recon %s started is refused', async (_via, startPartial) => {
    expect(await startPartial()).toBe(true)
    const res = await activate()
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe('a partial recon run is active')
  })

  test.each(otherStarts)('%s starts on a free graph, and an activation after it is refused', async (_via, startOther, writer) => {
    expect(await startOther()).toEqual({ accepted: true, status: 200 })
    expect(w.othersRunning.size).toBe(1)
    const res = await activate()
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe(writer)
  })
})

describe('S-4: interleaved, the start, save-version and activation hold one project lock', () => {
  // Without the lock, a start that passed its activation check goes on to
  // freeze a half-restored graph into the outgoing version, rotate, and ask the
  // orchestrator for a scan that wipes the graph the activation is restoring;
  // the activation then makes v1 current and drops its stored bytes, so the
  // scan destroys v1 as well. With it, the activation is refused.
  test('a start never reaches the orchestrator while an activation swaps the graph', async () => {
    const engagement = deferred()
    const swap = deferred()
    w.engagementHold = engagement.promise
    w.swapHold = swap.promise

    const scan = track(start())
    await until(() => w.engagementReached || scan.done)
    const act = track(activate())
    await until(() => w.restoring || act.done)
    engagement.resolve()
    await until(() => scan.done)
    swap.resolve()
    await Promise.all([scan.promise, act.promise])

    expect(w.startsWhileActivating).toBe(0)
    expect(storedNames('v2')).toEqual(names(V2_GRAPH))
  })

  // Without the lock, save-version checked the activation row before the
  // activation took it, then captured mid-swap and stored that half-restored
  // graph over the bytes the activation had just frozen for the outgoing version.
  test('a save-version never overwrites the outgoing version with a half-swapped graph', async () => {
    const body = deferred()
    const swap = deferred()
    w.swapHold = swap.promise

    const save = track(saveVersion(body.promise))
    await until(() => w.saveBodyReached || save.done)
    const act = track(activate())
    await until(() => w.restoring || act.done)
    body.resolve()
    await until(() => save.done)
    swap.resolve()
    await Promise.all([save.promise, act.promise])

    expect(storedNames('v2')).toEqual(names(V2_GRAPH))
  })

  // Without the lock, both read v2 as current, both demote it, and each mints
  // its own current version: the "exactly one current per project" invariant
  // breaks, and the version the scan reports populating is not the live graph.
  test('a save-version racing a start leaves exactly one current version', async () => {
    const body = deferred()
    const startCapture = deferred()
    w.captureHolds = [startCapture.promise]

    const save = track(saveVersion(body.promise))
    await until(() => w.saveBodyReached || save.done)
    const scan = track(start())
    await until(() => scan.done || w.captureHolds.length === 0)
    body.resolve()
    await until(() => save.done)
    startCapture.resolve()
    await Promise.all([save.promise, scan.promise])

    expect(currentVersions()).toHaveLength(1)
  })

  // Without the lock, a partial recon that passed its activation check went on
  // to ask the orchestrator for a run that writes into the graph the activation
  // is half-way through restoring.
  test.each(partialStarts)('a partial recon from %s never reaches the orchestrator while an activation swaps the graph', async (_via, startPartial) => {
    const engagement = deferred()
    const swap = deferred()
    w.engagementHold = engagement.promise
    w.swapHold = swap.promise

    const partial = track(startPartial())
    await until(() => w.engagementReached || partial.done)
    const act = track(activate())
    await until(() => w.restoring || act.done)
    engagement.resolve()
    await until(() => partial.done)
    swap.resolve()
    await Promise.all([partial.promise, act.promise])

    expect(w.startsWhileActivating).toBe(0)
    expect(await partial.promise).toBe(true)
    expect((await act.promise).status).toBe(409)
  })

  test('a start that arrives while a save-version holds the lock is refused as busy, before any freeze', async () => {
    const body = deferred()
    const save = track(saveVersion(body.promise))
    await until(() => w.saveBodyReached || save.done)

    const res = await start()
    expect(res).toMatchObject({ ok: false, status: 409, busy: 'the current graph is being saved as a version' })
    expect(w.scanRunning).toBe(false)

    body.resolve()
    expect((await save.promise).status).toBe(200)
    expect(currentVersions()).toEqual(['v3'])
  })

  // Without the lock, the start passed its activation check, the activation's
  // writer check found no scan yet, and the start then asked the orchestrator
  // for a run that writes findings into the half-restored graph.
  test.each(otherStarts)('%s never reaches the orchestrator while an activation swaps the graph', async (_via, startOther) => {
    const engagement = deferred()
    const swap = deferred()
    w.engagementHold = engagement.promise
    w.swapHold = swap.promise

    const scan = track(startOther())
    await until(() => w.engagementReached || scan.done)
    const act = track(activate())
    await until(() => w.restoring || act.done)
    engagement.resolve()
    await until(() => scan.done)
    swap.resolve()
    await Promise.all([scan.promise, act.promise])

    expect(w.startsWhileActivating).toBe(0)
    expect(await scan.promise).toEqual({ accepted: true, status: 200 })
    const res = await act.promise
    expect(res.status).toBe(409)
    expect((await res.json()).busy).toBe('a scan is being started')
  })

  // Without the lock, the save's writer check found nothing running and the
  // scan then wrote findings into the graph the save was freezing.
  test.each(otherStarts)('%s is refused as busy while a save-version holds the lock', async (_via, startOther) => {
    const body = deferred()
    const save = track(saveVersion(body.promise))
    await until(() => w.saveBodyReached || save.done)

    expect(await startOther()).toEqual({
      accepted: false, status: 409, busy: 'the current graph is being saved as a version',
    })
    expect(w.othersRunning.size).toBe(0)

    body.resolve()
    expect((await save.promise).status).toBe(200)
  })
})
