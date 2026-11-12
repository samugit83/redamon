/**
 * Scan Timeline — export/import round-trip (plan Section 9).
 *
 * History must survive a project round-trip, but importing must never resurrect
 * dangerous state: ids are regenerated and remapped, everything is re-owned under
 * the importing user, an in-flight run becomes `canceled`, and — the one that
 * matters operationally — an imported SCHEDULE arrives DISABLED, so importing a
 * project can never silently start scanning someone's target on the old cadence.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest } from 'next/server'
import JSZip from 'jszip'
import { gzipSync } from 'zlib'

const h = vi.hoisted(() => ({
  projectCreate: vi.fn(),
  versionCreate: vi.fn(),
  scheduleCreate: vi.fn(),
  jobCreate: vi.fn(),
  jobQueueCreate: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overEffectiveUser()))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: vi.fn().mockResolvedValue({ userId: 'importer' }),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: { create: (...a: unknown[]) => h.projectCreate(...a) },
    scanVersion: { create: (...a: unknown[]) => h.versionCreate(...a) },
    scanSchedule: { create: (...a: unknown[]) => h.scheduleCreate(...a) },
    scanJob: { create: (...a: unknown[]) => h.jobCreate(...a) },
    jobQueue: { create: (...a: unknown[]) => h.jobQueueCreate(...a) },
    conversation: { create: vi.fn() },
    chatMessage: { createMany: vi.fn() },
    remediation: { createMany: vi.fn() },
    report: { create: vi.fn() },
    userProjectPreset: { create: vi.fn() },
  },
}))
vi.mock('@/app/api/graph/neo4j', () => ({ getGraphSession: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/graphRestore', () => ({ clearProjectGraph: vi.fn(), restoreGraph: vi.fn() }))

import { POST } from './route'

const SNAPSHOT = gzipSync(Buffer.from(JSON.stringify({
  nodes: [{ labels: ['IP'], properties: { address: '10.0.0.1' }, _exportId: 'n1' }],
  relationships: [],
})))

async function exportZip(): Promise<File> {
  const zip = new JSZip()
  zip.file('manifest.json', JSON.stringify({ version: '1.0.0', projectName: 'src', stats: {} }))
  zip.file('project.json', JSON.stringify({ id: 'oldProject', userId: 'oldOwner', name: 'src', targetDomain: 'x.tld' }))
  zip.file('timeline/versions.json', JSON.stringify([
    {
      id: 'oldV1', seq: 1, label: 'Scan 1', isCurrent: false, pinned: true,
      nodeCount: 10, linkCount: 4, summary: { IP: 10 },
      snapshotBase64: SNAPSHOT.toString('base64'),
    },
    {
      id: 'oldV2', seq: 2, label: 'Scan 2', isCurrent: true, pinned: false,
      nodeCount: 12, linkCount: 5, summary: { IP: 12 }, snapshotBase64: null,
    },
  ]))
  zip.file('timeline/schedules.json', JSON.stringify([
    {
      id: 'oldS1', label: 'nightly', mode: 'cron', runAt: null, intervalMinutes: null,
      cronExpr: '0 3 * * *', scanMode: 'new', enabled: true,
      nextRunAt: '2026-08-01T03:00:00.000Z', lastRunAt: '2026-07-30T03:00:00.000Z',
      estimatedEnvelopeBytes: '2147483648',
    },
  ]))
  zip.file('timeline/jobs.json', JSON.stringify([
    { id: 'oldJ1', versionId: 'oldV1', scheduleId: 'oldS1', trigger: 'scheduled', mode: 'new',
      status: 'completed', startedAt: '2026-07-30T03:00:00.000Z', finishedAt: '2026-07-30T03:20:00.000Z',
      nodeCount: 10, ramReason: null },
    { id: 'oldJ2', versionId: 'oldV2', scheduleId: null, trigger: 'manual', mode: 'new',
      status: 'running', startedAt: '2026-07-30T09:00:00.000Z', finishedAt: null,
      nodeCount: null, ramReason: null },
  ]))
  const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
  return new File([buf], 'export.zip', { type: 'application/zip' })
}

function formReq(file: File): NextRequest {
  const fd = new FormData()
  fd.set('file', file)
  return new NextRequest('http://localhost:3000/api/projects/import', { method: 'POST', body: fd })
}

beforeEach(() => {
  vi.clearAllMocks()
  h.projectCreate.mockResolvedValue({ id: 'newProject', name: 'src' })
  let v = 0
  h.versionCreate.mockImplementation(async () => ({ id: `newV${++v}` }))
  h.scheduleCreate.mockImplementation(async () => ({ id: 'newS1' }))
  h.jobCreate.mockResolvedValue({ id: 'newJ' })
  h.jobQueueCreate.mockResolvedValue({ id: 'newJQ' })
})

describe('import — Scan Timeline history', () => {
  test('recreates versions under the new project with their snapshot bytes', async () => {
    const res = await POST(formReq(await exportZip()))
    expect(res.status).toBe(200)

    expect(h.versionCreate).toHaveBeenCalledTimes(2)
    const first = h.versionCreate.mock.calls[0][0].data
    expect(first).toMatchObject({
      projectId: 'newProject', seq: 1, label: 'Scan 1', isCurrent: false, pinned: true, nodeCount: 10,
    })
    expect(Buffer.from(first.snapshot).equals(SNAPSHOT)).toBe(true)

    // The current version keeps being current, with no bytes (it IS the live graph).
    const second = h.versionCreate.mock.calls[1][0].data
    expect(second).toMatchObject({ seq: 2, isCurrent: true, snapshot: null })
  })

  test('an imported schedule is DISABLED and unscheduled', async () => {
    await POST(formReq(await exportZip()))
    const data = h.scheduleCreate.mock.calls[0][0].data
    expect(data).toMatchObject({
      projectId: 'newProject',
      userId: 'importer',        // re-owned, never the exporting user
      cronExpr: '0 3 * * *',
      enabled: false,            // must not resume scanning on import
      nextRunAt: null,
    })
    expect(data.estimatedEnvelopeBytes).toBe(BigInt('2147483648'))
  })

  test('jobs are remapped to the NEW version and schedule ids', async () => {
    await POST(formReq(await exportZip()))
    const j1 = h.jobCreate.mock.calls[0][0].data
    expect(j1).toMatchObject({
      projectId: 'newProject', versionId: 'newV1', scheduleId: 'newS1',
      trigger: 'scheduled', status: 'completed', initiatedByUserId: 'importer',
    })
    // No old id may survive.
    expect(JSON.stringify(j1)).not.toContain('oldV1')
    expect(JSON.stringify(j1)).not.toContain('oldS1')
  })

  test('an in-flight run does not arrive as still running', async () => {
    await POST(formReq(await exportZip()))
    expect(h.jobCreate.mock.calls[1][0].data.status).toBe('canceled')
  })

  test('a crafted archive cannot create two current versions', async () => {
    // "exactly one current version per project" is the model's core invariant, and
    // the archive is untrusted input. A second isCurrent row would make the live
    // graph ambiguous for every later read.
    const zip = new JSZip()
    zip.file('manifest.json', JSON.stringify({ version: '1.0.0', projectName: 'src', stats: {} }))
    zip.file('project.json', JSON.stringify({ id: 'oldProject', userId: 'oldOwner', name: 'src' }))
    zip.file('timeline/versions.json', JSON.stringify([
      { id: 'a', seq: 1, label: 'A', isCurrent: true, snapshotBase64: null },
      { id: 'b', seq: 2, label: 'B', isCurrent: true, snapshotBase64: null },
      { id: 'c', seq: 3, label: 'C', isCurrent: true, snapshotBase64: null },
    ]))
    const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
    const res = await POST(formReq(new File([buf], 'export.zip', { type: 'application/zip' })))
    expect(res.status).toBe(200)

    const currents = h.versionCreate.mock.calls.filter(c => c[0].data.isCurrent)
    expect(currents).toHaveLength(1)
    // The highest seq wins, so the newest graph is the live one.
    expect(currents[0][0].data.seq).toBe(3)
  })

  test('C-8: a crafted archive with queue rows imports them as canceled', async () => {
    const zip = new JSZip()
    zip.file('manifest.json', JSON.stringify({ version: '1.0.0', projectName: 'src', stats: {} }))
    zip.file('project.json', JSON.stringify({ id: 'oldProject', userId: 'oldOwner', name: 'src' }))
    zip.file('timeline/job-queue.json', JSON.stringify([
      { id: 'q1', kind: 'full_recon', status: 'queued', payload: { mode: 'new' } },
      { id: 'q2', kind: 'gvm', status: 'running', payload: {} },
    ]))
    const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
    const res = await POST(formReq(new File([buf], 'export.zip', { type: 'application/zip' })))
    expect(res.status).toBe(200)
    expect(h.jobQueueCreate).toHaveBeenCalledTimes(2)
    for (const call of h.jobQueueCreate.mock.calls) {
      expect(call[0].data.status).toBe('canceled')
      expect(call[0].data.projectId).toBe('newProject')
    }
  })

  test('an export without timeline files imports fine (older archives)', async () => {
    const zip = new JSZip()
    zip.file('manifest.json', JSON.stringify({ version: '1.0.0', projectName: 'src', stats: {} }))
    zip.file('project.json', JSON.stringify({ id: 'oldProject', userId: 'oldOwner', name: 'src' }))
    const buf = new Uint8Array(await zip.generateAsync({ type: 'nodebuffer' }))
    const res = await POST(formReq(new File([buf], 'export.zip', { type: 'application/zip' })))
    expect(res.status).toBe(200)
    expect(h.versionCreate).not.toHaveBeenCalled()
    expect(h.scheduleCreate).not.toHaveBeenCalled()
    expect(h.jobCreate).not.toHaveBeenCalled()
  })
})
