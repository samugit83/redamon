/**
 * TruffleHog findings download: one artifact per source, scoped to the project.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  projectFindUnique: vi.fn(),
  readdir: vi.fn(),
  readFile: vi.fn(),
}))

vi.mock('@/lib/authz/guards', () => import('@/lib/authz/__testing__/routeGuardDoubles').then(m => m.overGuardProject()))
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@/lib/prisma', () => ({
  default: { project: { findUnique: (...a: unknown[]) => h.projectFindUnique(...a) } },
}))
vi.mock('fs/promises', () => ({
  readdir: (...a: unknown[]) => h.readdir(...a),
  readFile: (...a: unknown[]) => h.readFile(...a),
}))

const route = await import('./route')

const req = () => ({}) as never
const params = { params: Promise.resolve({ projectId: 'projA' }) }

const run = (payload: Record<string, unknown>) => JSON.stringify({
  source: 'docker', status: 'completed', findings: [{ detector_name: 'AWS' }], ...payload,
})

beforeEach(() => {
  vi.clearAllMocks()
  h.guard.mockResolvedValue(null)
  h.projectFindUnique.mockResolvedValue({ id: 'projA', name: 'Project A' })
  h.readFile.mockResolvedValue(run({}))
})

describe('GET /api/trufflehog/[projectId]/download', () => {
  test('returns every source artifact for the project', async () => {
    h.readdir.mockResolvedValue([
      'trufflehog_projA_docker.json',
      'trufflehog_projA_github.json',
    ])
    const body = await (await route.GET(req(), params)).json()
    expect(body.runs).toHaveLength(2)
    expect(body.project_id).toBe('projA')
    expect(body.total_findings).toBe(2)
  })

  test('F3: a project whose id prefixes another does not read its files', async () => {
    // `trufflehog_projA_` also prefix-matches `trufflehog_projA_x_github.json`.
    // Unreachable with fixed-length cuids, but one id-format change from serving
    // another project's findings, so the suffix is matched against known sources.
    h.readdir.mockResolvedValue([
      'trufflehog_projA_docker.json',
      'trufflehog_projA_x_github.json',   // belongs to project "projA_x"
    ])
    await route.GET(req(), params)
    const readPaths = h.readFile.mock.calls.map(c => String(c[0]))
    expect(readPaths.some(p => p.includes('projA_x'))).toBe(false)
    expect(readPaths).toHaveLength(1)
  })

  test('F3: an unrelated file in the directory is ignored', async () => {
    h.readdir.mockResolvedValue([
      'trufflehog_projA_docker.json',
      'trufflehog_projB_docker.json',
      'notes.txt',
      'trufflehog_projA_slack.json',      // not a known source
    ])
    await route.GET(req(), params)
    expect(h.readFile.mock.calls.map(c => String(c[0])))
      .toEqual([expect.stringContaining('trufflehog_projA_docker.json')])
  })

  test('404 when the project has no artifacts yet', async () => {
    h.readdir.mockResolvedValue([])
    expect((await route.GET(req(), params)).status).toBe(404)
  })

  test('404 for a project that does not exist', async () => {
    h.projectFindUnique.mockResolvedValue(null)
    expect((await route.GET(req(), params)).status).toBe(404)
  })

  test('an unreadable output directory is not a 500', async () => {
    h.readdir.mockRejectedValue(new Error('ENOENT'))
    expect((await route.GET(req(), params)).status).toBe(404)
  })

  test('one corrupt artifact does not lose the other sources', async () => {
    h.readdir.mockResolvedValue([
      'trufflehog_projA_docker.json',
      'trufflehog_projA_github.json',
    ])
    h.readFile
      .mockResolvedValueOnce('{ not json')
      .mockResolvedValueOnce(run({ source: 'github' }))
    const body = await (await route.GET(req(), params)).json()
    expect(body.runs).toHaveLength(1)
    expect(body.runs[0].source).toBe('github')
  })

  test('access control is enforced before anything is read', async () => {
    h.guard.mockResolvedValue(new Response('denied', { status: 404 }))
    const res = await route.GET(req(), params)
    expect(res.status).toBe(404)
    expect(h.readdir).not.toHaveBeenCalled()
    expect(h.projectFindUnique).not.toHaveBeenCalled()
  })
})

describe('HEAD /api/trufflehog/[projectId]/download', () => {
  test('200 when an artifact exists, 404 when none do', async () => {
    h.readdir.mockResolvedValue(['trufflehog_projA_docker.json'])
    expect((await route.HEAD(req(), params)).status).toBe(200)
    h.readdir.mockResolvedValue([])
    expect((await route.HEAD(req(), params)).status).toBe(404)
  })

  test('F3: another project\'s artifact does not make this one look ready', async () => {
    h.readdir.mockResolvedValue(['trufflehog_projA_x_github.json'])
    expect((await route.HEAD(req(), params)).status).toBe(404)
  })

  test('access control is enforced', async () => {
    h.guard.mockResolvedValue(new Response('denied', { status: 404 }))
    expect((await route.HEAD(req(), params)).status).toBe(404)
    expect(h.readdir).not.toHaveBeenCalled()
  })
})
