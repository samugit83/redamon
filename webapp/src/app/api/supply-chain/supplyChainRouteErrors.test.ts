/**
 * What the Supply-Chain routes answer when the orchestrator, the DB or the
 * shared upload volume fails. The upload volume's errno (EACCES, ENOSPC, EROFS)
 * is safe to show and is the whole diagnosis, so it travels as `code`.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'

const h = vi.hoisted(() => ({
  guard: vi.fn(),
  orchestratorFetch: vi.fn(),
  reconcile: vi.fn(),
  recordScanStart: vi.fn(),
  findProject: vi.fn(),
  updateProject: vi.fn(),
  existsSync: vi.fn(),
  mkdir: vi.fn(),
  writeFile: vi.fn(),
  readdir: vi.fn(),
  stat: vi.fn(),
  unlink: vi.fn(),
  readFile: vi.fn(),
}))

vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => h.guard(...a) }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))
vi.mock('@/lib/scanTimeline', () => ({
  reconcileScanJobStatus: (...a: unknown[]) => h.reconcile(...a),
  recordScanStart: (...a: unknown[]) => h.recordScanStart(...a),
}))
vi.mock('@/lib/session', () => ({ getEffectiveUser: vi.fn().mockResolvedValue({ userId: 'u1' }) }))
// A startable engagement: the R-11 gate has its own tests in start/route.test.ts.
vi.mock('@/lib/engagement', () => ({
  currentRoeTextSha256: vi.fn().mockResolvedValue(null),
  loadEngagement: vi.fn().mockResolvedValue({ blockers: [] }),
}))
vi.mock('@/lib/activationLock', () => ({ assertGraphNotActivating: vi.fn().mockResolvedValue(null) }))
vi.mock('@/lib/prisma', () => ({
  default: {
    project: {
      findUnique: (...a: unknown[]) => h.findProject(...a),
      update: (...a: unknown[]) => h.updateProject(...a),
    },
  },
}))
vi.mock('fs', async orig => ({
  ...(await orig<typeof import('fs')>()),
  existsSync: (...a: unknown[]) => h.existsSync(...a),
}))
vi.mock('fs/promises', () => ({
  mkdir: (...a: unknown[]) => h.mkdir(...a),
  writeFile: (...a: unknown[]) => h.writeFile(...a),
  readdir: (...a: unknown[]) => h.readdir(...a),
  stat: (...a: unknown[]) => h.stat(...a),
  unlink: (...a: unknown[]) => h.unlink(...a),
  readFile: (...a: unknown[]) => h.readFile(...a),
}))

const statusRoute = await import('./[projectId]/status/route')
const stopRoute = await import('./[projectId]/stop/route')
const pauseRoute = await import('./[projectId]/pause/route')
const resumeRoute = await import('./[projectId]/resume/route')
const logsRoute = await import('./[projectId]/logs/route')
const startRoute = await import('./[projectId]/start/route')
const uploadRoute = await import('./[projectId]/upload/route')
const downloadRoute = await import('./[projectId]/download/route')

const params = { params: Promise.resolve({ projectId: 'p1' }) }
const req = () => ({ signal: undefined }) as never

function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`connect ${code} 10.0.0.7:8010`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

const fsError = (code: string) => Object.assign(
  new Error(`${code}: operation failed, open '/data/supply-chain-uploads/p1/acme-lock.json'`), { code },
)

const prismaDown = () => Object.assign(
  new Error("Can't reach database server while reading target acme.example.com"),
  { name: 'PrismaClientInitializationError', code: 'P1001' },
)

const answered = (status: number, body: unknown) => new Response(
  typeof body === 'string' ? body : JSON.stringify(body), { status },
)

const uploadReq = (file: File) => ({
  headers: new Headers(),
  formData: async () => ({ get: () => file }),
}) as never

const deleteReq = (filename: string) => ({ url: `http://x/api/supply-chain/p1/upload?filename=${filename}` }) as never

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  h.guard.mockResolvedValue(null)
  h.reconcile.mockResolvedValue(undefined)
  h.recordScanStart.mockResolvedValue(undefined)
  h.findProject.mockResolvedValue({
    id: 'p1', userId: 'u1', supplyChainSbomFile: 'sbom.json', supplyChainInputMode: 'upload', supplyChainRepoUrl: '',
  })
  h.updateProject.mockResolvedValue({ updatedAt: new Date('2026-10-29T10:00:00Z') })
  h.existsSync.mockReturnValue(true)
  h.mkdir.mockResolvedValue(undefined)
  h.writeFile.mockResolvedValue(undefined)
  h.readdir.mockResolvedValue([])
  h.unlink.mockResolvedValue(undefined)
})

describe('GET status', () => {
  test('an unreachable orchestrator is a 503, not a synthetic idle', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(503)
    const body = await res.json()
    expect(body).toEqual({ error: 'Supply-Chain status unavailable', code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(console.error).toHaveBeenCalled()
  })

  test('a 5xx is a 502 with the upstream status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(503, { detail: 'Service not initialized' }))
    const res = await statusRoute.GET(req(), params)
    expect(res.status).toBe(502)
    expect(await res.json()).toEqual({ error: 'Service not initialized', code: 'orchestrator_error', upstreamStatus: 503 })
  })
})

describe.each([
  ['stop', stopRoute, 'Failed to stop Supply-Chain scan'],
  ['pause', pauseRoute, 'Failed to pause Supply-Chain scan'],
  ['resume', resumeRoute, 'Failed to resume Supply-Chain scan'],
])('POST %s', (_action, route, message) => {
  test('a throw names the orchestrator and is logged', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(503)
    expect(await res.json()).toEqual({ error: message, code: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(console.error).toHaveBeenCalled()
  })

  test("a refusal keeps the orchestrator's detail and status", async () => {
    h.orchestratorFetch.mockResolvedValue(answered(400, { detail: 'No Supply-Chain scan is running' }))
    const res = await route.POST(req(), params)
    expect(res.status).toBe(400)
    expect(await res.json()).toEqual({ error: 'No Supply-Chain scan is running', code: 'orchestrator_error', upstreamStatus: 400 })
  })
})

describe('GET logs', () => {
  test('a throw is a 503 with a body', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    const res = await logsRoute.GET(req(), params)
    expect(res.status).toBe(503)
    expect((await res.json()).error).toBe('Failed to connect to Supply-Chain log stream')
  })
})

describe('POST start', () => {
  test('a non-JSON 500 keeps the status and a code', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(500, 'Internal Server Error'))
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'Failed to start Supply-Chain scan', code: 'orchestrator_error', upstreamStatus: 500,
    })
  })

  test('the specific "no input" refusal is unchanged', async () => {
    h.findProject.mockResolvedValue({ id: 'p1', userId: 'u1', supplyChainSbomFile: '', supplyChainInputMode: 'upload' })
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(400)
    expect((await res.json()).error).toMatch(/^No SBOM\/lockfile uploaded/)
  })

  test('a DB failure answers its code, never the message', async () => {
    h.findProject.mockRejectedValue(prismaDown())
    const res = await startRoute.POST(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to start Supply-Chain scan', code: 'P1001' })
  })
})

describe('upload', () => {
  test('a listing that fails answers the fs code', async () => {
    h.readdir.mockRejectedValue(fsError('EACCES'))
    const res = await uploadRoute.GET(req(), params)
    expect(res.status).toBe(500)
    const body = await res.json()
    expect(body).toEqual({ error: 'Failed to list files', code: 'EACCES' })
    expect(JSON.stringify(body)).not.toContain('acme')
  })

  test('a full volume on upload answers ENOSPC', async () => {
    h.writeFile.mockRejectedValue(fsError('ENOSPC'))
    const res = await uploadRoute.POST(uploadReq(new File(['{}'], 'sbom.json')), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to upload file', code: 'ENOSPC' })
  })

  test('a file saved but not recorded as the input says so, with the Prisma code', async () => {
    h.updateProject.mockRejectedValue(prismaDown())
    const res = await uploadRoute.POST(uploadReq(new File(['{}'], 'sbom.json')), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'File saved but could not be set as the scan input. Try again.', code: 'P1001',
    })
  })

  test('a delete the volume refuses answers the fs code', async () => {
    h.unlink.mockRejectedValue(fsError('EROFS'))
    const res = await uploadRoute.DELETE(deleteReq('sbom.json'), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to delete file', code: 'EROFS' })
  })

  test('a file that vanished before the unlink is still a success', async () => {
    h.unlink.mockRejectedValue(fsError('ENOENT'))
    const res = await uploadRoute.DELETE(deleteReq('sbom.json'), params)
    expect(res.status).toBe(200)
    expect((await res.json()).success).toBe(true)
  })

  test('regression S-34: a project that still names the deleted file is not a success', async () => {
    h.updateProject.mockRejectedValue(prismaDown())
    const res = await uploadRoute.DELETE(deleteReq('sbom.json'), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({
      error: 'File removed but could not be cleared as the scan input. Try again.', code: 'P1001',
    })
  })

  test('a project row deleted meanwhile has no input left to clear', async () => {
    h.updateProject.mockRejectedValue(Object.assign(new Error('Record to update not found.'), { code: 'P2025' }))
    const res = await uploadRoute.DELETE(deleteReq('sbom.json'), params)
    expect(res.status).toBe(200)
  })

  test('deleting a file that is not the active input does not touch the project', async () => {
    const res = await uploadRoute.DELETE(deleteReq('other.json'), params)
    expect(res.status).toBe(200)
    expect(h.updateProject).not.toHaveBeenCalled()
  })
})

describe('download', () => {
  test('a HEAD that fails logs its cause', async () => {
    const err = prismaDown()
    h.findProject.mockRejectedValue(err)
    expect((await downloadRoute.HEAD(req(), params)).status).toBe(500)
    expect(console.error).toHaveBeenCalledWith('Error checking supply-chain data:', err)
  })

  test('a GET whose file cannot be read answers the fs code', async () => {
    h.readFile.mockRejectedValue(fsError('EACCES'))
    const res = await downloadRoute.GET(req(), params)
    expect(res.status).toBe(500)
    expect(await res.json()).toEqual({ error: 'Failed to download supply-chain data', code: 'EACCES' })
  })
})
