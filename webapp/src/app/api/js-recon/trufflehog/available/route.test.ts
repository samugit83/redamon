/**
 * GET /api/js-recon/trufflehog/available: one answer per `reason`.
 *
 * The JS Recon form locks its TruffleHog toggle only on `image_missing`; an
 * orchestrator that did not answer says nothing about the image, so it must
 * never read as "not installed".
 *
 * Run: npx vitest run --no-file-parallelism src/app/api/js-recon/trufflehog/available/route.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
// The route reads the session first (HD-10); these tests are about a signed-in account.
vi.mock('@/lib/session', () => ({ requireSession: async () => ({ userId: 'u1', role: 'standard' }) }))

const h = vi.hoisted(() => ({ orchestratorFetch: vi.fn() }))
vi.mock('@/lib/orchestrator', () => ({ orchestratorFetch: (...a: unknown[]) => h.orchestratorFetch(...a) }))

const { GET } = await import('./route')

function undiciFailure(code: string): TypeError {
  const err = new TypeError('fetch failed')
  const cause = new Error(`connect ${code} 10.0.0.7:8010`) as NodeJS.ErrnoException
  cause.code = code
  ;(err as TypeError & { cause?: unknown }).cause = cause
  return err
}

function timeout(): Error {
  const err = new Error('The operation was aborted due to timeout')
  err.name = 'TimeoutError'
  return err
}

const answered = (status: number, body: unknown) => new Response(
  typeof body === 'string' ? body : JSON.stringify(body),
  { status, headers: { 'Content-Type': typeof body === 'string' ? 'text/plain' : 'application/json' } },
)

async function answer() {
  const res = await GET()
  expect(res.status).toBe(200)
  return res.json()
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.spyOn(console, 'error').mockImplementation(() => {})
})

describe('GET /api/js-recon/trufflehog/available', () => {
  test('asks the orchestrator /health', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { trufflehog_available: true }))
    await GET()
    expect(String(h.orchestratorFetch.mock.calls[0][0])).toMatch(/\/health$/)
  })

  test('installed: available with no reason', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { status: 'healthy', gvm_available: false, trufflehog_available: true }))
    expect(await answer()).toEqual({ available: true, reason: null })
  })

  test('image absent: image_missing', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { status: 'healthy', trufflehog_available: false }))
    expect(await answer()).toEqual({ available: false, reason: 'image_missing' })
  })

  test('an unreachable orchestrator is orchestrator_unreachable, never image_missing', async () => {
    h.orchestratorFetch.mockRejectedValue(undiciFailure('ECONNREFUSED'))
    expect(await answer()).toEqual({ available: false, reason: 'orchestrator_unreachable', cause: 'ECONNREFUSED' })
    expect(console.error).toHaveBeenCalled()
  })

  test('a hung orchestrator is orchestrator_timeout', async () => {
    h.orchestratorFetch.mockRejectedValue(timeout())
    expect(await answer()).toEqual({ available: false, reason: 'orchestrator_timeout' })
  })

  test('a non-OK /health is orchestrator_error with its status', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(503, { detail: 'Service not initialized' }))
    expect(await answer()).toEqual({ available: false, reason: 'orchestrator_error', upstreamStatus: 503 })
  })

  test('an unreadable /health body is orchestrator_error', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, 'not json'))
    expect(await answer()).toEqual({ available: false, reason: 'orchestrator_error', upstreamStatus: 200 })
  })

  test('an orchestrator older than the field is orchestrator_error, not image_missing', async () => {
    h.orchestratorFetch.mockResolvedValue(answered(200, { status: 'healthy', gvm_available: true }))
    expect(await answer()).toEqual({ available: false, reason: 'orchestrator_error', upstreamStatus: 200 })
  })
})
