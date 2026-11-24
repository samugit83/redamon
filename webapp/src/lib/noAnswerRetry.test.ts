/**
 * A page's one-shot reads (the session, the saved project) are tried again when they get no
 * answer at all: Chromium aborts every request in flight with net::ERR_NETWORK_CHANGED when a host
 * address appears or goes away, which a container on a Docker bridge network starting or stopping
 * does. An answer, whatever its status, is never tried again; neither is a read its owner gave up.
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { ApiError, toApiError } from './apiError'
import { NO_ANSWER_RETRY_MS, readRetryingNoAnswer, isNoAnswer } from './noAnswerRetry'

let fetchMock: ReturnType<typeof vi.fn>
beforeEach(() => {
  vi.useFakeTimers()
  fetchMock = vi.fn()
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200 })
const lostBody = (failure: unknown) => ({ ok: true, status: 200, json: async () => { throw failure } }) as unknown as Response

describe('readRetryingNoAnswer', () => {
  test('the waits are small and bounded', () => {
    expect(NO_ANSWER_RETRY_MS).toEqual([500, 1000, 2000, 4000])
  })

  test.each([
    ['a network error', new TypeError('Failed to fetch')],
    ['an abort', new DOMException('The operation was aborted.', 'AbortError')],
    ['a timeout', new DOMException('The operation timed out.', 'TimeoutError')],
  ])('%s is tried again after the first wait, and the answer and its body returned', async (_what, failure) => {
    fetchMock.mockRejectedValueOnce(failure).mockResolvedValueOnce(ok({ id: 'u1' }))
    const read = readRetryingNoAnswer('/api/auth/me', { cache: 'no-store' })
    await vi.advanceTimersByTimeAsync(NO_ANSWER_RETRY_MS[0] - 1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    await vi.advanceTimersByTimeAsync(1)
    const { res, body } = await read
    expect(res.status).toBe(200)
    expect(body).toEqual({ id: 'u1' })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock).toHaveBeenLastCalledWith('/api/auth/me', { cache: 'no-store' })
  })

  test.each([
    ['lost on the way (TypeError)', new TypeError('network error')],
    ['cancelled (AbortError)', new DOMException('The operation was aborted.', 'AbortError')],
  ])('a 200 whose body was %s got no answer either: tried again', async (_what, failure) => {
    fetchMock.mockResolvedValueOnce(lostBody(failure)).mockResolvedValueOnce(ok({ id: 'P1' }))
    const read = readRetryingNoAnswer('/api/projects/P1')
    await vi.advanceTimersByTimeAsync(NO_ANSWER_RETRY_MS[0])
    await expect(read).resolves.toMatchObject({ body: { id: 'P1' } })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  test('a 200 whose body is not JSON is an answer: rejected at once, never tried again', async () => {
    fetchMock.mockResolvedValue(new Response('<html>portal</html>', { status: 200 }))
    await expect(readRetryingNoAnswer('/api/auth/me')).rejects.toBeInstanceOf(SyntaxError)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test.each([401, 403, 404, 500, 503])('an answer (HTTP %i) is returned at once, its body unread, never tried again', async (status) => {
    const answer = new Response('{"error":"x"}', { status })
    fetchMock.mockResolvedValue(answer)
    const { res, body } = await readRetryingNoAnswer('/api/projects/p1')
    expect(res).toBe(answer)
    expect(body).toBeUndefined()
    expect(res.bodyUsed).toBe(false)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('after the last wait the last failure is thrown: one try per wait, plus the first', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const outcome = readRetryingNoAnswer('/api/auth/me').catch((err: unknown) => err)
    await vi.advanceTimersByTimeAsync(NO_ANSWER_RETRY_MS.reduce((a, b) => a + b, 0))
    expect(await outcome).toBeInstanceOf(TypeError)
    expect(fetchMock).toHaveBeenCalledTimes(NO_ANSWER_RETRY_MS.length + 1)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(fetchMock).toHaveBeenCalledTimes(NO_ANSWER_RETRY_MS.length + 1)
  })

  test('an owner that gave up before the first wait stops it: no second try', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const outcome = readRetryingNoAnswer('/api/projects/P1', undefined, { keepTrying: () => false }).catch((err: unknown) => err)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(await outcome).toBeInstanceOf(TypeError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('an owner that gives up during a wait stops it: no try after the wait', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    let wanted = true
    const outcome = readRetryingNoAnswer('/api/projects/P1', undefined, { keepTrying: () => wanted }).catch((err: unknown) => err)
    await vi.advanceTimersByTimeAsync(100)
    wanted = false
    await vi.advanceTimersByTimeAsync(10_000)
    expect(await outcome).toBeInstanceOf(TypeError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test("the caller's own abort is never tried again", async () => {
    const controller = new AbortController()
    controller.abort()
    fetchMock.mockRejectedValue(new DOMException('The operation was aborted.', 'AbortError'))
    const outcome = readRetryingNoAnswer('/api/projects/P1', { signal: controller.signal }).catch((err: unknown) => err)
    await vi.advanceTimersByTimeAsync(10_000)
    expect((await outcome as DOMException).name).toBe('AbortError')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('isNoAnswer', () => {
  test('a request that got no answer', () => {
    expect(isNoAnswer(toApiError(new TypeError('Failed to fetch'), 'x'))).toBe(true)
    expect(isNoAnswer(toApiError(new DOMException('aborted', 'AbortError'), 'x'))).toBe(true)
    expect(isNoAnswer(toApiError(new DOMException('timed out', 'TimeoutError'), 'x'))).toBe(true)
  })

  test('an answer, or a body that is not JSON, is not "no answer"', () => {
    expect(isNoAnswer(new ApiError({ reason: 'x', status: 500, code: 'P1001' }))).toBe(false)
    expect(isNoAnswer(new ApiError({ reason: 'x', status: 401 }))).toBe(false)
    expect(isNoAnswer(toApiError(new SyntaxError('Unexpected token <'), 'x'))).toBe(false)
    expect(isNoAnswer(null)).toBe(false)
  })
})
