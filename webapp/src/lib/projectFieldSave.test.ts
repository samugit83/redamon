/**
 * The single-field project save (step 5.2, SH-40): it sends the version the caller read, answers the
 * saved row and its new version, tells the stale-row 409 apart from the PUT's other 409s, and throws
 * every other failure as the ApiError the callers already show.
 *
 * Run: npx vitest run --no-file-parallelism src/lib/projectFieldSave.test.ts
 * @vitest-environment node
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { STALE_FIELD_NOTICE, isStaleSave, reloadProjectRow, saveProjectFields } from './projectFieldSave'
import { STALE_SAVE_MESSAGE } from './projectVersion'
import { ApiError } from './apiError'

const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
const V1 = '2026-11-13T10:00:00.000Z'

function answer(res: Response) {
  const fetchMock = vi.fn(async () => res)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}
const sentBody = (m: ReturnType<typeof answer>) => JSON.parse(String((m.mock.calls[0] as unknown as [string, RequestInit])[1].body))

afterEach(() => vi.unstubAllGlobals())

describe('saveProjectFields', () => {
  test('sends the fields with the version read, and answers the saved row and its version', async () => {
    const m = answer(json(200, { id: 'p1', stealthMode: true, updatedAt: '2026-11-13T11:00:00.000Z' }))
    const saved = await saveProjectFields('p1', { stealthMode: true }, V1, 'Could not save')
    expect(sentBody(m)).toEqual({ stealthMode: true, updatedAt: V1 })
    expect((m.mock.calls[0] as unknown as [string, RequestInit])[1].method).toBe('PUT')
    expect(saved).toEqual({ ok: true, row: expect.objectContaining({ stealthMode: true }), version: '2026-11-13T11:00:00.000Z' })
  })

  test('without a version read it sends none, as before', async () => {
    const m = answer(json(200, { id: 'p1' }))
    await saveProjectFields('p1', { stealthMode: true }, null, 'Could not save')
    expect(sentBody(m)).toEqual({ stealthMode: true })
  })

  test('the stale-row 409 answers stale (by its code, or by the message an older server sends)', async () => {
    answer(json(409, { error: STALE_SAVE_MESSAGE, code: 'stale_save' }))
    expect(await saveProjectFields('p1', { stealthMode: true }, V1, 'x')).toEqual({ ok: false, stale: true })
    answer(json(409, { error: STALE_SAVE_MESSAGE }))
    expect(await saveProjectFields('p1', { stealthMode: true }, V1, 'x')).toEqual({ ok: false, stale: true })
  })

  test("another 409 (a scan running) and any other failure throw the server's error", async () => {
    answer(json(409, { error: 'A scan is running on this project.' }))
    await expect(saveProjectFields('p1', { targetDomain: 'x.test' }, V1, 'Could not save')).rejects.toBeInstanceOf(ApiError)
    answer(json(403, { error: 'You do not hold the permission this action needs (project:settings).', code: 'forbidden', permission: 'project:settings' }))
    await expect(saveProjectFields('p1', { stealthMode: true }, V1, 'Could not save')).rejects.toThrow(/project:settings/)
  })
})

describe('isStaleSave, reloadProjectRow and the notice', () => {
  test('only a 409 with the stale code or message', () => {
    expect(isStaleSave(409, { code: 'stale_save' })).toBe(true)
    expect(isStaleSave(409, { error: 'busy' })).toBe(false)
    expect(isStaleSave(400, { code: 'stale_save' })).toBe(false)
    expect(isStaleSave(409, null)).toBe(false)
  })

  test('the reload answers the row, or null when it cannot be read', async () => {
    answer(json(200, { id: 'p1', updatedAt: V1 }))
    expect(await reloadProjectRow('p1')).toEqual({ id: 'p1', updatedAt: V1 })
    answer(json(404, { error: 'Not found' }))
    expect(await reloadProjectRow('p1')).toBeNull()
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('network') }))
    expect(await reloadProjectRow('p1')).toBeNull()
  })

  test('the notice names what happened', () => {
    expect(STALE_FIELD_NOTICE).toMatch(/^Someone else changed this project/)
    expect(STALE_FIELD_NOTICE).toMatch(/reloaded/)
  })
})
