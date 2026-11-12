/**
 * The password policy hook asks /api/auth/password-policy only with the identity switch on, as
 * /api/auth/me's `flags` report it: off, the route answers 404, which the browser logged as an error
 * on every load of the Users page and My account (Phase 2 verification). It asks again when the
 * flag turns on (the session read after the first render), and drops a policy when it turns off.
 *
 * Run: npx vitest run --no-file-parallelism src/hooks/usePasswordPolicy.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { usePasswordPolicy } from './usePasswordPolicy'

const fetchMock = vi.fn()
const POLICY = { minLength: 16, maxBytes: 72, rules: true, description: 'At least 16 characters.' }

beforeEach(() => {
  fetchMock.mockReset().mockImplementation(async () => new Response(JSON.stringify(POLICY), { status: 200 }))
  vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => vi.unstubAllGlobals())

describe('usePasswordPolicy', () => {
  test('the identity switch off: nothing asked, no policy', async () => {
    const { result } = renderHook(() => usePasswordPolicy(false))
    await new Promise((r) => setTimeout(r, 10))
    expect(fetchMock).not.toHaveBeenCalled()
    expect(result.current).toBeNull()
  })

  test('on: the policy in force', async () => {
    const { result } = renderHook(() => usePasswordPolicy(true))
    await waitFor(() => expect(result.current).toEqual({ minLength: 16, rules: true, description: 'At least 16 characters.' }))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledWith('/api/auth/password-policy')
  })

  test('the flag known only after the session is read: asked then; turned off: dropped', async () => {
    const { result, rerender } = renderHook(({ on }) => usePasswordPolicy(on), { initialProps: { on: false } })
    expect(fetchMock).not.toHaveBeenCalled()
    rerender({ on: true })
    await waitFor(() => expect(result.current?.minLength).toBe(16))
    rerender({ on: false })
    await waitFor(() => expect(result.current).toBeNull())
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  test('a failed read keeps the floor quietly', async () => {
    fetchMock.mockImplementation(async () => new Response('{}', { status: 500 }))
    const { result } = renderHook(() => usePasswordPolicy(true))
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())
    expect(result.current).toBeNull()
  })
})
