/**
 * useCredentialKeys: the read/write path behind the inline credential shortcuts.
 *
 * Three behaviours here are load-bearing and none of them fail loudly:
 *   - the PUT body carries ONE key. A full-object write would send every other
 *     masked value back as its new plaintext, corrupting 21 keys to save 1.
 *   - after a save it re-reads instead of caching what was typed, so the hook
 *     never holds a plaintext secret that a later write could echo back.
 *   - it tolerates having no ProjectProvider. It is mounted inside scan cards
 *     that render outside one, where a throw blanks the whole surface.
 *
 * Run: npx vitest run src/hooks/useCredentialKeys.test.tsx
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, waitFor, act, cleanup } from '@testing-library/react'
import { useCredentialKeys } from './useCredentialKeys'

const mockProject = vi.hoisted(() => ({ value: { userId: 'user-1' } as { userId: string } | null }))
vi.mock('@/providers/ProjectProvider', () => ({
  useOptionalProject: () => mockProject.value,
}))

const STORED = {
  githubAccessToken: '••••••••cdef',
  trufflehogGithubToken: '',
  githubEnterpriseHost: 'ghe.example.com',
}

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  mockProject.value = { userId: 'user-1' }
  fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ...STORED }) })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe('useCredentialKeys', () => {
  test('reads the masked settings for the signed-in user', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(fetchMock).toHaveBeenCalledWith('/api/users/user-1/settings')
    expect(result.current.isSet('githubAccessToken')).toBe(true)
    expect(result.current.masked('githubAccessToken')).toBe('••••••••cdef')
  })

  test('an empty stored value is not set', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.isSet('trufflehogGithubToken')).toBe(false)
    expect(result.current.isSet('neverHeardOfIt')).toBe(false)
  })

  test('saving PUTs only the one key it was asked to write', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))

    await act(async () => { await result.current.save('trufflehogGithubToken', 'ghp_new') })

    const put = fetchMock.mock.calls.find(c => c[1]?.method === 'PUT')!
    expect(put[0]).toBe('/api/users/user-1/settings')
    const body = JSON.parse(put[1].body)
    // Exactly one key: anything else would resend masked values as plaintext.
    expect(Object.keys(body)).toEqual(['trufflehogGithubToken'])
    expect(body.trufflehogGithubToken).toBe('ghp_new')
  })

  test('a save re-reads rather than caching the plaintext it just sent', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))

    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ ...STORED, trufflehogGithubToken: '••••••••_new' }),
    })
    await act(async () => { await result.current.save('trufflehogGithubToken', 'ghp_new') })

    expect(result.current.isSet('trufflehogGithubToken')).toBe(true)
    // The hook must hold the mask, never 'ghp_new'.
    expect(result.current.masked('trufflehogGithubToken')).toBe('••••••••_new')
  })

  test('a rejected save reports the server error and returns false', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))

    fetchMock.mockResolvedValueOnce({ ok: false, json: async () => ({ error: 'Bad host' }) })
    let ok: boolean | undefined
    await act(async () => { ok = await result.current.save('githubEnterpriseHost', 'nope') })

    expect(ok).toBe(false)
    expect(result.current.error).toBe('Bad host')
  })

  test('a network failure is reported, not thrown', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))

    // What a browser fetch throws when nothing answered.
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'))
    let ok: boolean | undefined
    await act(async () => { ok = await result.current.save('trufflehogGithubToken', 'x') })

    expect(ok).toBe(false)
    expect(result.current.error).toBe('Could not save the key (network_error)')
  })

  test('a server failure on save carries its code and status', async () => {
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))

    fetchMock.mockResolvedValueOnce({
      ok: false, status: 500, json: async () => ({ error: 'Failed to update user settings', code: 'P2024' }),
    })
    await act(async () => { await result.current.save('trufflehogGithubToken', 'x') })

    expect(result.current.error).toBe('Failed to update user settings (P2024 · HTTP 500)')
  })

  test('a failed read degrades to "nothing is set" instead of throwing, and says why', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.isSet('githubAccessToken')).toBe(false)
    expect(result.current.loadError).toBe("Couldn't read your saved keys (network_error)")
  })

  test('a read the server refused names its status, and a later good read clears it', async () => {
    fetchMock.mockResolvedValueOnce({
      ok: false, status: 500, json: async () => ({ error: 'Failed to fetch user settings', code: 'P1001' }),
    })
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loadError).toBe("Couldn't read your saved keys (P1001 · HTTP 500)"))
    expect(result.current.isSet('githubAccessToken')).toBe(false)

    await act(async () => { await result.current.refresh() })
    expect(result.current.loadError).toBeUndefined()
    expect(result.current.isSet('githubAccessToken')).toBe(true)
  })

  test('with no user in scope it neither fetches nor hangs on loading', async () => {
    mockProject.value = null
    const { result } = renderHook(() => useCredentialKeys())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(fetchMock).not.toHaveBeenCalled()

    let ok: boolean | undefined
    await act(async () => { ok = await result.current.save('trufflehogGithubToken', 'x') })
    expect(ok).toBe(false)
    expect(result.current.error).toBe('No user in session')
  })

  describe('a new GitHub Enterprise host with a stored token (re-entry, review of 1.6)', () => {
    const REFUSAL = {
      ok: false, status: 400,
      json: async () => ({
        error: 'The GitHub Enterprise host changed: type the GitHub Enterprise token again, or clear it.',
        code: 'secret_reentry_required', field: 'githubEnterpriseToken', fields: ['githubEnterpriseToken'], endpoint: 'githubEnterpriseHost',
      }),
    }
    const puts = () => fetchMock.mock.calls.filter(([, init]) => init?.method === 'PUT').map(([, init]) => JSON.parse(init.body))

    test('the caller is asked, and the host goes with the typed token in the same request', async () => {
      const { result } = renderHook(() => useCredentialKeys())
      await waitFor(() => expect(result.current.loading).toBe(false))
      fetchMock.mockResolvedValueOnce(REFUSAL)
      const onSecretReentry = vi.fn().mockResolvedValue({ githubEnterpriseToken: 'ghe_typed' })

      let ok: boolean | undefined
      await act(async () => { ok = await result.current.save('githubEnterpriseHost', 'ghe2.example.com', { onSecretReentry }) })

      expect(ok).toBe(true)
      expect(onSecretReentry).toHaveBeenCalledWith(expect.objectContaining({ field: 'githubEnterpriseToken', fields: ['githubEnterpriseToken'] }))
      expect(puts()).toEqual([
        { githubEnterpriseHost: 'ghe2.example.com' },
        { githubEnterpriseHost: 'ghe2.example.com', githubEnterpriseToken: 'ghe_typed' },
      ])
      expect(result.current.error).toBe('')
    })

    test('declined, nothing more is sent and the server\'s sentence is the error', async () => {
      const { result } = renderHook(() => useCredentialKeys())
      await waitFor(() => expect(result.current.loading).toBe(false))
      fetchMock.mockResolvedValueOnce(REFUSAL)

      let ok: boolean | undefined
      await act(async () => { ok = await result.current.save('githubEnterpriseHost', 'ghe2.example.com', { onSecretReentry: async () => null }) })

      expect(ok).toBe(false)
      expect(puts()).toHaveLength(1)
      expect(result.current.error).toContain('type the GitHub Enterprise token again')
    })
  })
})
