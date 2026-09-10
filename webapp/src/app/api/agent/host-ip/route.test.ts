/**
 * Unit tests for the /api/agent/host-ip proxy route (issue #180, strategy row 7).
 *
 * The route forwards the agent's read-only /host-ip to the settings UI. It must
 * FAIL OPEN QUIETLY: any agent failure (non-2xx, thrown fetch, malformed body)
 * degrades to 200 { detectedHostIp: '' } so the caller just shows no suggestion,
 * never a 5xx or a crash.
 *
 * Run: npx vitest run src/app/api/agent/host-ip/route.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import * as route from './route'

function installFetch(body: unknown, ok = true): void {
  global.fetch = vi.fn(async () =>
    new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status: ok ? 200 : 503,
      headers: { 'Content-Type': 'application/json' },
    }),
  ) as typeof fetch
}

beforeEach(() => { vi.restoreAllMocks() })
afterEach(() => { vi.restoreAllMocks() })

async function bodyOf(resp: Response) {
  return resp.json()
}

describe('GET /api/agent/host-ip', () => {
  test('passes the agent value through on success', async () => {
    installFetch({ detectedHostIp: '192.168.1.50' })
    const resp = await route.GET()
    expect(resp.status).toBe(200)
    expect(await bodyOf(resp)).toEqual({ detectedHostIp: '192.168.1.50' })
  })

  test('agent non-2xx -> 200 empty (fail open)', async () => {
    installFetch({ error: 'boom' }, false)
    const resp = await route.GET()
    expect(resp.status).toBe(200)
    expect(await bodyOf(resp)).toEqual({ detectedHostIp: '' })
  })

  test('agent down (fetch throws) -> 200 empty', async () => {
    global.fetch = vi.fn(async () => { throw new Error('ECONNREFUSED') }) as typeof fetch
    const resp = await route.GET()
    expect(resp.status).toBe(200)
    expect(await bodyOf(resp)).toEqual({ detectedHostIp: '' })
  })

  test('malformed JSON body -> 200 empty', async () => {
    installFetch('not-json{')
    const resp = await route.GET()
    expect(resp.status).toBe(200)
    expect(await bodyOf(resp)).toEqual({ detectedHostIp: '' })
  })

  test('non-string detectedHostIp is coerced to empty', async () => {
    installFetch({ detectedHostIp: 12345 })
    const resp = await route.GET()
    expect(await bodyOf(resp)).toEqual({ detectedHostIp: '' })
  })
})
