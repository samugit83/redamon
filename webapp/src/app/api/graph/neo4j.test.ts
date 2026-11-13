/**
 * Driver lifetime + query timeout.
 *
 * REGRESSION: `getDriver()` used to return a FRESH driver on every call when
 * NODE_ENV=production (only development reused the singleton). Since a driver
 * owns a pool of up to `maxConnectionPoolSize` Bolt connections and nothing
 * closes it per-request, every API call leaked a whole pool -- the most likely
 * cause of Neo4j's "Increase in network aborts detected" on a busy instance.
 * `production returns the same instance` is the test that pins that bug.
 *
 * Also pins the query timeout: the driver's connectionTimeout only bounds
 * ACQUIRING a connection, so without a transaction timeout a whole-graph read
 * hangs the request forever.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const h = vi.hoisted(() => {
  let created = 0
  return {
    created: () => created,
    reset: () => { created = 0 },
    make: () => {
      created += 1
      const id = created
      return {
        id,
        session: vi.fn(() => ({ run: vi.fn(), close: vi.fn() })),
        close: vi.fn(async () => {}),
        verifyConnectivity: vi.fn(async () => {}),
      }
    },
  }
})

vi.mock('neo4j-driver', () => {
  const driver = vi.fn(() => h.make())
  const auth = { basic: vi.fn(() => ({})) }
  return { default: { driver, auth }, driver, auth }
})

import { getDriver, getGraphSession, closeDriver, verifyConnection } from './neo4j'

beforeEach(async () => {
  await closeDriver()
  globalThis.neo4jDriver = undefined
  h.reset()
  vi.unstubAllEnvs()
})

afterEach(async () => {
  await closeDriver()
  vi.unstubAllEnvs()
})

describe('driver lifetime', () => {
  test('returns the same instance across calls', () => {
    const a = getDriver()
    const b = getDriver()
    const c = getDriver()
    expect(a).toBe(b)
    expect(b).toBe(c)
    expect(h.created()).toBe(1)
  })

  // The bug: this branch used to call createDriver() unconditionally.
  test('production returns the same instance (does not build one per call)', () => {
    vi.stubEnv('NODE_ENV', 'production')
    const first = getDriver()
    for (let i = 0; i < 25; i++) getDriver()
    expect(getDriver()).toBe(first)
    expect(h.created()).toBe(1)
  })

  test('every session comes from the one shared driver', () => {
    vi.stubEnv('NODE_ENV', 'production')
    getGraphSession()
    getGraphSession()
    getGraphSession()
    expect(h.created()).toBe(1)
    expect(getDriver().session).toHaveBeenCalledTimes(3)
  })

  test('verifyConnection reuses the driver rather than building one', async () => {
    const d = getDriver()
    await expect(verifyConnection()).resolves.toBe(true)
    expect(h.created()).toBe(1)
    expect(d.verifyConnectivity).toHaveBeenCalled()
  })

  test('closeDriver closes the pool, clears it, and the next get builds a fresh one', async () => {
    const first = getDriver()
    await closeDriver()
    expect(first.close).toHaveBeenCalledTimes(1)
    const second = getDriver()
    expect(second).not.toBe(first)
    expect(h.created()).toBe(2)
  })

  test('closeDriver is safe when no driver was ever created', async () => {
    await expect(closeDriver()).resolves.toBeUndefined()
    expect(h.created()).toBe(0)
  })
})

describe('read-only sessions (fix of the 4.3 review finding 1)', () => {
  test('a read-only session asks the driver for READ access, so Neo4j refuses a write in it', () => {
    getGraphSession({ readOnly: true })
    expect(getDriver().session).toHaveBeenCalledWith({ defaultAccessMode: 'READ' })
  })

  test('every other session is opened as before, with no options', () => {
    getGraphSession()
    getGraphSession({})
    expect((getDriver().session as ReturnType<typeof vi.fn>).mock.calls).toEqual([[], []])
  })

  test('a read-only session still carries the query timeout', async () => {
    const session = getGraphSession({ readOnly: true })
    await session.run('MATCH (n) RETURN n')
    const tx = (getDriver().session as ReturnType<typeof vi.fn>).mock.results[0].value.run.mock.calls[0][2]
    expect(tx).toEqual({ timeout: 120_000 })
  })
})

describe('query timeout', () => {
  const txConfigOf = (session: ReturnType<typeof getGraphSession>) =>
    (getDriver().session as ReturnType<typeof vi.fn>).mock.results[0].value.run.mock.calls[0][2]

  test('run() carries a default timeout', async () => {
    const session = getGraphSession()
    await session.run('MATCH (n) RETURN n')
    expect(txConfigOf(session)).toEqual({ timeout: 120_000 })
  })

  test('NEO4J_QUERY_TIMEOUT_MS overrides the default', async () => {
    vi.stubEnv('NEO4J_QUERY_TIMEOUT_MS', '5000')
    const session = getGraphSession()
    await session.run('MATCH (n) RETURN n')
    expect(txConfigOf(session)).toEqual({ timeout: 5000 })
  })

  test.each(['0', '-1', 'abc', ''])('falls back to the default for %o', async raw => {
    vi.stubEnv('NEO4J_QUERY_TIMEOUT_MS', raw)
    const session = getGraphSession()
    await session.run('MATCH (n) RETURN n')
    expect(txConfigOf(session)).toEqual({ timeout: 120_000 })
  })

  test('a caller-supplied config wins over the default', async () => {
    const session = getGraphSession()
    await session.run('MATCH (n) RETURN n', {}, { timeout: 999 })
    expect(txConfigOf(session)).toEqual({ timeout: 999 })
  })

  test('query and params are forwarded untouched', async () => {
    const session = getGraphSession()
    await session.run('MATCH (n {id:$id}) RETURN n', { id: 'x' })
    const call = (getDriver().session as ReturnType<typeof vi.fn>)
      .mock.results[0].value.run.mock.calls[0]
    expect(call[0]).toBe('MATCH (n {id:$id}) RETURN n')
    expect(call[1]).toEqual({ id: 'x' })
  })

  test('non-run members pass through the proxy', async () => {
    const session = getGraphSession()
    await session.close()
    const raw = (getDriver().session as ReturnType<typeof vi.fn>).mock.results[0].value
    expect(raw.close).toHaveBeenCalledTimes(1)
  })
})
