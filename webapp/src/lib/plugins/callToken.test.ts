/**
 * Call tokens (TD-07): the only credential plugin code holds. Short-lived, bound to one
 * plugin version, user, project, session and job, signed with a secret of their own.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'
import { SignJWT, decodeJwt } from 'jose'
import { setNowForTests } from './clock'
import {
  CALL_TOKEN_AUDIENCE,
  CallTokenConfigError,
  callTokenTtlSeconds,
  mintCallToken,
  verifyCallToken,
  type MintCallTokenInput,
} from './callToken'

const SECRET = 'c'.repeat(64)
const AUTH = 'b'.repeat(64)
const T0 = new Date('2026-10-09T10:00:00.000Z')

const base: MintCallTokenInput = {
  pluginId: 'skiller',
  version: '1.2.0',
  sub: 'user-1',
  prj: 'project-1',
  ses: 'session-1',
  conv: 'conv-1',
  perms: ['session:read', 'llm:invoke'],
  kind: 'action',
  timeoutSeconds: 120,
}

let clock = T0
beforeEach(() => {
  vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', SECRET)
  vi.stubEnv('AUTH_SECRET', AUTH)
  vi.stubEnv('PLUGIN_ACTION_MAX_TIMEOUT', '')
  clock = T0
  setNowForTests(() => clock)
})
afterEach(() => {
  setNowForTests(null)
  vi.unstubAllEnvs()
})

const advance = (seconds: number) => {
  clock = new Date(clock.getTime() + seconds * 1000)
}

describe('mint and verify', () => {
  test('a token round-trips with every claim it was minted with', async () => {
    const { token, jti, expiresAt } = await mintCallToken({ ...base, act: 'admin-1' })
    const claims = await verifyCallToken(token, { kinds: ['action'] })
    expect(claims).toMatchObject({
      pid: 'skiller',
      ver: '1.2.0',
      sub: 'user-1',
      act: 'admin-1',
      prj: 'project-1',
      ses: 'session-1',
      conv: 'conv-1',
      perms: ['session:read', 'llm:invoke'],
      kind: 'action',
      jti,
      aud: CALL_TOKEN_AUDIENCE,
    })
    expect(claims!.exp).toBe(Math.floor(expiresAt.getTime() / 1000))
    expect(jti).toMatch(/^[0-9a-f-]{36}$/)
  })

  test('optional claims are absent, not empty, when not given', async () => {
    const { token } = await mintCallToken({ pluginId: 'echo', version: '1.0.0', sub: 'u', perms: [], kind: 'action', timeoutSeconds: 5 })
    const claims = await verifyCallToken(token, { kinds: ['action'] })
    expect(claims).not.toBeNull()
    for (const k of ['act', 'prj', 'ses', 'conv', 'jid']) expect(claims).not.toHaveProperty(k)
  })

  test('every token has its own jti', async () => {
    const a = await mintCallToken(base)
    const b = await mintCallToken(base)
    expect(a.jti).not.toBe(b.jti)
  })

  test('the claims carry no role, so the middleware can never read one as a login session', async () => {
    const { token } = await mintCallToken(base)
    expect(decodeJwt(token)).not.toHaveProperty('role')
  })

  test('a job token carries its job id, and only a job token does', async () => {
    const { token } = await mintCallToken({ ...base, kind: 'job', jid: 'job-1' })
    expect(await verifyCallToken(token, { kinds: ['job'] })).toMatchObject({ kind: 'job', jid: 'job-1' })
    await expect(mintCallToken({ ...base, kind: 'job' })).rejects.toThrow(/job id/)
    await expect(mintCallToken({ ...base, kind: 'action', jid: 'job-1' })).rejects.toThrow(/job id/)
  })

  test('a malformed plugin id or user is refused at mint', async () => {
    await expect(mintCallToken({ ...base, pluginId: 'Bad Id' })).rejects.toThrow(/plugin id/)
    await expect(mintCallToken({ ...base, sub: '' })).rejects.toThrow(/user/)
  })
})

describe('refusals', () => {
  test('expired: valid until exp, refused one second after', async () => {
    const { token } = await mintCallToken(base)
    advance(callTokenTtlSeconds(120) - 1)
    expect(await verifyCallToken(token, { kinds: ['action'] })).not.toBeNull()
    advance(2)
    expect(await verifyCallToken(token, { kinds: ['action'] })).toBeNull()
  })

  test('a token signed with another secret is refused', async () => {
    const { token } = await mintCallToken(base)
    vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', 'd'.repeat(64))
    expect(await verifyCallToken(token, { kinds: ['action'] })).toBeNull()
  })

  test('a login session cookie (AUTH_SECRET, sub + role) is not a call token', async () => {
    const login = await new SignJWT({ sub: 'user-1', role: 'admin' })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(new TextEncoder().encode(AUTH))
    expect(await verifyCallToken(login, { kinds: ['action', 'job'] })).toBeNull()
  })

  const forge = (claims: Record<string, unknown>, opts: { aud?: string; alg?: string } = {}) =>
    new SignJWT({ pid: 'skiller', ver: '1.2.0', perms: [], kind: 'action', ...claims })
      .setProtectedHeader({ alg: opts.alg ?? 'HS256' })
      .setSubject('user-1')
      .setJti('11111111-2222-3333-4444-555555555555')
      .setAudience(opts.aud ?? CALL_TOKEN_AUDIENCE)
      .setIssuedAt(Math.floor(T0.getTime() / 1000))
      .setExpirationTime(Math.floor(T0.getTime() / 1000) + 60)
      .sign(new TextEncoder().encode(SECRET))

  test('a well-formed forgery with the right secret passes (control for the cases below)', async () => {
    expect(await verifyCallToken(await forge({}), { kinds: ['action'] })).not.toBeNull()
  })

  test('the wrong audience is refused', async () => {
    expect(await verifyCallToken(await forge({}, { aud: 'redamon-mcp' }), { kinds: ['action'] })).toBeNull()
  })

  test('a kind the caller does not accept is refused', async () => {
    const { token } = await mintCallToken({ ...base, kind: 'job', jid: 'job-1' })
    expect(await verifyCallToken(token, { kinds: ['action'] })).toBeNull()
  })

  // TD-28: migration code gets no token at all, so no kind may ever be read as one.
  test('a migration kind is refused even when the caller would accept it', async () => {
    const t = await forge({ kind: 'migration' })
    expect(await verifyCallToken(t, { kinds: ['action', 'job', 'migration' as never] })).toBeNull()
    await expect(mintCallToken({ ...base, kind: 'migration' as never })).rejects.toThrow(/kind/)
  })

  test.each([
    ['no plugin id', { pid: undefined }],
    ['a malformed plugin id', { pid: '../etc' }],
    ['no version', { ver: undefined }],
    ['permissions that are not a list of strings', { perms: 'llm:invoke' }],
    ['a job token without its job id', { kind: 'job' }],
    ['a project that is not a string', { prj: 7 }],
  ])('a token with %s is refused', async (_name, claims) => {
    expect(await verifyCallToken(await forge(claims), { kinds: ['action', 'job'] })).toBeNull()
  })

  test('alg none and garbage are refused', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
    const payload = Buffer.from(JSON.stringify({ pid: 'skiller', sub: 'u', aud: CALL_TOKEN_AUDIENCE })).toString('base64url')
    expect(await verifyCallToken(`${header}.${payload}.`, { kinds: ['action'] })).toBeNull()
    expect(await verifyCallToken('not-a-token', { kinds: ['action'] })).toBeNull()
    expect(await verifyCallToken('', { kinds: ['action'] })).toBeNull()
  })
})

// Step 5.10 (SH-35): the token names the project's owner as its tenant beside the person it acts for.
describe('the tenant claim', () => {
  test('a token names its tenant beside the person: the owner of a shared project', async () => {
    const { token } = await mintCallToken({ ...base, sub: 'collaborator-1', ten: 'owner-1' })
    expect(await verifyCallToken(token, { kinds: ['action'] })).toMatchObject({ sub: 'collaborator-1', ten: 'owner-1', prj: 'project-1' })
    expect(decodeJwt(token)).toMatchObject({ sub: 'collaborator-1', ten: 'owner-1' })
  })

  test('without a tenant the person is the tenant, and the claim is written all the same', async () => {
    const { token } = await mintCallToken(base)
    expect(decodeJwt(token).ten).toBe('user-1')
    expect((await verifyCallToken(token, { kinds: ['action'] }))!.ten).toBe('user-1')
  })

  test('an empty tenant is refused at mint', async () => {
    await expect(mintCallToken({ ...base, ten: '' })).rejects.toThrow(/tenant/)
  })

  test('a token minted before the claim existed reads as its own user (the owner it was minted for)', async () => {
    const legacy = await new SignJWT({ pid: 'skiller', ver: '1.2.0', perms: [], kind: 'action', prj: 'project-1' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user-1')
      .setJti('11111111-2222-3333-4444-555555555555')
      .setAudience(CALL_TOKEN_AUDIENCE)
      .setIssuedAt(Math.floor(T0.getTime() / 1000))
      .setExpirationTime(Math.floor(T0.getTime() / 1000) + 60)
      .sign(new TextEncoder().encode(SECRET))
    expect(await verifyCallToken(legacy, { kinds: ['action'] })).toMatchObject({ sub: 'user-1', ten: 'user-1' })
  })

  test.each([[''], [7], [null], [['owner-1']]])('a malformed tenant %j never verifies', async (ten) => {
    const forged = await new SignJWT({ pid: 'skiller', ver: '1.2.0', perms: [], kind: 'action', ten })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('user-1')
      .setJti('11111111-2222-3333-4444-555555555555')
      .setAudience(CALL_TOKEN_AUDIENCE)
      .setIssuedAt(Math.floor(T0.getTime() / 1000))
      .setExpirationTime(Math.floor(T0.getTime() / 1000) + 60)
      .sign(new TextEncoder().encode(SECRET))
    expect(await verifyCallToken(forged, { kinds: ['action'] })).toBeNull()
  })
})

describe('the secret', () => {
  test.each([
    ['missing', ''],
    ['the compose placeholder', 'changeme'],
    ['shorter than 32 characters', 'x'.repeat(31)],
  ])('%s: minting and verifying fail closed with plugins_not_configured', async (_name, value) => {
    const { token } = await mintCallToken(base)
    vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', value)
    const minted = await mintCallToken(base).catch((e: unknown) => e)
    expect(minted).toBeInstanceOf(CallTokenConfigError)
    expect((minted as CallTokenConfigError).code).toBe('plugins_not_configured')
    await expect(verifyCallToken(token, { kinds: ['action'] })).rejects.toBeInstanceOf(CallTokenConfigError)
  })

  test('a secret equal to AUTH_SECRET is refused: a leaked call token must never sign a login', async () => {
    vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', AUTH)
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const minted = await mintCallToken(base).catch((e: unknown) => e)
    expect(minted).toBeInstanceOf(CallTokenConfigError)
    expect(String((minted as Error).message)).toMatch(/AUTH_SECRET/)
    expect(err.mock.calls.flat().join(' ')).toMatch(/\[plugins\].*PLUGIN_CALL_TOKEN_SECRET/)
    err.mockRestore()
  })

  // Phase 04 review: the runner holds PLUGIN_RUNNER_KEY, and a compromised runner must not
  // be able to mint call tokens; the other platform keys must not double as it either.
  test.each(['PLUGIN_RUNNER_KEY', 'INTERNAL_API_KEY', 'AGENT_WS_TICKET_SECRET'])('a secret equal to %s is refused', async (name) => {
    vi.stubEnv(name, SECRET)
    const err = vi.spyOn(console, 'error').mockImplementation(() => {})
    const minted = await mintCallToken(base).catch((e: unknown) => e)
    expect(minted).toBeInstanceOf(CallTokenConfigError)
    expect(String((minted as Error).message)).toContain(name)
    err.mockRestore()
  })
})

describe('time to live (RV-20)', () => {
  test('a 900 s action with PLUGIN_ACTION_MAX_TIMEOUT=900 gets a 960 s token', async () => {
    vi.stubEnv('PLUGIN_ACTION_MAX_TIMEOUT', '900')
    expect(callTokenTtlSeconds(900)).toBe(960)
    const { token } = await mintCallToken({ ...base, timeoutSeconds: 900 })
    const c = decodeJwt(token)
    expect(c.exp! - c.iat!).toBe(960)
  })

  test('the setting caps a longer manifest timeout; the default cap is 900 s', () => {
    expect(callTokenTtlSeconds(3600)).toBe(960)
    vi.stubEnv('PLUGIN_ACTION_MAX_TIMEOUT', '300')
    expect(callTokenTtlSeconds(3600)).toBe(360)
    expect(callTokenTtlSeconds(30)).toBe(90)
  })

  test.each([0, -5, 1.5, Number.NaN])('a timeout of %s is refused', (t) => {
    expect(() => callTokenTtlSeconds(t)).toThrow(/timeout/)
  })
})

describe('the middleware never takes a call token for a login', () => {
  async function middlewareStatus(cookie: string) {
    vi.resetModules()
    const { middleware } = await import('@/middleware')
    const req = new NextRequest('http://localhost:3000/api/projects', {
      headers: { cookie: `redamon-auth=${cookie}` },
    })
    return (await middleware(req)).status
  }

  test('a call token sent as the session cookie gets 401', async () => {
    const { token } = await mintCallToken(base)
    expect(await middlewareStatus(token)).toBe(401)
  })

  test('even one signed with AUTH_SECRET is refused, because it carries no role', async () => {
    vi.stubEnv('PLUGIN_CALL_TOKEN_SECRET', 'e'.repeat(64))
    const { token } = await mintCallToken(base)
    const claims = decodeJwt(token)
    const resigned = await new SignJWT(claims as Record<string, unknown>)
      .setProtectedHeader({ alg: 'HS256' })
      .sign(new TextEncoder().encode(AUTH))
    expect(await middlewareStatus(resigned)).toBe(401)
  })
})
