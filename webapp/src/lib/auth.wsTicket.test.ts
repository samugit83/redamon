/**
 * createWsTicket writes the socket it opens into `aud` (HD-25) and the project's
 * owner into `ten` (step 5.3). The claim set here is the one
 * agentic/tests/test_ws_ticket_interop.py signs with jose and verifies with the
 * agent's Python verifier: keep the two in step.
 *
 * Run: npx vitest run src/lib/auth.wsTicket.test.ts
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi, afterEach } from 'vitest'
import { jwtVerify, decodeProtectedHeader } from 'jose'

vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))

import { createWsTicket } from './auth'

const SECRET = 'w'.repeat(64)
const key = new TextEncoder().encode(SECRET)

afterEach(() => {
  vi.unstubAllEnvs()
  vi.stubEnv('AUTH_SECRET', 'a'.repeat(64))
})

describe('createWsTicket', () => {
  test('aud names the socket; HS256 with sub, pid, sid, iat and a 60 s exp', async () => {
    vi.stubEnv('AGENT_WS_TICKET_SECRET', SECRET)
    for (const socket of ['agent', 'kali-terminal', 'cypherfix-triage', 'cypherfix-codefix'] as const) {
      const ticket = await createWsTicket('u1', 'p1', 's1', socket)
      expect(ticket).toBeTruthy()
      expect(decodeProtectedHeader(ticket!)).toEqual({ alg: 'HS256' })
      const { payload } = await jwtVerify(ticket!, key)
      expect(Object.keys(payload).sort()).toEqual(['aud', 'exp', 'iat', 'pid', 'sid', 'sub'])
      expect(payload).toMatchObject({ sub: 'u1', pid: 'p1', sid: 's1', aud: socket })
      expect(typeof payload.aud).toBe('string')
      expect(payload.exp! - payload.iat!).toBe(60)
    }
  })

  test('the real actor rides along as act, only when it is another account', async () => {
    vi.stubEnv('AGENT_WS_TICKET_SECRET', SECRET)
    const acting = (await jwtVerify((await createWsTicket('u1', 'p1', 's1', 'agent', 'admin-1'))!, key)).payload
    expect(acting.act).toBe('admin-1')
    const self = (await jwtVerify((await createWsTicket('u1', 'p1', 's1', 'agent', 'u1'))!, key)).payload
    expect(self).not.toHaveProperty('act')
  })

  test('an agent ticket carries cap, the agent permissions its person holds (step 3.9b)', async () => {
    vi.stubEnv('AGENT_WS_TICKET_SECRET', SECRET)
    const held = (await jwtVerify((await createWsTicket('u1', 'p1', 's1', 'agent', undefined, ['agent:fireteam']))!, key)).payload
    expect(Object.keys(held).sort()).toEqual(['aud', 'cap', 'exp', 'iat', 'pid', 'sid', 'sub'])
    expect(held.cap).toEqual(['agent:fireteam'])
    // An empty cap is written: it means "holds none", never "today's behaviour" (no claim).
    const none = (await jwtVerify((await createWsTicket('u1', 'p1', 's1', 'agent', 'admin-1', []))!, key)).payload
    expect(none).toMatchObject({ cap: [], act: 'admin-1' })
    const without = (await jwtVerify((await createWsTicket('u1', 'p1', 's1', 'agent'))!, key)).payload
    expect(without).not.toHaveProperty('cap')
  })

  test('the tenant rides along as ten, the project owner, beside the person in sub (step 5.3)', async () => {
    vi.stubEnv('AGENT_WS_TICKET_SECRET', SECRET)
    const shared = (await jwtVerify((await createWsTicket('collab', 'p1', 's1', 'agent', undefined, [], 'owner'))!, key)).payload
    expect(Object.keys(shared).sort()).toEqual(['aud', 'cap', 'exp', 'iat', 'pid', 'sid', 'sub', 'ten'])
    expect(shared).toMatchObject({ sub: 'collab', ten: 'owner', pid: 'p1', sid: 's1', aud: 'agent' })
    // Written for an owner too: the agent never has to guess whose graph it is.
    const own = (await jwtVerify((await createWsTicket('owner', 'p1', 's1', 'kali-terminal', 'admin-1', undefined, 'owner'))!, key)).payload
    expect(own).toMatchObject({ sub: 'owner', ten: 'owner', act: 'admin-1' })
    expect(own).not.toHaveProperty('cap')
  })

  test('an empty tenant is refused, never written or left out', async () => {
    vi.stubEnv('AGENT_WS_TICKET_SECRET', SECRET)
    await expect(createWsTicket('u1', 'p1', 's1', 'agent', undefined, [], '')).rejects.toThrow('A ticket tenant is a non-empty user id')
  })

  test('no ticket without a secret, or with the compose placeholder', async () => {
    vi.stubEnv('AGENT_WS_TICKET_SECRET', '')
    expect(await createWsTicket('u1', 'p1', 's1', 'kali-terminal')).toBeNull()
    vi.stubEnv('AGENT_WS_TICKET_SECRET', 'changeme')
    expect(await createWsTicket('u1', 'p1', 's1', 'kali-terminal')).toBeNull()
  })
})
