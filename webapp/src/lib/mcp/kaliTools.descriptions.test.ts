/**
 * What the sandbox tools tell a connected agent about per-user sandboxes
 * (group 1): a command may answer `starting`, and a sandbox that cannot be used
 * says why in `errorCode`. The descriptions are the only place an agent learns
 * which of those codes a retry can fix, so they are pinned here, together with
 * the annotations and scopes this change must leave as they are.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeAll, afterAll, vi } from 'vitest'

vi.mock('@/lib/prisma', () => ({ default: {} }))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn() }))

import type { Tool } from '@modelcontextprotocol/sdk/types.js'
import { KALI_EXEC_ERROR_CODES } from '@/lib/sandbox/contract'
import { listAdvertisedTools, toolScopes } from './apiReference'

let tools: Map<string, Tool>

beforeAll(async () => {
  vi.stubEnv('MCP_KALI_EXEC_ENABLED', 'true')
  tools = new Map((await listAdvertisedTools()).map(t => [t.name, t]))
})

afterAll(() => {
  vi.unstubAllEnvs()
})

const describedAs = (name: string) => {
  const tool = tools.get(name)
  expect(tool, `${name} is not advertised`).toBeDefined()
  return tool!.description ?? ''
}

describe.each(['kali_exec', 'kali_output'])('%s describes a per-user sandbox', name => {
  test('starting: the caller\'s sandbox is starting, poll kali_output', () => {
    const text = describedAs(name)
    expect(text).toMatch(/"starting"[^.]*your sandbox is starting/i)
    expect(text).toMatch(/poll kali_output/i)
  })

  test('ram: the instance\'s memory is in use, retry later', () => {
    expect(describedAs(name)).toMatch(/"ram"[^.]*memory is in use[^.]*retry later/i)
  })

  test('sandbox_refused: the token\'s owner may not use it here, retrying will not help', () => {
    expect(describedAs(name)).toMatch(
      /"sandbox_refused"[^.]*token's owner may not use the Kali sandbox on this project[^.]*retrying will not help/i
    )
  })

  test('every code of the contract is explained', () => {
    const text = describedAs(name)
    for (const code of KALI_EXEC_ERROR_CODES) expect(text, code).toContain(`"${code}"`)
  })
})

describe("kali_exec tells a client the person's reverse-shell port (FU-24)", () => {
  test('where to read it, what 4444 means, and how a listener outlives the 300 s cap', () => {
    const text = describedAs('kali_exec')
    expect(text).toMatch(/reverse-shell port is \$MSF_REVERSE_PORT inside the sandbox/)
    expect(text).toMatch(/4444 means it has no pool port: a callback then needs your own tunnel, or use a bind payload/)
    // A backgrounded command returns at once and keeps running (network_recon_server.py runs
    // `bash -c`); at the cap only bash is killed, so nothing is promised of a foreground listener.
    expect(text).toMatch(/kali_exec stops waiting at the 300-second cap, so start a listener in the background/)
    expect(text).toMatch(/\(`nohup nc -lvnp \$MSF_REVERSE_PORT >\/tmp\/l\.log 2>&1 &`\): it keeps running until your sandbox stops/)
    expect(text).not.toMatch(/cannot keep a listener open|A listener in the foreground ends/)
  })
})

describe('what group 1 leaves as it is', () => {
  test('annotations: kali_exec and kali_cancel stay destructive, kali_output read-only', () => {
    expect(tools.get('kali_exec')!.annotations).toEqual({
      readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true,
    })
    expect(tools.get('kali_cancel')!.annotations).toEqual({
      readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false,
    })
    expect(tools.get('kali_output')!.annotations).toEqual({ readOnlyHint: true, openWorldHint: false })
  })

  test('scopes: each exec tool needs kali:exec and nothing else', () => {
    for (const name of ['kali_exec', 'kali_output', 'kali_cancel']) {
      expect(toolScopes(tools.get(name)!), name).toEqual({ required: ['kali:exec'] })
    }
  })

  test('no description promises that /tmp outlives an idle sandbox', () => {
    // A per-user sandbox stops when unused and starts again with an empty /tmp.
    const text = describedAs('kali_exec')
    expect(text).toMatch(/\/tmp/)
    expect(text).toMatch(/empty \/tmp/i)
  })
})
