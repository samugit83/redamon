/**
 * A seeded world for the Gateway tests: two users with a project and a chat session
 * each, and the `echo` plugin installed, enabled and ready at 1.0.0. Every test file
 * mocks `@/lib/prisma` with the fake below (vi.mock must sit in the test file).
 */
import { NextRequest } from 'next/server'
import type { FakePrisma, Row } from './fakePrisma'
import { mintCallToken, type MintCallTokenInput } from '../callToken'

export const CALL_SECRET = 'g'.repeat(64)
export const GATEWAY_BASE = 'http://plugin-gateway:7071/api/plugin-gateway/v1/'

export const ALICE = 'user-alice'
export const BOB = 'user-bob'
export const ALICE_PROJECT = 'project-alice'
export const BOB_PROJECT = 'project-bob'
export const ALICE_SESSION = 'session-alice'
export const ALICE_CONV = 'conv-alice'
export const BOB_SESSION = 'session-bob'
export const ALICE_OTHER_PROJECT = 'project-alice-2'
export const ALICE_OTHER_SESSION = 'session-alice-2'

export function echoManifest(over: Record<string, unknown> = {}): Row {
  return {
    id: 'echo',
    version: '1.0.0',
    displayName: 'Echo',
    description: 'Test fixture',
    platform: '>=1.0.0 <2.0.0',
    dataVersion: 1,
    permissions: ['session:read', 'llm:invoke', 'override:skill.text'],
    llmFeature: { description: 'Echoes things' },
    actions: [
      { id: 'echo', entry: 'engine/main.py:echo', timeoutSeconds: 30 },
      { id: 'sleep', entry: 'engine/main.py:sleep', timeoutSeconds: 30, async: true },
      { id: 'think', entry: 'engine/main.py:think', timeoutSeconds: 60, llm: true },
    ],
    ...over,
  }
}

export function echoInstall(over: Record<string, unknown> = {}): Row {
  return {
    pluginId: 'echo',
    enabled: true,
    status: 'ready',
    activeVersion: '1.0.0',
    dataVersion: 1,
    grantedPermissions: ['session:read', 'llm:invoke', 'override:skill.text'],
    manifest: echoManifest(),
    revokedReason: null,
    ...over,
  }
}

export function seedWorld(db: FakePrisma, opts: { install?: Row | null } = {}): void {
  db.seed('user', [
    { id: ALICE, name: 'Alice', email: 'alice@example.com', role: 'standard' },
    { id: BOB, name: 'Bob', email: 'bob@example.com', role: 'standard' },
    { id: 'user-admin', name: 'Admin', email: 'admin@example.com', role: 'admin' },
  ])
  db.seed('project', [
    { id: ALICE_PROJECT, userId: ALICE, name: 'A' },
    { id: ALICE_OTHER_PROJECT, userId: ALICE, name: 'A2' },
    { id: BOB_PROJECT, userId: BOB, name: 'B' },
  ])
  db.seed('conversation', [
    { id: ALICE_CONV, sessionId: ALICE_SESSION, userId: ALICE, projectId: ALICE_PROJECT, title: 'Recon of example.com' },
    { id: 'conv-alice-2', sessionId: ALICE_OTHER_SESSION, userId: ALICE, projectId: ALICE_OTHER_PROJECT },
    { id: 'conv-bob', sessionId: BOB_SESSION, userId: BOB, projectId: BOB_PROJECT },
  ])
  if (opts.install !== null) db.seed('pluginInstall', [opts.install ?? echoInstall()])
}

export type TokenInput = Partial<MintCallTokenInput>

/** Who owns each seeded project: the tenant actions.ts names in a token for it. */
export const PROJECT_OWNERS: Readonly<Record<string, string>> = {
  [ALICE_PROJECT]: ALICE,
  [ALICE_OTHER_PROJECT]: ALICE,
  [BOB_PROJECT]: BOB,
}

/**
 * A call token for Alice's session in Alice's project, unless overridden. Its tenant is the
 * project's owner, as the action start mints it, unless `ten` is given.
 */
export async function token(over: TokenInput = {}): Promise<string> {
  const input: MintCallTokenInput = {
    pluginId: 'echo',
    version: '1.0.0',
    sub: ALICE,
    prj: ALICE_PROJECT,
    ses: ALICE_SESSION,
    conv: ALICE_CONV,
    perms: ['session:read', 'llm:invoke', 'override:skill.text'],
    kind: 'action',
    timeoutSeconds: 30,
    ...over,
  }
  if (!('ten' in over)) input.ten = (input.prj && PROJECT_OWNERS[input.prj]) || input.sub
  for (const k of Object.keys(input) as (keyof MintCallTokenInput)[]) {
    if (input[k] === undefined) delete input[k]
  }
  return (await mintCallToken(input)).token
}

export interface GatewayRequestOptions {
  token?: string | null
  headers?: Record<string, string>
  rawBody?: string
  contentType?: string | null
}

export function gatewayRequest(op: string, body: unknown, opts: GatewayRequestOptions = {}): NextRequest {
  const headers = new Headers(opts.headers ?? {})
  if (opts.contentType !== null) headers.set('content-type', opts.contentType ?? 'application/json')
  if (opts.token) headers.set('authorization', `Bearer ${opts.token}`)
  return new NextRequest(GATEWAY_BASE + op, {
    method: 'POST',
    headers,
    body: opts.rawBody ?? JSON.stringify(body),
  })
}

export async function answer(res: Response): Promise<{ status: number; body: Record<string, unknown> }> {
  const text = await res.text()
  let body: Record<string, unknown> = {}
  try {
    body = JSON.parse(text)
  } catch {
    body = { raw: text }
  }
  return { status: res.status, body }
}
