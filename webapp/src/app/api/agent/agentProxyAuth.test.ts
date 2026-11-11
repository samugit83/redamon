/**
 * Every webapp proxy to the agent's workspace, Metasploit-session and
 * agent-session-stop routes must send the master internal key.
 *
 * Those agent routes are published on 0.0.0.0:8090 and now refuse any caller
 * without INTERNAL_API_KEY; the webapp is the only legitimate caller, and it has
 * already checked that the signed-in user owns the project. A proxy that drops
 * the header turns into a 401 in the UI (the file drawer, the sessions panel, a
 * conversation delete that no longer stops its agent loop).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/access', () => ({
  guardProject: vi.fn(async () => null),
  requireProjectAccess: vi.fn(async () => ({ project: { id: 'p1', userId: 'u1' } })),
  requireEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  requireConversationAccess: vi.fn(async () => ({ conversation: { id: 'c1', userId: 'u1', projectId: 'p1' } })),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: { findUnique: vi.fn(async () => ({ githubAccessToken: '' })) },
    conversation: {
      findUnique: vi.fn(async () => ({ sessionId: 's1', userId: 'u1', projectId: 'p1' })),
      delete: vi.fn(async () => ({})),
    },
  },
}))
vi.mock('@/lib/audit', () => ({ writeAudit: vi.fn(async () => {}) }))
vi.mock('@/lib/session', () => ({
  getSession: vi.fn(async () => ({ userId: 'u1', role: 'user' })),
  getEffectiveUser: vi.fn(async () => ({ userId: 'u1' })),
  // The Metasploit-session and job proxies read the session first (HD-10).
  requireSession: vi.fn(async () => ({ userId: 'u1', role: 'user' })),
}))
vi.mock('../graph/neo4j', () => ({
  getGraphSession: () => ({ run: vi.fn(async () => ({ records: [] })), close: vi.fn(async () => {}) }),
}))

import * as wsList from './workspace/list/route'
import * as wsTree from './workspace/tree/route'
import * as wsPreview from './workspace/preview/route'
import * as wsProperties from './workspace/properties/route'
import * as wsJobs from './workspace/jobs/route'
import * as wsArchiveDownload from './workspace/archive-download/route'
import * as wsDelete from './workspace/delete/route'
import * as wsRename from './workspace/rename/route'
import * as wsReset from './workspace/reset/route'
import * as wsMkdir from './workspace/mkdir/route'
import * as wsBulkArchive from './workspace/bulk-archive/route'
import * as wsUpload from './workspace/upload/route'
import * as wsJobCancel from './workspace/jobs/[jobId]/cancel/route'
import * as wsJobStatus from './workspace/jobs/[jobId]/route'
import * as wsUploadCreate from './workspace/upload-sessions/route'
import * as wsUploadChunk from './workspace/upload-sessions/[uploadId]/chunk/route'
import * as wsUploadCommit from './workspace/upload-sessions/[uploadId]/commit/route'
import * as wsUploadAbort from './workspace/upload-sessions/[uploadId]/route'
import * as wsImport from './workspace/import-url/route'
import * as wsImportResolve from './workspace/import-url/resolve/route'
import * as wsImportResync from './workspace/import-url/resync/route'
import * as sessions from './sessions/route'
import * as sessionInteract from './sessions/[id]/interact/route'
import * as sessionKill from './sessions/[id]/kill/route'
import * as jobKill from './jobs/[id]/kill/route'
import * as conversation from '../conversations/[id]/route'

const KEY = 'test-master-key'
const BASE = 'http://x'
const idParams = (id: string) => ({ params: Promise.resolve({ id }) })

const json = (path: string, body: unknown) =>
  new NextRequest(`${BASE}${path}`, {
    method: 'POST',
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' },
  })

function uploadRequest(): NextRequest {
  const form = new FormData()
  form.set('projectId', 'p1')
  form.set('path', '.')
  form.set('file', new File(['hello'], 'a.txt'))
  return new NextRequest(`${BASE}/api/agent/workspace/upload`, { method: 'POST', body: form })
}

type Case = { name: string; agentPath: string; call: () => Promise<Response> }

const CASES: Case[] = [
  { name: 'workspace list', agentPath: '/workspace/list', call: () => wsList.GET(new NextRequest(`${BASE}/x?projectId=p1&path=.`)) },
  { name: 'workspace tree', agentPath: '/workspace/tree', call: () => wsTree.GET(new NextRequest(`${BASE}/x?projectId=p1`)) },
  { name: 'workspace preview', agentPath: '/workspace/preview', call: () => wsPreview.GET(new NextRequest(`${BASE}/x?projectId=p1&path=a`)) },
  { name: 'workspace properties', agentPath: '/workspace/properties', call: () => wsProperties.GET(new NextRequest(`${BASE}/x?projectId=p1&path=a`)) },
  { name: 'workspace jobs', agentPath: '/workspace/jobs', call: () => wsJobs.GET(new NextRequest(`${BASE}/x?projectId=p1`)) },
  { name: 'workspace archive-download', agentPath: '/workspace/archive-download', call: () => wsArchiveDownload.GET(new NextRequest(`${BASE}/x?projectId=p1&path=a`)) },
  { name: 'workspace delete', agentPath: '/workspace?', call: () => wsDelete.DELETE(new NextRequest(`${BASE}/x?projectId=p1&path=a`, { method: 'DELETE' })) },
  { name: 'workspace rename', agentPath: '/workspace/rename', call: () => wsRename.POST(json('/x', { projectId: 'p1', path: 'a', newName: 'b' })) },
  { name: 'workspace reset', agentPath: '/workspace/reset', call: () => wsReset.POST(json('/x', { projectId: 'p1' })) },
  { name: 'workspace mkdir', agentPath: '/workspace/mkdir', call: () => wsMkdir.POST(json('/x', { projectId: 'p1', path: 'd' })) },
  { name: 'workspace bulk-archive', agentPath: '/workspace/bulk-archive', call: () => wsBulkArchive.POST(json('/x', { projectId: 'p1', paths: ['a'] })) },
  { name: 'workspace upload', agentPath: '/workspace/upload', call: () => wsUpload.POST(uploadRequest()) },
  {
    name: 'workspace job cancel',
    agentPath: '/workspace/jobs/j1/cancel',
    call: () => wsJobCancel.POST(new NextRequest(`${BASE}/x?projectId=p1`, { method: 'POST' }), { params: Promise.resolve({ jobId: 'j1' }) }),
  },
  {
    name: 'workspace job status',
    agentPath: `/workspace/jobs/${'a'.repeat(32)}?projectId=p1`,
    call: () => wsJobStatus.GET(new NextRequest(`${BASE}/x?projectId=p1`), { params: Promise.resolve({ jobId: 'a'.repeat(32) }) }),
  },
  {
    name: 'workspace upload-session create',
    agentPath: '/workspace/upload-sessions',
    call: () => wsUploadCreate.POST(json('/x', { projectId: 'p1', name: 'a', size: 1, kind: 'file' })),
  },
  {
    name: 'workspace upload-session chunk',
    agentPath: `/workspace/upload-sessions/${'f'.repeat(32)}/chunk`,
    call: () => wsUploadChunk.PUT(new NextRequest(`${BASE}/x?projectId=p1&offset=0`, { method: 'PUT', body: new Uint8Array([1]) }),
      { params: Promise.resolve({ uploadId: 'f'.repeat(32) }) }),
  },
  {
    name: 'workspace upload-session commit',
    agentPath: `/workspace/upload-sessions/${'f'.repeat(32)}/commit`,
    call: () => wsUploadCommit.POST(json('/x', { projectId: 'p1' }), { params: Promise.resolve({ uploadId: 'f'.repeat(32) }) }),
  },
  {
    name: 'workspace upload-session abort',
    agentPath: `/workspace/upload-sessions/${'f'.repeat(32)}?projectId=p1`,
    call: () => wsUploadAbort.DELETE(new NextRequest(`${BASE}/x?projectId=p1`, { method: 'DELETE' }),
      { params: Promise.resolve({ uploadId: 'f'.repeat(32) }) }),
  },
  { name: 'workspace import-url resolve', agentPath: '/workspace/import-url/resolve',
    call: () => wsImportResolve.POST(json('/x', { projectId: 'p1', url: 'https://github.com/o/r' })) },
  { name: 'workspace import-url', agentPath: '/workspace/import-url',
    call: () => wsImport.POST(json('/x', { projectId: 'p1', url: 'https://github.com/o/r' })) },
  // Its first agent call reads the folder's import record (the mock has none).
  { name: 'workspace import-url resync', agentPath: '/workspace/properties',
    call: () => wsImportResync.POST(json('/x', { projectId: 'p1', path: 'uploads/r' })) },
  { name: 'sessions list', agentPath: '/sessions', call: () => sessions.GET() },
  { name: 'session interact', agentPath: '/sessions/1/interact', call: () => sessionInteract.POST(json('/x', { command: 'id' }), idParams('1')) },
  { name: 'session kill', agentPath: '/sessions/1/kill', call: () => sessionKill.POST(new NextRequest(`${BASE}/x`, { method: 'POST' }), idParams('1')) },
  { name: 'msf job kill', agentPath: '/jobs/1/kill', call: () => jobKill.POST(new NextRequest(`${BASE}/x`, { method: 'POST' }), idParams('1')) },
  {
    name: 'conversation delete (agent-session/stop)',
    agentPath: '/agent-session/stop',
    call: () => conversation.DELETE(new NextRequest(`${BASE}/x`, { method: 'DELETE' }), idParams('c1')),
  },
]

let calls: { url: string; init?: RequestInit }[]

beforeEach(() => {
  calls = []
  vi.stubEnv('INTERNAL_API_KEY', KEY)
  vi.stubGlobal('fetch', vi.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } })
  }))
})

afterEach(() => {
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('agent proxies send the master internal key', () => {
  test.each(CASES)('$name', async ({ agentPath, call }) => {
    await call()
    const hit = calls.find(c => c.url.includes(agentPath))
    expect(hit, `no fetch to ${agentPath}; saw ${calls.map(c => c.url).join(', ')}`).toBeDefined()
    const headers = (hit!.init?.headers ?? {}) as Record<string, string>
    expect(headers['x-internal-key']).toBe(KEY)
  })

  test('JSON proxies keep their Content-Type next to the key', async () => {
    await wsRename.POST(json('/x', { projectId: 'p1', path: 'a', newName: 'b' }))
    const headers = calls[0].init?.headers as Record<string, string>
    expect(headers['Content-Type']).toBe('application/json')
  })

  test('upload sets no Content-Type, so fetch writes the multipart boundary', async () => {
    await wsUpload.POST(uploadRequest())
    const headers = calls[0].init?.headers as Record<string, string>
    expect(Object.keys(headers).map(k => k.toLowerCase())).not.toContain('content-type')
    expect(calls[0].init?.body).toBeInstanceOf(FormData)
  })
})
