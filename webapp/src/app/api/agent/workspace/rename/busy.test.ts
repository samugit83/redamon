/**
 * Rename, delete, upload and mkdir forward the agent's busy answer with the id
 * of the import holding the folder.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/access', () => ({ guardProject: async () => null }))

import { POST as rename } from './route'
import { DELETE as remove } from '../delete/route'
import { POST as upload } from '../upload/route'
import { POST as mkdir } from '../mkdir/route'

const JOB = 'b'.repeat(32)
let agentAnswer: () => Response

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => agentAnswer()))
})

const busy = () => new Response(JSON.stringify({
  error: 'A running import is replacing this folder. Retry when it finishes.', code: 'busy', jobId: JOB,
}), { status: 409, headers: { 'Content-Type': 'application/json' } })

const renameRequest = () => new NextRequest('http://x/api/agent/workspace/rename', {
  method: 'POST', body: JSON.stringify({ projectId: 'p1', path: 'uploads/r', newName: 'x' }),
})
const deleteRequest = () => new NextRequest('http://x/api/agent/workspace/delete?projectId=p1&path=uploads/r&recursive=true',
  { method: 'DELETE' })

describe('workspace rename and delete while an import holds the folder', () => {
  test('rename answers 409 busy with the job id', async () => {
    agentAnswer = busy
    const res = await rename(renameRequest())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'busy', jobId: JOB, error: expect.stringContaining('running import') })
  })

  test('delete answers 409 busy with the job id', async () => {
    agentAnswer = busy
    const res = await remove(deleteRequest())
    expect(res.status).toBe(409)
    expect(await res.json()).toMatchObject({ code: 'busy', jobId: JOB })
  })

  test('upload and mkdir answer 409 busy with the job id', async () => {
    agentAnswer = busy
    const fd = new FormData()
    fd.append('projectId', 'p1')
    fd.append('path', 'uploads/r')
    fd.append('file', new File(['x'], 'notes.txt'))
    const up = await upload(new NextRequest('http://x/api/agent/workspace/upload', { method: 'POST', body: fd }))
    expect(up.status).toBe(409)
    expect(await up.json()).toMatchObject({ code: 'busy', jobId: JOB })
    const md = await mkdir(new NextRequest('http://x/api/agent/workspace/mkdir', {
      method: 'POST', body: JSON.stringify({ projectId: 'p1', path: 'uploads/r/sub' }),
    }))
    expect(md.status).toBe(409)
    expect(await md.json()).toMatchObject({ code: 'busy', jobId: JOB })
  })

  test('an upload name collision keeps its exists code for the overwrite prompt', async () => {
    agentAnswer = () => new Response(JSON.stringify({ error: 'notes.txt already exists in uploads', code: 'exists' }),
      { status: 409, headers: { 'Content-Type': 'application/json' } })
    const fd = new FormData()
    fd.append('projectId', 'p1')
    fd.append('file', new File(['x'], 'notes.txt'))
    const up = await upload(new NextRequest('http://x/api/agent/workspace/upload', { method: 'POST', body: fd }))
    expect(up.status).toBe(409)
    expect((await up.json()).code).toBe('exists')
  })

  test('other failures keep their answer', async () => {
    agentAnswer = () => new Response(JSON.stringify({ error: 'cannot rename a protected folder' }),
      { status: 400, headers: { 'Content-Type': 'application/json' } })
    const res = await rename(renameRequest())
    expect(res.status).toBe(400)
    expect((await res.json()).jobId).toBeUndefined()
  })
})
