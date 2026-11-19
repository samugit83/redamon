/**
 * The workspace tools: the agent's /workspace/* endpoints, called with the master key like the UI's
 * workspace routes (app/api/agent/agentProxy.ts). The agent bounds them loosely, so the Navigator's
 * tighter caps are set here, never by the model. A binary file is refused.
 */
import { agentFetch } from '@/lib/agentFetch'
import { McpToolError } from '@/lib/mcp/errors'
import { WORKSPACE_MAX_ENTRIES, WORKSPACE_READ_MAX_BYTES, WORKSPACE_TREE_MAX_DEPTH } from '../constants'

const q = encodeURIComponent

function cleanPath(path: string): string {
  const p = path.trim() || '.'
  if (p.includes('\0')) throw new McpToolError('That path is not valid.', 'bad_args')
  return p
}

async function agentJson(url: string): Promise<Record<string, unknown>> {
  const res = await agentFetch(url, { cache: 'no-store' }, { timeoutMs: 20_000 })
  const body = await res.json().catch(() => null) as Record<string, unknown> | null
  if (!res.ok || !body) {
    // The agent's 4xx sentences are its own ("not a file: x", "path escapes workspace"), never data.
    const msg = res.status < 500 && typeof body?.error === 'string' ? body.error.slice(0, 200) : 'The workspace could not be read.'
    throw new McpToolError(msg, res.status === 404 ? 'not_found' : 'workspace_error')
  }
  return body
}

export async function workspaceTree(projectId: string, path: string, maxDepth: number, maxEntries: number) {
  const depth = Math.max(1, Math.min(WORKSPACE_TREE_MAX_DEPTH, Math.trunc(maxDepth)))
  const entries = Math.max(10, Math.min(WORKSPACE_MAX_ENTRIES, Math.trunc(maxEntries)))
  return agentJson(`/workspace/tree?projectId=${q(projectId)}&path=${q(cleanPath(path))}&maxDepth=${depth}&maxEntries=${entries}`)
}

export async function workspaceList(projectId: string, path: string, limit: number) {
  const n = Math.max(1, Math.min(WORKSPACE_MAX_ENTRIES, Math.trunc(limit)))
  return agentJson(`/workspace/list?projectId=${q(projectId)}&path=${q(cleanPath(path))}&limit=${n}`)
}

export async function workspaceRead(projectId: string, path: string) {
  const body = await agentJson(
    `/workspace/preview?projectId=${q(projectId)}&path=${q(cleanPath(path))}&maxBytes=${WORKSPACE_READ_MAX_BYTES}`,
  )
  if (body.isBinary === true) throw new McpToolError('This is a binary file; only text files can be read.', 'binary_file')
  return { path: body.path, content: body.content, truncated: body.truncated === true, size: body.size, mime: body.mime }
}
