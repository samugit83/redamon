/**
 * Conversations with the agent and the assistants ask for their permission (step 3.9; PE-19,
 * PE-22): listing and creating a project's conversations, and every read or write of one (its
 * messages, its Fireteam waves and members) `agent:chat` on the conversation's project, after the
 * conversation guard (the author, on a project they still see) has found it; the text-to-Cypher
 * and command assistants `agent:assistants` on the project the body names. Starting a Fireteam
 * wave is the agent's to enforce (3.9b); these routes only read and record it.
 * Real guard, can() and registry; the session and Prisma are doubles (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { vi } from 'vitest'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  // The conversation guard reads the effective user: the one the identity names.
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import {
  OWNED_PROJECT, OWNER, describeRoutePermissions, type RouteCase, type RouteCaseState,
} from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string>, body?: unknown): RouteCase => ({
  route, permission, params, body, handler: async () => (await load())[route.split(' ')[0]] as never,
})

/** The conversation the guard reads before the permission: the owner's, on the owned project. */
const conversation = (h: RouteCaseState) => {
  h.models.conversation = {
    findUnique: async () => ({ id: 'c1', sessionId: 's1', userId: OWNER, projectId: OWNED_PROJECT }),
  }
}
const onConversation = (c: RouteCase): RouteCase => ({ ...c, arrange: conversation })
const c1 = { id: 'c1' }
const s1 = { sessionId: 's1' }

describeRoutePermissions('conversations and the agent assistants', [
  at('GET /api/conversations?projectId=[projectId]', () => import('./route'), 'agent:chat', { projectId: OWNED_PROJECT }),
  at('POST /api/conversations', () => import('./route'), 'agent:chat', {}, { projectId: OWNED_PROJECT, sessionId: 's-new' }),
  onConversation(at('GET /api/conversations/[id]', () => import('./[id]/route'), 'agent:chat', c1)),
  onConversation(at('PATCH /api/conversations/[id]', () => import('./[id]/route'), 'agent:chat', c1, { title: 't' })),
  onConversation(at('DELETE /api/conversations/[id]', () => import('./[id]/route'), 'agent:chat', c1)),
  onConversation(at('POST /api/conversations/[id]/messages', () => import('./[id]/messages/route'), 'agent:chat', c1, { role: 'user', content: 'x' })),
  onConversation(at('GET /api/conversations/by-session/[sessionId]', () => import('./by-session/[sessionId]/route'), 'agent:chat', s1)),
  onConversation(at('PATCH /api/conversations/by-session/[sessionId]', () => import('./by-session/[sessionId]/route'), 'agent:chat', s1, { title: 't' })),
  onConversation(at('POST /api/conversations/by-session/[sessionId]/messages', () => import('./by-session/[sessionId]/messages/route'),
    'agent:chat', s1, { role: 'user', content: 'x' })),
  onConversation(at('GET /api/conversations/by-session/[sessionId]/fireteams', () => import('./by-session/[sessionId]/fireteams/route'), 'agent:chat', s1)),
  onConversation(at('POST /api/conversations/by-session/[sessionId]/fireteams', () => import('./by-session/[sessionId]/fireteams/route'),
    'agent:chat', s1, { fireteamId: 'f1' })),
  onConversation(at('PATCH /api/conversations/by-session/[sessionId]/fireteams/[fireteamIdKey]',
    () => import('./by-session/[sessionId]/fireteams/[fireteamIdKey]/route'), 'agent:chat', { ...s1, fireteamIdKey: 'f1' }, { status: 'done' })),
  onConversation(at('PATCH /api/conversations/by-session/[sessionId]/fireteams/[fireteamIdKey]/members/[memberIdKey]',
    () => import('./by-session/[sessionId]/fireteams/[fireteamIdKey]/members/[memberIdKey]/route'), 'agent:chat',
    { ...s1, fireteamIdKey: 'f1', memberIdKey: 'm1' }, { status: 'done' })),
  at('POST /api/agent/text-to-cypher', () => import('../agent/text-to-cypher/route'), 'agent:assistants', {},
    { question: 'list ips', project_id: OWNED_PROJECT }),
  at('POST /api/agent/command-whisperer', () => import('../agent/command-whisperer/route'), 'agent:assistants', {},
    { prompt: 'list files', session_type: 'shell', project_id: OWNED_PROJECT }),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})
