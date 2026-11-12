/**
 * Recon presets and custom Nuclei templates ask for their permission (step 3.8; PE-19, PE-22): the
 * account's presets `self:presets` to read, `preset:write` to save, delete or generate one;
 * uploading or deleting a custom template `scan:custom_templates`. All are capabilities with no
 * project: a preset and a template belong to an account (applying a preset to a project is the
 * project's settings save). Real guard, can() and registry; the session and Prisma are doubles
 * (routePermissionCases.ts).
 *
 * @vitest-environment node
 */
import { vi } from 'vitest'

const h = vi.hoisted(() => ({
  identity: vi.fn(), projects: new Map<string, { id: string; userId: string }>(),
  downstream: vi.fn(), upstream: vi.fn(), models: {} as Record<string, unknown>,
}))
vi.hoisted(() => {
  // Read at import time by the templates route; a path that never exists.
  process.env.NUCLEI_TEMPLATES_PATH = '/nonexistent/rbac-preset-permissions-templates'
})
vi.mock('@/lib/session', async (orig) => ({
  ...(await orig<typeof import('@/lib/session')>()),
  getAuthzIdentity: (...a: unknown[]) => h.identity(...a),
  // The routes read the account again after the guard: the same one the identity names.
  getEffectiveUser: async () => {
    const id = await h.identity()
    return id ? { userId: (id.actingAs ?? id.principal).id } : null
  },
  requireSession: async () => {
    const id = await h.identity()
    return id ? { userId: id.principal.id, role: id.principal.role } : new Response(null, { status: 401 })
  },
}))
vi.mock('@/lib/prisma', async () => ({ default: (await import('@/lib/authz/__testing__/routePermissionCases')).authPrisma(h) }))
vi.mock('@/lib/authz/guards', async (orig) => {
  const real = await orig<typeof import('@/lib/authz/guards')>()
  return { ...real, requirePermission: vi.fn(real.requirePermission) }
})

import { describeRoutePermissions, type RouteCase } from '@/lib/authz/__testing__/routePermissionCases'
import { setFlagsForTests } from '@/lib/authz/flags'
import { clearCapabilityCachesForTests } from '@/lib/authz/capabilities'
import { clearInstanceRootCacheForTests } from '@/lib/authz/root'
import type { PermissionId } from '@/lib/authz/permissions'

type Mod = Record<string, unknown>
const at = (route: string, load: () => Promise<Mod>, permission: PermissionId, params: Record<string, string>, body?: unknown): RouteCase => ({
  route, permission, params, body, projectId: null, handler: async () => (await load())[route.split(' ')[0]] as never,
})

describeRoutePermissions('presets and custom templates', [
  at('GET /api/presets', () => import('./route'), 'self:presets', {}),
  at('POST /api/presets', () => import('./route'), 'preset:write', {}, { name: 'mine', settings: {} }),
  at('GET /api/presets/[id]', () => import('./[id]/route'), 'self:presets', { id: 'up1' }),
  at('DELETE /api/presets/[id]', () => import('./[id]/route'), 'preset:write', { id: 'up1' }),
  at('POST /api/presets/generate', () => import('./generate/route'), 'preset:write', {}, { description: 'x' }),
  at('POST /api/nuclei-templates', () => import('@/app/api/nuclei-templates/route'), 'scan:custom_templates', {}, {}),
  at('DELETE /api/nuclei-templates', () => import('@/app/api/nuclei-templates/route'), 'scan:custom_templates', {}),
], h, {
  setFlags: setFlagsForTests,
  clearCaches: () => { clearCapabilityCachesForTests(); clearInstanceRootCacheForTests() },
})
