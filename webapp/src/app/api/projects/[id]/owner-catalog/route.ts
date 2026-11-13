import { NextRequest, NextResponse } from 'next/server'
import { requireLevel, requirePermission } from '@/lib/authz/guards'
import { rbacFlags } from '@/lib/authz/flags'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { withRouteErrors } from '@/lib/routeErrors'
import { ownerCatalog, ownerModelOptions } from '@/lib/ownerCatalog'

// GET /api/projects/[id]/owner-catalog[?models=1] - the project owner's catalogs for a collaborator's
// project form (step 5.7, SH-26): providers, Jev configurations, attack skills, tradecraft resources,
// MCP servers and which API keys are set, by name and presence, never a value (lib/ownerCatalog.ts).
// The form reads its own account's catalogs for a project it owns; a collaborator's would be the
// wrong account's, so it reads these. `recon:read` (R), as the project GET: whoever sees the project
// sees which of the owner's options its settings name. `?models=1` adds the owner's model options,
// which call the owner's providers through the agent: only for the controls the owner and a co-owner
// change (level M). With RBAC_SHARING_ENABLED off the route does not exist: 404 before anything is
// read (DV-30).
export const GET = withRouteErrors("Could not read the project owner's catalogs", async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!rbacFlags().sharing) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  if (!auth.access) return routeNotFound()
  const wantsModels = request.nextUrl.searchParams.get('models') === '1'
  if (wantsModels) {
    const refused = requireLevel(auth, 'M')
    if (refused) return refused
  }
  const ownerId = auth.access.project.userId
  const catalog = await ownerCatalog(ownerId)
  if (!wantsModels) return NextResponse.json(catalog)
  const listed = await ownerModelOptions(ownerId)
  if ('failure' in listed) return listed.failure
  return NextResponse.json({ ...catalog, models: listed.models })
})
