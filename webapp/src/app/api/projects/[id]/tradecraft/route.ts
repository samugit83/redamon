import { NextRequest, NextResponse } from 'next/server'
import { requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { projectTradecraftView } from '@/lib/tradecraft/projectView'

// GET /api/projects/[id]/tradecraft - the project's Tradecraft Resources accordion and the counts of
// the chat's top bar (§3.4, T4.4). `recon:read`, as the project GET: whoever reads the project reads
// which of the owner's resources it uses. Whose resources and whether the viewer owns the project
// come from the access the guard answered, never from the caller (lib/tradecraft/projectView.ts says
// what each viewer gets).
export const GET = withRouteErrors("Could not read the project's tradecraft resources", async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  const { id } = await params
  const auth = await requirePermission(request, 'recon:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  if (!auth.access) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json(await projectTradecraftView({
    projectId: id,
    ownerId: auth.access.project.userId,
    viewer: { personId: auth.effective.userId, actorId: auth.actingAs ? auth.principal.id : null },
    viewerIsOwner: auth.access.via === 'owner',
  }))
})
