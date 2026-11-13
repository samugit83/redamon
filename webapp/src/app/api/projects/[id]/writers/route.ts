import { NextRequest, NextResponse } from 'next/server'
import { requireLevel, requirePermission } from '@/lib/authz/guards'
import { withRouteErrors } from '@/lib/routeErrors'
import { routeNotFound } from '@/lib/authz/accountStatus'
import { sharingInForce } from '@/lib/authz/sharingPolicy'
import { otherWritersView } from '@/lib/authz/projectWriters'

// GET /api/projects/[id]/writers - who else is writing the project right now (step 5.11, SH-40):
// each live scan, agent session, triage run or mute-rule apply of another person, with that
// person's name, email and account type, for the ProjectWriters banner. Never the caller's own,
// never an account id. graph:read, then the Write level: the people who could start a writer are
// the ones the banner is for (a Read share, an overseer, break-glass get 403). With sharing not in
// force the route does not exist: 404 before anything is read (DV-30).
export const GET = withRouteErrors('Could not read who is writing the project', async (
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) => {
  if (!(await sharingInForce()).enabled) return routeNotFound()
  const { id } = await params
  const auth = await requirePermission(request, 'graph:read', { projectId: id })
  if (auth instanceof NextResponse) return auth
  const refused = requireLevel(auth, 'W')
  if (refused) return refused
  return NextResponse.json(await otherWritersView(id, auth.access!.project.userId, auth.effective.userId))
})
