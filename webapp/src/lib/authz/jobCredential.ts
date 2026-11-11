/**
 * The scanner key's second half (step 1.16, HD-20). SCANNER_API_KEY sits in every
 * target-facing scan container, so on its own it opens nothing: a scan calls back with
 * the key AND the job credential the webapp minted for its start (X-Redamon-Job), and
 * a scanner-key route reads only that credential's tenant and project. The master key
 * (`isInternalRequest`) is not affected; callers check it first.
 */
import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { CredentialRefused, JOB_CREDENTIAL_HEADER, verifyJobCredential, type MachineClaims } from './machineCredential'

type JobScope = { tenant?: string; projectId?: string }

function checkJob(request: NextRequest, scope: JobScope): { claims: MachineClaims } | { refused: NextResponse } {
  const token = request.headers.get(JOB_CREDENTIAL_HEADER)
  if (!token) return { refused: refusal(request, 'missing') }
  try {
    const claims = verifyJobCredential(token)
    if (scope.tenant !== undefined && claims.ten !== scope.tenant) return { refused: refusal(request, 'tenant_mismatch') }
    if (scope.projectId !== undefined && claims.pid !== scope.projectId) {
      return { refused: refusal(request, 'project_mismatch') }
    }
    return { claims }
  } catch (err) {
    if (err instanceof CredentialRefused) return { refused: refusal(request, err.code) }
    throw err
  }
}

/**
 * Null when the request's job credential is valid and names `tenant` / `projectId`
 * (each checked when given); otherwise the 403 to return, logged with its reason.
 */
export function scannerJobRefusal(request: NextRequest, scope: JobScope): NextResponse | null {
  const checked = checkJob(request, scope)
  return 'refused' in checked ? checked.refused : null
}

/**
 * scannerJobRefusal, and the credential's project must still exist and belong to its
 * tenant (`project_gone` otherwise). A credential copied out of a scan stays valid for
 * up to 7 days after the scan stops; on a route that hands out the owner's secrets it
 * stops working once the project is deleted or has another owner.
 */
export async function scannerJobRefusalForLiveProject(
  request: NextRequest,
  scope: JobScope,
): Promise<NextResponse | null> {
  const checked = checkJob(request, scope)
  if ('refused' in checked) return checked.refused
  const project = await prisma.project.findUnique({ where: { id: checked.claims.pid }, select: { userId: true } })
  if (!project || project.userId !== checked.claims.ten) return refusal(request, 'project_gone')
  return null
}

function refusal(request: NextRequest, reason: string): NextResponse {
  console.warn(`[rbac] job credential refused reason=${reason} route=${request.nextUrl?.pathname ?? ''}`)
  return NextResponse.json(
    {
      error: 'The scanner key reads only with the job credential of a scan of this project and its owner',
      code: 'job_credential_required',
      reason,
    },
    { status: 403 },
  )
}
