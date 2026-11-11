/**
 * The scanner key's second half (step 1.16, HD-20). SCANNER_API_KEY sits in every
 * target-facing scan container, so on its own it opens nothing: a scan calls back with
 * the key AND the job credential the webapp minted for its start (X-Redamon-Job), and
 * a scanner-key route reads only that credential's tenant and project. The master key
 * (`isInternalRequest`) is not affected; callers check it first.
 */
import { NextRequest, NextResponse } from 'next/server'
import { CredentialRefused, JOB_CREDENTIAL_HEADER, verifyJobCredential } from './machineCredential'

/**
 * Null when the request's job credential is valid and names `tenant` / `projectId`
 * (each checked when given); otherwise the 403 to return, logged with its reason.
 */
export function scannerJobRefusal(
  request: NextRequest,
  scope: { tenant?: string; projectId?: string },
): NextResponse | null {
  const token = request.headers.get(JOB_CREDENTIAL_HEADER)
  if (!token) return refusal(request, 'missing')
  try {
    const claims = verifyJobCredential(token)
    if (scope.tenant !== undefined && claims.ten !== scope.tenant) return refusal(request, 'tenant_mismatch')
    if (scope.projectId !== undefined && claims.pid !== scope.projectId) return refusal(request, 'project_mismatch')
    return null
  } catch (err) {
    if (err instanceof CredentialRefused) return refusal(request, err.code)
    throw err
  }
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
