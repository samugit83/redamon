import { NextRequest, NextResponse } from 'next/server'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { requireAccountWrite, type EffectiveUser } from '@/lib/session'

/**
 * The guard of the user-skill routes only the upload dialog calls: a same-origin browser
 * request that passes the account's write rule (requireAccountWrite: the real signed-in
 * user is `id`, or an admin acting as a passwordless managed `id`). No internal key and no
 * admin bypass: these routes create skills the agent runs, or spend the owner's model
 * keys, and an admin acting as an account that can sign in for itself does not write it
 * (HD-23). The answer is the user the request acts for: `id`.
 */
export async function requireOwnBrowserRequest(request: NextRequest, id: string): Promise<NextResponse | EffectiveUser> {
  if (!sameOrigin(request)) return crossOriginResponse()
  const denied = await requireAccountWrite(id)
  if (denied) return denied
  return { userId: id }
}
