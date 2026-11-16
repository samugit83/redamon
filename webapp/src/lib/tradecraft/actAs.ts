/**
 * The act-as rules for a resource's site login (§6.6): while an administrator acts as the
 * account, the login is masked, cannot be changed and is not used. Phase 6 (T6.5) fills this
 * module; until then no resource holds a login, so nothing is refused here. The GitHub token's
 * refusal (`use_github_token`) stays where it is, in the routes that would send the token.
 */
import type { NextResponse } from 'next/server'

export interface LoginUseContext {
  ownerId: string
  resourceId: string
}

/** The refusal of a login's use or change under act-as, or null. */
export async function loginUseRefusal(ctx: LoginUseContext): Promise<NextResponse | null> {
  void ctx
  return null
}
