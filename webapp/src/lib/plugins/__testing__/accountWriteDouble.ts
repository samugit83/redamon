/**
 * The account write rule of `requireAccountWrite` (lib/session.ts, HD-23) for route tests
 * that replace `@/lib/session` with a session double: the signed-in user is the account,
 * or an admin acts as a passwordless managed account (`managed`). The real rule, over
 * signed tokens, is proved in session.userAccess.test.ts.
 */
import { NextResponse } from 'next/server'

export interface AccountWriteState {
  session: unknown
  /** The account the session acts as (the act-as cookie), '' when none. */
  effective: string
  /** Accounts without a password: an admin acting as one may write it. */
  managed?: ReadonlySet<string>
}

export function accountWriteDouble(state: () => AccountWriteState) {
  return async (targetUserId: string): Promise<NextResponse | null> => {
    const { session, effective, managed } = state()
    const s = session as { userId?: string; role?: string } | null
    if (!s?.userId) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    if (s.userId === targetUserId) return null
    if (s.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    if (effective === targetUserId && managed?.has(targetUserId)) return null
    return NextResponse.json(
      { error: 'Only the account itself can change this.', code: 'own_account_only' },
      { status: 403 },
    )
  }
}
