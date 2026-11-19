/**
 * The act-as rules for a resource's site login (§6.6): while an administrator acts as the
 * account, the login is masked (everywhere, `masking.ts`), cannot be changed, and is not used.
 *  - Use (`use_site_logins`): Add, Refresh, Save & re-ingest, Check URL, the focus preview, Read
 *    now and the Map view's page text, on a resource that holds a login or with a login the
 *    request carries;
 *  - Change (`change_site_logins`, D-37): every write of the login, on any account, including
 *    the passwordless managed accounts `requireUserAccess` lets an acting administrator write.
 * The refusals follow the permissions switch, like every act-as refusal (`refuseWhileActingAsOn`
 * answers null with it off). The GitHub token's refusal (`use_github_token`) stays where it is,
 * in the routes that would send the token.
 *
 * A login change is audited in the write's own transaction, with the names of what changed.
 */
import type { NextResponse } from 'next/server'
import { writeAuditTx, type AuditTx } from '@/lib/audit'
import { actorFields } from '@/lib/auditActor'
import { refuseWhileActingAsOn } from '@/lib/authz/actAsRefusals'
import type { JobActor } from './jobs'
import { hasStoredLogin } from './masking'
import { loadOwnResource } from './resourceAccess'
import { changedLoginFields, hasCredentials } from './v2/fields'

export interface LoginUseContext {
  ownerId: string
  /** A saved resource, read here by its id and its account. */
  resourceId?: string | null
  /** A saved resource the caller already read. */
  resource?: { hasLogin: boolean; credentials: unknown } | null
  /** A login carried by the request itself (a Check URL of a resource being added). */
  credentials?: unknown
}

/** The 403 when the action would use a site login while someone acts as the account; null otherwise. */
export async function loginUseRefusal(ctx: LoginUseContext): Promise<NextResponse | null> {
  let login = ctx.credentials !== undefined && ctx.credentials !== null && hasCredentials(ctx.credentials)
  if (!login) {
    const row = ctx.resource ?? (ctx.resourceId ? await loadOwnResource(ctx.ownerId, ctx.resourceId) : null)
    login = !!row && hasStoredLogin(row)
  }
  return login ? refuseWhileActingAsOn(ctx.ownerId, 'use_site_logins') : null
}

/** The 403 when a write would add, change or remove a site login while someone acts as the account. */
export async function loginChangeRefusal(ownerId: string): Promise<NextResponse | null> {
  return refuseWhileActingAsOn(ownerId, 'change_site_logins')
}

/**
 * The `tradecraft.credentials_changed` row of a login write, through the write's transaction:
 * field and header names only, with whether the resource holds a login before and after. The
 * person is the job's real actor, the account acted as on whose behalf. No change, no row.
 */
export async function auditLoginChange(tx: AuditTx, input: {
  actor: JobActor
  ownerId: string
  resourceId: string
  before: unknown
  after: unknown
  /** The row's flag, when it may say more than the stored login (a login the flag alone records). */
  beforeHasLogin?: boolean
}): Promise<void> {
  const changed = changedLoginFields(input.before, input.after)
  const was = input.beforeHasLogin ?? hasCredentials(input.before)
  const is = hasCredentials(input.after)
  if (changed.length === 0 && was === is) return
  const { actorUserId, realActorUserId } = input.actor
  await writeAuditTx(tx, {
    ...actorFields({
      actorId: realActorUserId ?? actorUserId,
      onBehalfOfUserId: realActorUserId ? actorUserId : null,
      actorEmail: null,
    }),
    action: 'tradecraft.credentials_changed',
    permission: 'self:tradecraft',
    targetType: 'tradecraft_resource',
    targetId: input.resourceId,
    before: { hasLogin: was },
    after: { hasLogin: is, changed },
  })
}
