/**
 * What putting a scan in the queue decides, beyond `recon:schedule` (§5.5): the queue starts the
 * job later as the person who queued it, so queueing (or re-confirming a held job) needs the
 * permission that starts that kind of scan directly, and a full recon in overwrite mode
 * `recon:overwrite`. Without this a person could queue a scan they may not start.
 */
import type { QueueableKind } from '@/lib/enqueueJob'
import type { PermissionId } from './permissions'

export const QUEUED_KIND_PERMISSION: Readonly<Record<QueueableKind, PermissionId>> = Object.freeze({
  full_recon: 'recon:scan',
  partial_recon: 'recon:partial',
  gvm: 'scan:gvm',
  github_hunt: 'scan:secrets',
  trufflehog: 'scan:secrets',
  supply_chain: 'scan:supply_chain',
  supply_chain_repo: 'scan:supply_chain',
  ai_attack: 'scan:ai_attack',
})

/**
 * The permissions a job of `kind` with `payload` needs besides `recon:schedule`, for `requireAlso`.
 * An unknown kind needs none here: the enqueue refuses it (400) before anything is written.
 */
export function queuedJobPermissions(kind: string, payload: unknown): PermissionId[] {
  if (!Object.hasOwn(QUEUED_KIND_PERMISSION, kind)) return []
  const out: PermissionId[] = [QUEUED_KIND_PERMISSION[kind as QueueableKind]]
  const mode = payload && typeof payload === 'object' ? (payload as { mode?: unknown }).mode : undefined
  if (kind === 'full_recon' && mode === 'overwrite') out.push('recon:overwrite')
  return out
}
