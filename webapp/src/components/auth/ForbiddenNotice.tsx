'use client'

import { ApiError } from '@/lib/apiError'
import { PERMISSIONS, isPermissionId } from '@/lib/authz/permissions'
import styles from './ForbiddenNotice.module.css'

/**
 * The permission a refusal names, or null for any other error: a route's 403 carries
 * `{error, code: 'forbidden', permission}` (authz/guards.ts `forbiddenResponse`, DV-07).
 */
export function forbiddenPermission(error: unknown): string | null {
  if (!(error instanceof ApiError) || error.status !== 403 || error.code !== 'forbidden') return null
  const permission = error.body?.permission
  return typeof permission === 'string' && permission ? permission : null
}

/** The notice as one line, for a control too small to hold it: a disabled button's title. */
export function forbiddenNoticeText(permission: string): string {
  const description = isPermissionId(permission) ? PERMISSIONS[permission].description : null
  return `You do not have the permission this needs. ${permission}${description ? `: ${description}` : '.'} Ask an administrator to grant it to you.`
}

interface ForbiddenNoticeProps {
  /** The id the 403 named; one the registry does not hold is shown as sent, without a description. */
  permission: string
  className?: string
}

/**
 * Why the server refused (UI-12): the permission it named, what that permission allows, and who can
 * change it. Says nothing about the resource, so it adds nothing to what the 403 already told.
 */
export function ForbiddenNotice({ permission, className }: ForbiddenNoticeProps) {
  const description = isPermissionId(permission) ? PERMISSIONS[permission].description : null
  return (
    <div role="alert" className={className ? `${styles.notice} ${className}` : styles.notice}>
      <p className={styles.title}>You do not have the permission this needs.</p>
      <p className={styles.body}>
        <code className={styles.id}>{permission}</code>
        {description && <>: {description}</>}
        {' '}Ask an administrator to grant it to you.
      </p>
    </div>
  )
}

interface RefusalNoticeProps {
  /** What `useRefusal` / `useRefusalCheck` answered (hooks/useCan.ts). */
  refusal: { kind: 'level' | 'permission'; permission: string; text: string }
  className?: string
}

/**
 * The notice for a control refused up front: the permission notice above, or, when the person's
 * access to the project does not reach what the control needs (step 4.11), that access in one line
 * ("Read access, shared by <owner>").
 */
export function RefusalNotice({ refusal, className }: RefusalNoticeProps) {
  if (refusal.kind === 'permission') return <ForbiddenNotice permission={refusal.permission} className={className} />
  return (
    <div role="status" className={className ? `${styles.notice} ${className}` : styles.notice}>
      <p className={styles.title}>{refusal.text}.</p>
      <p className={styles.body}>You can see this project but not change it.</p>
    </div>
  )
}
