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
