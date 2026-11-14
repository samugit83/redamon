'use client'

import type { MyAccess } from '@/lib/authz/projectAccess'
import { catalogPickRefusal } from '@/lib/settingsFieldAccess'
import { useOwnerCatalog, type OwnerCatalogSource } from '@/hooks/useOwnerCatalog'

/**
 * Whether a screen of `access`'s project runs on the project OWNER's catalog rather than the
 * person's own account: any access that is not the owner's; never with RBAC_SHARING_ENABLED off (no
 * `myAccess`, DV-30). The reports page asks it for the narratives model, which is the owner's too.
 */
export function readsOwnerCatalog(access: MyAccess | null | undefined): access is MyAccess {
  return !!access && access.level !== 'owner'
}

/**
 * The project owner's catalog for a screen that shows `access`'s project (step 5.7, SH-26): the one
 * rule the settings form and the graph page (Other Scans, the AI drawer) share. Any access that is
 * not the owner's (read, write, oversight, break-glass) reads it, because the project runs on the
 * owner's keys, models, skills and MCP servers; the owner, and every screen with
 * RBAC_SHARING_ENABLED off (no `myAccess`), get null and read their own account as before (DV-30).
 * The owner's models are read only at Manage, and only while `models` (a screen whose picker is not
 * on view passes false, so the agent's model listing is not asked on every page view).
 *
 * A module of its own so the settings classes it imports stay out of every screen that only reads
 * the context (useCredentialKeys and the sections).
 */
export function useProjectOwnerCatalog(
  projectId: string | null | undefined,
  access: MyAccess | null | undefined,
  { models = true }: { models?: boolean } = {},
): OwnerCatalogSource | null {
  const enabled = readsOwnerCatalog(access)
  const pickRefusal = enabled ? catalogPickRefusal(access) : null
  return useOwnerCatalog(projectId, { enabled, models: models && enabled && pickRefusal === null, pickRefusal })
}
