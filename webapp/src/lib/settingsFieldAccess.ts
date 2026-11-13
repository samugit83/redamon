/**
 * What a collaborator's project form lets them change (step 5.7, SH-26, SH-08): the server's own
 * settings classes (lib/authz/settingsRisk.ts, step 5.1) judged in the browser against the row as
 * stored, so a change the person's access does not reach is refused where it is made, with the
 * reason, instead of failing the whole save later. A Read + Write share changes ordinary settings
 * and tightens safety gates; loosening a gate needs Manage (and Exploitation & shells for the gates
 * that toggle relies on); the scope needs Manage to narrow and the owner to widen; the owner's
 * secrets are the owner's alone. The project PUT still decides every save.
 *
 * Picking from the owner's catalog (the owner's models, Jev configurations, skills and MCP tools)
 * needs Manage: those controls are disabled below it.
 *
 * No `myAccess` (RBAC_SHARING_ENABLED off) or the owner's own access: nothing is refused (DV-30).
 * Data only, no React: tests and the form share it.
 */
import { classifyField, NEED_LABEL, NEED_LEVELS, type SettingsNeed } from '@/lib/authz/settingsRisk'
import type { MyAccess } from '@/lib/authz/projectAccess'
import { sameValue } from '@/lib/reconSettings/roeParse'
import { myAccessMeets, readAccessNotice } from '@/lib/readOnlyProject'
import { sharedByLabel } from '@/lib/sharedProjects'

export interface FieldChangeRefusal {
  key: string
  needs: SettingsNeed
  /** "<key> needs Manage (loosens a safety gate: ...). Read + Write access without Manage, shared by <owner>." */
  text: string
}

const collaborator = (access: MyAccess | null | undefined): access is MyAccess => !!access && access.level !== 'owner'

function reaches(access: MyAccess, needs: SettingsNeed): boolean {
  return NEED_LEVELS[needs].every(level => myAccessMeets(access, level))
}

/**
 * The first of `changes` that `access` may not make to the stored row, or null. `current` is the
 * form as it stands, so the rules that read another field (the RoE window, the target the
 * subdomain prefixes hang under) see what the save would send; a value equal to the stored one is
 * no change, as on the server.
 */
export function fieldChangeRefusal(
  stored: Record<string, unknown>,
  current: Record<string, unknown>,
  changes: Record<string, unknown>,
  access: MyAccess | null | undefined,
): FieldChangeRefusal | null {
  if (!collaborator(access)) return null
  const afterRow = { ...stored, ...current, ...changes }
  for (const key of Object.keys(changes)) {
    if (sameValue(stored[key], changes[key])) continue
    const risk = classifyField(key, stored[key], changes[key], stored, afterRow)
    if (reaches(access, risk.needs)) continue
    const missing = NEED_LEVELS[risk.needs].find(level => !myAccessMeets(access, level)) ?? null
    return {
      key,
      needs: risk.needs,
      text: `${key} needs ${NEED_LABEL[risk.needs]}${risk.reason ? ` (${risk.reason})` : ''}. ${readAccessNotice(access, missing)}.`,
    }
  }
  return null
}

/** Why `access` may not pick from the owner's catalog (below Manage), or null. */
export function catalogPickRefusal(access: MyAccess | null | undefined): string | null {
  if (!collaborator(access) || myAccessMeets(access, 'M')) return null
  return `${readAccessNotice(access, 'M')}: picking from the owner's models, Jev configurations, skills and MCP tools needs Manage`
}

/** What a Read + Write share may change in the form, said once above it; null for any other access. */
export function writeAccessSummary(access: MyAccess | null | undefined): string | null {
  if (!access || access.level !== 'write') return null
  const owner = sharedByLabel({ myAccess: access })
  const exploitNote = myAccessMeets(access, 'W+X') ? '' : ' (the approval, tunnel and Kali gates also need Exploitation & shells)'
  if (myAccessMeets(access, 'M')) {
    return `Read + Write access with Manage, shared by ${owner}. You can change settings, loosen safety gates${exploitNote}, ` +
      "narrow the targets and engagement limits, and pick from the owner's models, Jev configurations, skills and MCP tools. " +
      "Widening the scope, and the owner's credentials, custom headers and RoE record, are the owner's alone."
  }
  return `Read + Write access, shared by ${owner}. You can change ordinary settings and tighten safety gates. ` +
    `Loosening a safety gate needs Manage${exploitNote}; the targets and engagement limits need Manage to narrow them ` +
    "and the owner to widen them; picking from the owner's models, Jev configurations, skills and MCP tools needs Manage. " +
    "The owner's credentials, custom headers and RoE record are the owner's alone."
}
