/**
 * A single-field save of the project row (step 5.2, SH-40): the auto-saved toggles of the settings
 * form and the chat drawer's settings, the stealth and model switches of the graph page, the traffic
 * capture toggle. Each sends the row's `updatedAt` as the caller last read it, so the PUT's
 * compare-and-swap refuses a save over a value someone else changed meanwhile (a collaborator, the
 * owner in another tab, an MCP agent) instead of overwriting it, as the form's full save already does.
 * On that 409 the caller reloads the row and says so (`STALE_FIELD_NOTICE`). A caller that read no
 * version sends none, and the save is the unconditional one it was before.
 */
import { readApiError } from '@/lib/apiError'
import { STALE_SAVE_MESSAGE, versionOf } from '@/lib/projectVersion'

/** What a refused single-field save tells the person, after the row was read again. */
export const STALE_FIELD_NOTICE = 'Someone else changed this project. It was reloaded: make your change again if you still want it.'

/** Whether a PUT answer is the stale-row 409 (not the PUT's other 409s: a scan running, an activation). */
export function isStaleSave(status: number, body: unknown): boolean {
  if (status !== 409 || !body || typeof body !== 'object') return false
  const { code, error } = body as { code?: unknown; error?: unknown }
  return code === 'stale_save' || error === STALE_SAVE_MESSAGE
}

export type FieldSaveResult =
  | { ok: true; row: Record<string, unknown> | null; version: string | null }
  | { ok: false; stale: true }

/**
 * PUT `fields` to the project with `version` (the row's `updatedAt` as last read). Resolves the saved
 * row and its new version, or `stale` on the stale-row 409; any other failure throws the ApiError
 * (`readApiError`), so the caller shows it as before.
 */
export async function saveProjectFields(
  projectId: string,
  fields: Record<string, unknown>,
  version: string | null | undefined,
  failure: string,
): Promise<FieldSaveResult> {
  const sent = versionOf(version)
  const res = await fetch(`/api/projects/${projectId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(sent ? { ...fields, updatedAt: sent } : fields),
  })
  if (res.ok) {
    const row = await res.json().catch(() => null) as Record<string, unknown> | null
    return { ok: true, row, version: versionOf(row?.updatedAt) }
  }
  if (res.status === 409) {
    const body = await res.clone().json().catch(() => null)
    if (isStaleSave(res.status, body)) return { ok: false, stale: true }
  }
  throw await readApiError(res, failure)
}

/** The project row read again after a stale save; null when it cannot be read (the next save says so). */
export async function reloadProjectRow(projectId: string): Promise<Record<string, unknown> | null> {
  try {
    const res = await fetch(`/api/projects/${projectId}`)
    return res.ok ? await res.json() as Record<string, unknown> : null
  } catch {
    return null
  }
}
