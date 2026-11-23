/**
 * Copies of community skills imported before a catalog edit keep their old text (gap G-29): the
 * import answers them in `outdated` and replaces one only when the person chose it, since a copy
 * may carry their own edits. Shared by Global Settings → Agent Skills and the project form.
 */
export interface OutdatedSkill {
  skillId: string
  name: string
  communityId: string
}

export function outdatedOf(result: unknown): OutdatedSkill[] {
  const list = result && typeof result === 'object' ? (result as { outdated?: unknown }).outdated : null
  if (!Array.isArray(list)) return []
  return list.filter((o): o is OutdatedSkill => !!o && typeof o === 'object'
    && typeof (o as OutdatedSkill).skillId === 'string' && typeof (o as OutdatedSkill).name === 'string')
}

const NAMES_SHOWN = 10

export function outdatedPrompt(list: OutdatedSkill[]): string {
  const names = list.slice(0, NAMES_SHOWN).map(o => `"${o.name}"`).join(', ')
  const more = list.length > NAMES_SHOWN ? ` and ${list.length - NAMES_SHOWN} more` : ''
  return `${list.length} of your skills differ from the Community catalog's current version: ${names}${more}. ` +
    'Update them to the catalog\'s version? This replaces their text, including any changes you made to them.'
}

/**
 * Asks about the outdated copies of `result`, then sends the update for them. Null when there are
 * none or the person declined; the second answer otherwise (it may itself be a failure).
 */
export async function offerCommunityUpdates(
  userId: string, result: unknown, confirm: (message: string, title: string) => Promise<boolean>,
): Promise<Response | null> {
  const outdated = outdatedOf(result)
  if (outdated.length === 0) return null
  if (!(await confirm(outdatedPrompt(outdated), 'Update your community skills?'))) return null
  return fetch(`/api/users/${userId}/attack-skills/import-community`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ update: outdated.map(o => o.skillId) }),
  })
}
