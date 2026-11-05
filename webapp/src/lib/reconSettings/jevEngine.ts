import prisma from '@/lib/prisma'

/**
 * Every per-hook Jev field. The first four are engine switches on an LLM hook
 * (`true` answers it with Jev instead of the LLM); the rest switch on a Jev-only
 * hook that has no LLM twin. A new switch-on needs an explicit owner-owned Jev selection.
 */
export const JEV_ENGINE_FIELDS = [
  'ffufAiUseJev',
  'nucleiTagsAiUseJev',
  'wafAiUseJev',
  'takeoverAiUseJev',
  'ffufJevBasePaths',
  'httpxJevPageType',
  'resourceEnumJevToolHealth',
  'hakrawlerJevSeedOrder',
  'serializedScanJevRank',
  'routeExposureJevRank',
  'routeExposureJevWallCheck',
  'routeExposureJevAssess',
] as const

export type JevEngineField = typeof JEV_ENGINE_FIELDS[number]

/**
 * A Prisma `select` for every field above. A writer that judges a switch-on
 * against the stored row must read all of them: a field it leaves out reads as
 * undefined, so a stored true counts as a switch-on and every save is refused once
 * the project's selected provider is unavailable.
 */
export const JEV_ENGINE_SELECT = {
  ...Object.fromEntries(JEV_ENGINE_FIELDS.map(k => [k, true])),
  jevProviderId: true,
} as { [K in JevEngineField | 'jevProviderId']: true }

export const JEV_HOOK_LABEL: Record<JevEngineField, string> = {
  ffufAiUseJev: 'FFuf extensions',
  nucleiTagsAiUseJev: 'Nuclei tag selection',
  wafAiUseJev: 'WAF classification',
  takeoverAiUseJev: 'takeover disambiguation',
  ffufJevBasePaths: 'FFuf base-path ranking',
  httpxJevPageType: 'page-type labels',
  resourceEnumJevToolHealth: 'silent tool-failure check',
  hakrawlerJevSeedOrder: 'Hakrawler seed order',
  serializedScanJevRank: 'serialized-object ranking',
  routeExposureJevRank: 'route exposure ranking',
  routeExposureJevWallCheck: 'route exposure wall check',
  routeExposureJevAssess: 'route exposure lead assessment',
}

export const JEV_VERIFY_FAILED = "Couldn't verify the project's Jev provider, try again."

type Row = Record<string, unknown> | null | undefined

/** The engine fields a write turns ON: true in `next`, not already true in `before`. */
export function jevSwitchedOn(before: Row, next: Row): JevEngineField[] {
  return JEV_ENGINE_FIELDS.filter(k => next?.[k] === true && before?.[k] !== true)
}

/**
 * Judge the merged selection against the project owner, never the actor.
 * Existing unconfigured hooks may keep falling back during unrelated saves;
 * switching a hook on or changing its non-null provider requires validation.
 */
export async function validateJevEngineChange(
  before: Row,
  next: Row,
  ownerUserId: string | null | undefined,
): Promise<string | null> {
  const on = jevSwitchedOn(before, next)
  const selectionWritten = !!next && Object.prototype.hasOwnProperty.call(next, 'jevProviderId')
  const selection = selectionWritten ? next?.jevProviderId : before?.jevProviderId
  const selectionChanged = selectionWritten && selection !== (before?.jevProviderId ?? null)
  if (on.length === 0 && !selectionChanged) return null
  if (!ownerUserId) return JEV_VERIFY_FAILED
  // Clearing is intentional fallback, but cannot simultaneously switch on a new hook.
  if (selection === null && on.length === 0) return null
  if (typeof selection !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(selection)) {
    const named = on.map(k => `${k} (${JEV_HOOK_LABEL[k]})`).join(', ')
    return `Can't use Jev${named ? ` for ${named}` : ''}: select an explicit Jev provider for this project. ` +
      'Add a TypeSafe or OpenRouter Jev configuration in Settings → LLM Providers, then select it in the project.'
  }
  try {
    const provider = await prisma.userLlmProvider.findFirst({
      where: { id: selection, userId: ownerUserId, providerType: { in: ['jev', 'jev_openrouter'] } },
      select: { id: true },
    })
    if (provider) return null
  } catch {
    return JEV_VERIFY_FAILED
  }
  return 'The selected Jev provider is unavailable or does not belong to the project owner. ' +
    'Select an owner-owned TypeSafe or OpenRouter Jev configuration in the project.'
}

/** Import keeps hook intent but never replays an account-scoped provider id. */
export async function jevImportWarnings(row: Row, _importerUserId: string | null | undefined): Promise<string[]> {
  return JEV_ENGINE_FIELDS.filter(k => row?.[k] === true).map(k =>
    `${k} (${JEV_HOOK_LABEL[k]}) is set to use Jev: this hook uses its static fallback until you ` +
    'select a Jev provider for the imported project. Provider selections do not travel with exports.')
}
