/**
 * The account's ingestion settings, the values of the Configure ingestion dialog (§3.2, §4):
 * `TradecraftUserSettings.ingestion` holds only the keys a person changed, so a default the
 * spec changes later reaches every account that never touched it. The only writer of that
 * column; the merge with a resource's overrides is `effectiveSettings.ts`.
 */
import prisma from '@/lib/prisma'
import { lockTradecraftUserSettings } from './switch'
import { effectiveSettings, canonicalJson } from './effectiveSettings'
import {
  SECTIONS, SETTINGS, cloneValue, validateUserSettings, type SettingError, type SettingsValues,
} from './settingsSpec'

const USER_KEYS = SETTINGS.filter(s => s.scope === 'ingestion' && s.level !== 'resource')
const USER_KEY_SET: ReadonlySet<string> = new Set(USER_KEYS.map(s => s.key))

/** The ingestion sections that hold at least one setting a person sets at account level. */
export const INGESTION_SECTIONS: readonly string[] = SECTIONS
  .filter(sec => sec.scope === 'ingestion' && USER_KEYS.some(s => s.section === sec.id))
  .map(sec => sec.id)

export interface IngestionSettingsView {
  values: SettingsValues
  /** The keys whose value comes from the account (a saved value), in spec order. */
  changed: string[]
  defaults: SettingsValues
}

export type SaveResult = { ok: true; view: IngestionSettingsView } | { ok: false; errors: SettingError[] }

export function ingestionDefaults(): SettingsValues {
  const out: SettingsValues = {}
  for (const s of USER_KEYS) out[s.key] = cloneValue(s.default)
  return out
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function viewOf(stored: unknown): IngestionSettingsView {
  const eff = effectiveSettings({ user: { ingestion: stored }, scope: 'ingestion' })
  const values: SettingsValues = {}
  const changed: string[] = []
  for (const s of USER_KEYS) {
    values[s.key] = eff.values[s.key]
    if (eff.provenance[s.key] === 'user') changed.push(s.key)
  }
  return { values, changed, defaults: ingestionDefaults() }
}

export async function readIngestionSettings(userId: string): Promise<IngestionSettingsView> {
  const row = await prisma.tradecraftUserSettings.findUnique({ where: { userId }, select: { ingestion: true } })
  return viewOf(row?.ingestion ?? {})
}

/**
 * Applies `edit` to the stored values under the account's row lock, so two saves at once
 * (two tabs) each start from the other's committed result. Keys the spec does not know are
 * kept: a newer version may have written them, and a roll-back must not erase them.
 */
async function writeStored(
  userId: string, edit: (stored: Record<string, unknown>) => Record<string, unknown>,
): Promise<IngestionSettingsView> {
  return prisma.$transaction(async (tx) => {
    await lockTradecraftUserSettings(tx, userId)
    const row = await tx.tradecraftUserSettings.findUnique({ where: { userId }, select: { ingestion: true } })
    const before = isPlainObject(row?.ingestion) ? row!.ingestion as Record<string, unknown> : {}
    const after = edit({ ...before })
    if (canonicalJson(after) !== canonicalJson(before)) {
      await tx.tradecraftUserSettings.upsert({
        where: { userId },
        create: { userId, ingestion: after as object },
        update: { ingestion: after as object },
      })
    }
    return viewOf(after)
  })
}

/**
 * Saves the values a person changed. Every key must be an ingestion setting of level
 * `user` or `both`, within the range the dialog shows; one bad key refuses the whole save.
 * A value equal to its default removes the key.
 */
export async function saveIngestionSettings(userId: string, input: unknown): Promise<SaveResult> {
  const parsed = validateUserSettings('ingestion', input)
  if (!parsed.ok) return parsed
  const defaults = ingestionDefaults()
  const view = await writeStored(userId, (stored) => {
    for (const [key, value] of Object.entries(parsed.value)) {
      if (canonicalJson(value) === canonicalJson(defaults[key])) delete stored[key]
      else stored[key] = value
    }
    return stored
  })
  return { ok: true, view }
}

/** Resets one section of the dialog, or `all`. */
export async function resetIngestionSettings(userId: string, section: string): Promise<SaveResult> {
  if (section !== 'all' && !INGESTION_SECTIONS.includes(section)) {
    return {
      ok: false,
      errors: [{ key: 'reset', code: 'bad_value', message: `reset must be "all" or one of ${INGESTION_SECTIONS.join(', ')}` }],
    }
  }
  const view = await writeStored(userId, (stored) => {
    for (const key of Object.keys(stored)) {
      if (!USER_KEY_SET.has(key)) continue
      if (section === 'all' || SETTINGS.find(s => s.key === key)!.section === section) delete stored[key]
    }
    return stored
  })
  return { ok: true, view }
}
