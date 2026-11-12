import type { PluginInstall } from '@prisma/client'
import prisma from '@/lib/prisma'
import { accountHolds } from '@/lib/authz/adminPermission'
import { compareVersions, parseVersion } from '@/lib/semver'
import { CatalogError, chooseRelease, isRevoked, loadCatalog, type LoadedCatalog } from './catalog'
import { likePrefix } from './dataStore'
import { hasKeptAnything, rollbackCheck, type RollbackCheck } from './lifecycle'
import { PERMISSION_TEXT, isPluginPermission } from './permissions'
import { PLUGIN_PLATFORM_VERSION } from './platformVersion'
import { pluginIconPath } from './pluginIcon'
import { overridesQualify } from './registry'
import type { CatalogRelease, PluginCatalog } from './schemas/catalog'
import { dataLimits } from './settings'
import { listVersions } from './staging'

/**
 * The model of the Plugins page (README.PLUGINS.md §7.1): one entry per catalog plugin,
 * merged with the installed rows (an installed plugin the catalog no longer lists is still
 * shown and manageable), and the catalog's state in words that say what to do. Only the model
 * of whoever manages plugins (platform:plugins, `viewerIsAdmin`) carries errors and the
 * management details; "Admins only" below means them.
 */
export type CardState =
  | 'not_installed'
  | 'installing'
  | 'updating'
  | 'uninstalling'
  | 'ready'
  | 'disabled'
  | 'failed'
  | 'incompatible'
  | 'revoked'

export interface PermissionView {
  id: string
  title: string
  consent: string
}

export interface CatalogView {
  state: 'ok' | 'unreachable' | 'invalid' | 'untrusted'
  message: string | null
  /**
   * Admins only, when the catalog is not used: the check's own sentence (the file that
   * failed, the HTTP status or errno, the key id, which signature check) and the first
   * schema errors. All the platform's words or our validator's paths, capped.
   */
  detail?: string
  details?: string[]
  official: boolean
  extraKey: boolean
  replayed: boolean
  serial: number | null
}

export interface InstalledView {
  version: string | null
  previousVersion: string | null
  status: string
  enabled: boolean
  dataVersion: number
  grantedPermissions: string[]
  installedAt: string | null
  revokedReason: string | null
  operationKind: string | null
  /** Admins only. */
  lastError?: string | null
}

export interface PluginEntry {
  id: string
  displayName: string
  description: string
  /** Same-origin URL of the avatar the catalog names (api/plugins/[pluginId]/icon); absent when it names none. */
  icon?: string
  /** The plugin's documentation page, from the catalog. */
  docsUrl?: string
  /** null while the catalog cannot be read: whether it still lists the plugin is unknown. */
  inCatalog: boolean | null
  state: CardState
  installed: InstalledView | null
  /** The newest release this platform can run, for Install. */
  available: { version: string; dataVersion: number; platform: string; permissions: PermissionView[] } | null
  update: { version: string; newPermissions: string[]; migratesData: boolean } | null
  /** Why Install cannot be offered now; null when it can. */
  installBlocked: string | null
  /** Admins only: why the last install attempt of a plugin not installed failed. */
  lastAttemptError?: string | null
  /** Admins only: data or skill versions an uninstall with "keep data" left, which Delete kept data removes. */
  keptData?: boolean
}

export interface PluginsPage {
  platformVersion: string
  /** The viewer holds platform:plugins: the management details and actions are theirs. */
  managesPlugins: boolean
  catalog: CatalogView
  plugins: PluginEntry[]
}

const CATALOG_MESSAGES: Record<string, (e: CatalogError) => string> = {
  catalog_unreachable: (e) =>
    `The plugin catalog could not be reached (${e.fetchCode ?? 'network'}). Installed plugins keep working; ` +
    'an admin can install one now with Install from file, giving an archive, its catalog and signature.',
  signature_invalid: () => 'The plugin catalog failed its signature check, so it is not used. Installed plugins keep working.',
  schema_invalid: () => 'The plugin catalog is not a valid catalog for this RedAmon, so it is not used. Installed plugins keep working.',
  unknown_key: () =>
    'The plugin catalog is signed with a key this RedAmon does not trust (PLUGINS_EXTRA_TRUSTED_KEYS). Installed plugins keep working.',
}

const STATE_OF: Record<string, CatalogView['state']> = {
  catalog_unreachable: 'unreachable',
  signature_invalid: 'invalid',
  schema_invalid: 'invalid',
  unknown_key: 'untrusted',
}

const CATALOG_DETAIL_MAX = 300
const CATALOG_DETAILS_MAX = 5

const capped = (text: string, max: number) => (text.length > max ? `${text.slice(0, max)}…` : text)

function catalogView(loaded: LoadedCatalog | null, error: CatalogError | null, manages: boolean): CatalogView {
  if (!loaded) {
    const code = error?.code ?? 'catalog_unreachable'
    const details = error?.details?.slice(0, CATALOG_DETAILS_MAX).map((d) => capped(d, CATALOG_DETAIL_MAX))
    return {
      state: STATE_OF[code] ?? 'unreachable',
      message: error ? (CATALOG_MESSAGES[code] ?? (() => error.message))(error) : null,
      ...(manages && error ? { detail: capped(error.message, CATALOG_DETAIL_MAX) } : {}),
      ...(manages && details?.length ? { details } : {}),
      official: false,
      extraKey: false,
      replayed: false,
      serial: null,
    }
  }
  return {
    state: 'ok',
    message: null,
    official: loaded.official,
    extraKey: loaded.warnings.includes('extra_key'),
    replayed: loaded.warnings.includes('replayed'),
    serial: loaded.serial,
  }
}

export function permissionViews(ids: string[]): PermissionView[] {
  return ids.map((id) =>
    isPluginPermission(id) ? { id, ...PERMISSION_TEXT[id] } : { id, title: id, consent: 'A permission this RedAmon does not know.' },
  )
}

export function cardState(row: PluginInstall | null): CardState {
  if (!row || row.status === 'available') return 'not_installed'
  if (row.status === 'installing' || row.status === 'updating' || row.status === 'uninstalling') return row.status
  if (row.revokedReason != null) return 'revoked'
  if (row.status === 'failed') return 'failed'
  if (row.status === 'incompatible') return 'incompatible'
  return row.enabled ? 'ready' : 'disabled'
}

function installedView(row: PluginInstall, manages: boolean): InstalledView {
  const v: InstalledView = {
    version: row.activeVersion,
    previousVersion: row.previousVersion,
    status: row.status,
    enabled: row.enabled,
    dataVersion: row.dataVersion,
    grantedPermissions: Array.isArray(row.grantedPermissions) ? (row.grantedPermissions as string[]) : [],
    installedAt: row.installedAt ? new Date(row.installedAt).toISOString() : null,
    revokedReason: row.revokedReason,
    operationKind: row.operationKind,
  }
  if (manages) v.lastError = row.lastError
  return v
}

function entryOf(
  id: string,
  meta: Pick<PluginCatalog['plugins'][number], 'displayName' | 'description' | 'icon' | 'docsUrl'> | null,
  releases: CatalogRelease[] | null,
  row: PluginInstall | null,
  loaded: LoadedCatalog | null,
  manages: boolean,
): PluginEntry {
  const manifest = row?.manifest as { displayName?: string; description?: string } | null
  const best = releases && loaded ? chooseRelease({ id, releases }, PLUGIN_PLATFORM_VERSION, loaded.catalog.revoked) : null
  const state = cardState(row)
  const installedState = state !== 'not_installed'
  let update: PluginEntry['update'] = null
  if (best && row?.activeVersion && installedState &&
      compareVersions(parseVersion(best.version), parseVersion(row.activeVersion)) > 0) {
    const granted = Array.isArray(row.grantedPermissions) ? (row.grantedPermissions as string[]) : []
    update = {
      version: best.version,
      newPermissions: best.permissions.filter((p) => !granted.includes(p)),
      migratesData: best.dataVersion !== row.dataVersion,
    }
  }
  let installBlocked: string | null = null
  if (!loaded) installBlocked = 'The catalog is unavailable.'
  else if (!releases) installBlocked = 'The catalog in use does not list this plugin.'
  else if (!best) {
    const newestRevoked = chooseRelease({ id, releases }, PLUGIN_PLATFORM_VERSION, [])
    installBlocked = newestRevoked
      ? `Every release of this plugin that runs on this RedAmon was revoked: ${isRevoked(loaded.catalog, id, newestRevoked.version)}`
      : 'No release of this plugin runs on this RedAmon; it needs a newer RedAmon.'
  }
  const entry: PluginEntry = {
    id,
    displayName: meta?.displayName ?? manifest?.displayName ?? id,
    description: meta?.description ?? manifest?.description ?? '',
    inCatalog: loaded ? !!releases : null,
    state,
    installed: row && installedState ? installedView(row, manages) : null,
    available: best
      ? { version: best.version, dataVersion: best.dataVersion, platform: best.platform, permissions: permissionViews(best.permissions) }
      : null,
    update,
    installBlocked,
  }
  if (meta?.icon) entry.icon = pluginIconPath(id, meta.icon.sha256)
  if (meta?.docsUrl) entry.docsUrl = meta.docsUrl
  if (manages && row && !installedState) entry.lastAttemptError = row.lastError
  return entry
}

/** Whether the viewer manages plugins (`platform:plugins`), on a fresh read of the account. */
export async function viewerIsAdmin(userId: string): Promise<boolean> {
  return accountHolds(userId, 'platform:plugins', { fresh: true })
}

export async function buildPluginsPage(manages: boolean): Promise<PluginsPage> {
  let loaded: LoadedCatalog | null = null
  let error: CatalogError | null = null
  try {
    loaded = await loadCatalog({ source: 'official' })
  } catch (e) {
    if (!(e instanceof CatalogError)) throw e
    error = e
  }
  const rows = await prisma.pluginInstall.findMany({ orderBy: { pluginId: 'asc' } })
  const byId = new Map(rows.map((r) => [r.pluginId, r]))
  const plugins: PluginEntry[] = []
  for (const p of loaded?.catalog.plugins ?? []) {
    plugins.push(entryOf(p.id, p, p.releases, byId.get(p.id) ?? null, loaded, manages))
    byId.delete(p.id)
  }
  // Installed (or kept after "uninstall, keep data") but not in the catalog in use. A row that
  // keeps nothing (an attempt that failed, a plugin delisted) has nothing to show or manage.
  for (const row of byId.values()) {
    if (row.status === 'available' && (!manages || !(await hasKeptAnything(row.pluginId)))) continue
    plugins.push(entryOf(row.pluginId, null, null, row, loaded, manages))
  }
  if (manages) {
    for (const e of plugins) {
      if (e.state === 'not_installed' && rows.some((r) => r.pluginId === e.id) && (await hasKeptAnything(e.id))) e.keptData = true
    }
  }
  plugins.sort((a, b) => a.displayName.localeCompare(b.displayName))
  return { platformVersion: PLUGIN_PLATFORM_VERSION, managesPlugins: manages, catalog: catalogView(loaded, error, manages), plugins }
}

export interface PluginDetail {
  plugin: PluginEntry
  admin?: {
    lastError: string | null
    versionsOnDisk: string[]
    grantedPermissions: PermissionView[]
    data: { rows: number; bytes: number; maxRows: number; maxBytes: number }
    activeVersions: number
    /** Approved versions that do not reach the agent while the plugin is in this state. */
    dormantVersions: number
    /** Proposals for people's own skills: waiting for review, and saved as new skills. */
    userSkillProposals: { waiting: number; saved: number }
    rollback: RollbackCheck
  }
}

export async function buildPluginDetail(pluginId: string, manages: boolean): Promise<PluginDetail | null> {
  const page = await buildPluginsPage(manages)
  const plugin = page.plugins.find((p) => p.id === pluginId)
  const row = await prisma.pluginInstall.findUnique({ where: { pluginId } })
  if (!plugin && !row) return null
  const entry = plugin ?? entryOf(pluginId, null, null, row, null, manages)
  if (!manages) return { plugin: entry }
  const [usage, overrides] = await Promise.all([
    prisma.pluginData.aggregate({
      where: { pluginId, namespace: 'live', NOT: { collection: { startsWith: likePrefix('__') } } },
      _count: { _all: true },
      _sum: { sizeBytes: true },
    }),
    prisma.pluginOverride.findMany({ where: { pluginId, status: 'active' }, select: { changeSetId: true } }),
  ])
  const activeVersions = new Set(overrides.map((o) => o.changeSetId)).size
  const userSkillRows = await prisma.pluginOverride.findMany({
    where: { pluginId, extensionPoint: 'user_skill.text', status: { in: ['proposed', 'adopted'] } },
    select: { changeSetId: true, status: true },
  })
  const setsWith = (status: string) => new Set(userSkillRows.filter((r) => r.status === status).map((r) => r.changeSetId)).size
  const limits = dataLimits()
  return {
    plugin: entry,
    admin: {
      lastError: row?.lastError ?? null,
      versionsOnDisk: await listVersions(pluginId),
      grantedPermissions: permissionViews(Array.isArray(row?.grantedPermissions) ? (row!.grantedPermissions as string[]) : []),
      data: { rows: usage._count._all, bytes: usage._sum.sizeBytes ?? 0, maxRows: limits.maxRows, maxBytes: limits.maxBytes },
      activeVersions,
      dormantVersions: row && overridesQualify(row) ? 0 : activeVersions,
      userSkillProposals: { waiting: setsWith('proposed'), saved: setsWith('adopted') },
      rollback: await rollbackCheck(pluginId),
    },
  }
}
