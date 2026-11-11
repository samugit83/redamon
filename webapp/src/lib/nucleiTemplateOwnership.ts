/**
 * Who may use which custom Nuclei template (HD-08, F-07).
 *
 * The files live in one shared folder (NUCLEI_TEMPLATES_PATH in the webapp; recon
 * mounts the same host folder read-only at `/custom-templates` in the nuclei container
 * as soon as one custom template is selected, recon/helpers/nuclei_helpers.py). The
 * `NucleiTemplate` table says who owns each file: a null owner, or no row at all, is an
 * instance template. A project may use only its owner's templates and instance
 * templates, so a scan never runs another member's file.
 *
 * Three project fields reach that folder:
 * - `nucleiSelectedCustomTemplates`: paths relative to the folder, passed as
 *   `-t /custom-templates/<path>` (a `.yml` entry is swapped for its `.yaml` sibling
 *   when one exists);
 * - `nucleiTemplates`, `nucleiCustomTemplates`: free-form `-t` values. Nuclei splits a
 *   value on commas, resolves an absolute path as is and a relative one against its
 *   working directory (`/` in the projectdiscovery/nuclei image) and then its templates
 *   directory (`/root/nuclei-templates`), and expands a value holding `*` as a glob. So
 *   `.`, `../..`, `/c*` and `/custom-templates/` all load every file in the mount.
 *
 * Every entry is judged by where it can land: a single template file in the folder
 * must be selectable; anything wider that reaches the mount (the mount itself, a
 * folder, a glob, an ancestor such as `/`) is never selectable; a free-form value that
 * stays outside the mount (an official template) is not this module's business.
 */
import { stat } from 'fs/promises'
import path from 'path'

export const NUCLEI_TEMPLATE_FIELDS = [
  'nucleiSelectedCustomTemplates', 'nucleiTemplates', 'nucleiCustomTemplates',
] as const
export type NucleiTemplateField = (typeof NUCLEI_TEMPLATE_FIELDS)[number]

export const TEMPLATE_NOT_SELECTABLE = 'template_not_selectable'

const MOUNT = 'custom-templates'
const NUCLEI_CWD = '/'
const NUCLEI_TEMPLATE_DIR = '/root/nuclei-templates'
const NUCLEI_HOME = '/root'
const TEMPLATE_FILE = /\.ya?ml$/i
// filepath.Glob syntax; nuclei globs only a value holding `*`, but `?` and `[` are
// then live too, so any of them makes a segment a pattern here.
const GLOB_CHARS = /[*?[\\]/

export type TemplateOwnership = 'own' | 'instance' | 'other'

/** `userId` is the effective user: the owner of the project being edited. */
export function ownershipOf(ownerUserId: string | null | undefined, userId: string): TemplateOwnership {
  if (ownerUserId === null || ownerUserId === undefined) return 'instance'
  return ownerUserId === userId ? 'own' : 'other'
}

export function templatesRoot(): string {
  return process.env.NUCLEI_TEMPLATES_PATH || '/data/nuclei-templates'
}

/** Where one entry can point nuclei inside the mount. */
export type MountReach =
  | { kind: 'outside' }
  | { kind: 'files'; paths: string[] }
  | { kind: 'broad' }

function segmentReachesMount(segment: string): boolean {
  if (segment === MOUNT) return true
  if (!GLOB_CHARS.test(segment)) return false
  // A character class or an escape: assume it can match rather than emulate Go here.
  if (/[[\\]/.test(segment)) return true
  const pattern = segment.replace(/[.+^${}()|]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')
  return new RegExp(`^${pattern}$`).test(MOUNT)
}

/** One absolute, normalized path as nuclei would open it. */
function reachOfAbsolute(abs: string): MountReach {
  const segments = abs.split('/').filter(Boolean)
  // `/` holds the mount: loading it loads every file in it.
  if (segments.length === 0) return { kind: 'broad' }
  if (!segmentReachesMount(segments[0])) return { kind: 'outside' }
  if (segments[0] !== MOUNT || segments.length === 1) return { kind: 'broad' }
  const rest = segments.slice(1)
  if (rest.some(s => GLOB_CHARS.test(s))) return { kind: 'broad' }
  const rel = rest.join('/')
  return TEMPLATE_FILE.test(rel) ? { kind: 'files', paths: [rel] } : { kind: 'broad' }
}

function combine(reaches: MountReach[]): MountReach {
  if (reaches.some(r => r.kind === 'broad')) return { kind: 'broad' }
  const paths = reaches.flatMap(r => (r.kind === 'files' ? r.paths : []))
  return paths.length ? { kind: 'files', paths: [...new Set(paths)] } : { kind: 'outside' }
}

/** Every place a free-form `-t` value can resolve to. */
function freeFormResolutions(value: string): string[] {
  if (path.posix.isAbsolute(value)) return [path.posix.normalize(value)]
  const out = [path.posix.resolve(NUCLEI_CWD, value), path.posix.resolve(NUCLEI_TEMPLATE_DIR, value)]
  if (value === '~' || value.startsWith('~/')) out.push(path.posix.resolve(NUCLEI_HOME, value.slice(1).replace(/^\/+/, '')))
  return out
}

export function mountReach(field: NucleiTemplateField, entry: string): MountReach {
  if (field === 'nucleiSelectedCustomTemplates') {
    // Upload names never hold a comma; one here would become a second -t value.
    if (entry.includes(',')) return { kind: 'broad' }
    const reach = reachOfAbsolute(path.posix.normalize(`/${MOUNT}/${entry}`))
    if (reach.kind !== 'files') return reach
    const [rel] = reach.paths
    return { kind: 'files', paths: /\.yml$/i.test(rel) ? [rel, `${rel.slice(0, -4)}.yaml`] : [rel] }
  }
  const parts = entry.split(',').map(p => p.replace(/["']/g, '').trim()).filter(Boolean)
  return combine(parts.flatMap(p => freeFormResolutions(p).map(reachOfAbsolute)))
}

export interface TemplateOwnerRow { path: string; ownerUserId: string | null }
export interface TemplateRowReader {
  nucleiTemplate: {
    findMany(args: {
      where: { path: { in: string[] } }
      select: { path: true; ownerUserId: true }
    }): Promise<TemplateOwnerRow[]>
  }
}

async function isDirectory(rel: string): Promise<boolean> {
  try {
    return (await stat(path.join(templatesRoot(), rel))).isDirectory()
  } catch {
    return false
  }
}

/** Judges entries against one project owner, reading each row and folder once. */
class SelectionJudge {
  private rows = new Map<string, string | null>()
  private dirs = new Map<string, boolean>()

  constructor(private db: TemplateRowReader, private ownerUserId: string) {}

  async load(reaches: MountReach[]): Promise<void> {
    const paths = [...new Set(reaches.flatMap(r => (r.kind === 'files' ? r.paths : [])))]
    if (paths.length === 0) return
    const rows = await this.db.nucleiTemplate.findMany({
      where: { path: { in: paths } },
      select: { path: true, ownerUserId: true },
    })
    for (const row of rows) this.rows.set(row.path, row.ownerUserId)
    await Promise.all(paths.filter(p => !this.rows.has(p)).map(async p => this.dirs.set(p, await isDirectory(p))))
  }

  selectable(field: NucleiTemplateField, reach: MountReach): boolean {
    if (reach.kind === 'broad') return false
    if (reach.kind === 'outside') return field !== 'nucleiSelectedCustomTemplates'
    return reach.paths.every(p => {
      if (this.rows.has(p)) {
        const owner = this.rows.get(p)
        return owner === null || owner === this.ownerUserId
      }
      return !this.dirs.get(p)
    })
  }
}

const entriesOf = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []

export interface SelectionRefusal {
  error: string
  code: typeof TEMPLATE_NOT_SELECTABLE
  field: NucleiTemplateField
  entry: string
}

/**
 * The first template entry this save ADDS that the project's owner may not use, or
 * null. Entries already stored are not judged, so a file another member uploads later
 * at a path a selection already names cannot block an unrelated save; the service
 * read drops it from every scan instead (`withoutUnselectableTemplates`).
 */
export async function templateSelectionRefusal(
  db: TemplateRowReader,
  { ownerUserId, data, stored }: { ownerUserId: string; data: Record<string, unknown>; stored: Record<string, unknown> },
): Promise<SelectionRefusal | null> {
  const candidates: { field: NucleiTemplateField; entry: string; reach: MountReach }[] = []
  for (const field of NUCLEI_TEMPLATE_FIELDS) {
    if (!(field in data)) continue
    const kept = new Set(entriesOf(stored[field]))
    for (const entry of entriesOf(data[field])) {
      if (!kept.has(entry)) candidates.push({ field, entry, reach: mountReach(field, entry) })
    }
  }
  if (candidates.length === 0) return null
  const judge = new SelectionJudge(db, ownerUserId)
  await judge.load(candidates.map(c => c.reach))
  const refused = candidates.find(c => !judge.selectable(c.field, c.reach))
  if (!refused) return null
  return {
    error: `The Nuclei template "${refused.entry}" in ${refused.field} cannot be used by this project: ` +
      "only the project owner's own templates and instance templates can be selected.",
    code: TEMPLATE_NOT_SELECTABLE,
    field: refused.field,
    entry: refused.entry,
  }
}

/**
 * The project as a scan may read it: every entry of the three fields that is no
 * longer selectable for the project's owner is left out, with how many per field.
 * Covers rows written by import, presets and the MCP tools, which never pass the PUT.
 */
export async function withoutUnselectableTemplates<T extends { userId: string } & Record<string, unknown>>(
  db: TemplateRowReader,
  project: T,
): Promise<{ project: T; dropped: Partial<Record<NucleiTemplateField, number>> }> {
  const present = NUCLEI_TEMPLATE_FIELDS.filter(f => entriesOf(project[f]).length > 0)
  if (present.length === 0) return { project, dropped: {} }
  const reaches = present.map(field => ({
    field, entries: entriesOf(project[field]).map(entry => ({ entry, reach: mountReach(field, entry) })),
  }))
  const judge = new SelectionJudge(db, project.userId)
  await judge.load(reaches.flatMap(r => r.entries.map(e => e.reach)))
  const next: Record<string, unknown> = { ...project }
  const dropped: Partial<Record<NucleiTemplateField, number>> = {}
  for (const { field, entries } of reaches) {
    const kept = entries.filter(e => judge.selectable(field, e.reach)).map(e => e.entry)
    if (kept.length !== entries.length) {
      dropped[field] = entries.length - kept.length
      next[field] = kept
    }
  }
  return Object.keys(dropped).length ? { project: next as T, dropped } : { project, dropped }
}
