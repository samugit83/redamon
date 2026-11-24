/**
 * The custom Nuclei templates a person's Kali sandbox may hold (FU-6). Every ensure names them
 * (`EnsureRequest.custom_templates`), and the orchestrator copies exactly those files into the
 * view's sandbox; without the field it copies none. The rule is the template routes' own
 * (`ownershipOf`, nucleiTemplateOwnership.ts): the person's own templates and the instance's (a null
 * owner, or a file with no row), never another person's. The person is the sandbox's, so the act_as
 * view gets the member's templates, never the acting admin's.
 *
 * The person's own and the null-owner templates come from their rows, each path checked on disk
 * segment by segment without following a link, so nobody else's uploads can crowd them out. Only a
 * file with no row (an instance template from before the rows, or one an operator copied in) needs
 * the walk, which reads at most WALK_MAX_ENTRIES directory entries, CUSTOM_TEMPLATES_MAX_DEPTH
 * folders deep, and follows no link. At most SANDBOX_TEMPLATES_MAX paths are named, each in the
 * orchestrator's own shape (`normalize_template_paths`), so nothing named can leave the folder.
 *
 * Server-side only.
 */
import { lstat, opendir, stat } from 'fs/promises'
import path from 'path'
import prisma from '@/lib/prisma'
import { ownershipOf, templatesRoot } from '@/lib/nucleiTemplateOwnership'

// recon_orchestrator/sandbox_contract.py `_TEMPLATE_SEGMENT`, `_TEMPLATE_FILE`, CUSTOM_TEMPLATES_MAX_DEPTH:
// plain segments (none dot-led, so no `..` and no hidden file), ending in .yaml or .yml.
const TEMPLATE_SEGMENT = /^[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}$/
const TEMPLATE_FILE = /\.ya?ml$/i
export const CUSTOM_TEMPLATES_MAX_DEPTH = 8
/** recon_orchestrator/sandbox_manager.py CUSTOM_TEMPLATES_MAX_FILES: the orchestrator copies no more. */
export const SANDBOX_TEMPLATES_MAX = 2000
/** Directory entries the walk for files with no row reads: a folder flooded with files costs a bounded read. */
export const WALK_MAX_ENTRIES = 20_000

/** A path the orchestrator accepts: relative, plain segments, a template file, at most 8 deep. */
export function isSandboxTemplatePath(rel: string): boolean {
  const parts = rel.split('/')
  return parts.length <= CUSTOM_TEMPLATES_MAX_DEPTH && TEMPLATE_FILE.test(parts[parts.length - 1])
    && parts.every(p => TEMPLATE_SEGMENT.test(p))
}

/** Whether `rel` is a regular file under `root` with no link on the way: lstat never follows one. */
async function plainFile(root: string, rel: string, dirs: Map<string, Promise<boolean>>): Promise<boolean> {
  const parts = rel.split('/')
  for (let i = 1; i < parts.length; i++) {
    const dir = parts.slice(0, i).join('/')
    let isDir = dirs.get(dir)
    if (!isDir) {
      isDir = lstat(path.join(root, dir)).then(s => s.isDirectory(), () => false)
      dirs.set(dir, isDir)
    }
    if (!(await isDir)) return false
  }
  return lstat(path.join(root, rel)).then(s => s.isFile(), () => false)
}

/** The first SANDBOX_TEMPLATES_MAX of `paths`, in order, that are plain files on disk. */
async function existingFiles(root: string, paths: string[]): Promise<string[]> {
  const dirs = new Map<string, Promise<boolean>>()
  const out: string[] = []
  for (const rel of paths) {
    if (out.length >= SANDBOX_TEMPLATES_MAX) break
    if (await plainFile(root, rel, dirs)) out.push(rel)
  }
  return out
}

/** Template files under `root` that no row names, as posix paths relative to it. */
async function filesWithoutRow(root: string, rowed: ReadonlySet<string>): Promise<string[]> {
  const found: string[] = []
  const queue: { dir: string; rel: string[] }[] = [{ dir: root, rel: [] }]
  let read = 0
  while (queue.length > 0 && read < WALK_MAX_ENTRIES && found.length < SANDBOX_TEMPLATES_MAX) {
    const { dir, rel } = queue.shift()!
    let handle
    try {
      handle = await opendir(dir)
    } catch (err) {
      // The folder itself unreadable is the caller's failure; a subfolder that went away is skipped.
      if (rel.length === 0) throw err
      continue
    }
    // Read lazily: leaving the loop closes the folder, so a huge one is never listed whole.
    for await (const entry of handle) {
      if (++read > WALK_MAX_ENTRIES) break
      // A Dirent describes the link itself: a symbolic link is neither, so it is never followed.
      if (!TEMPLATE_SEGMENT.test(entry.name)) continue
      const parts = [...rel, entry.name]
      const relPath = parts.join('/')
      if (entry.isDirectory()) {
        if (parts.length < CUSTOM_TEMPLATES_MAX_DEPTH) queue.push({ dir: path.join(dir, entry.name), rel: parts })
      } else if (entry.isFile() && !rowed.has(relPath) && isSandboxTemplatePath(relPath)) {
        found.push(relPath)
      }
    }
  }
  return found
}

let lastWarned = 0

/** A folder that cannot be read gives the sandbox no template (fail closed); a missing one is silent. */
function unreadable(err: unknown): string[] {
  const code = (err as NodeJS.ErrnoException)?.code ?? 'error'
  if (code !== 'ENOENT' && Date.now() - lastWarned > 60_000) {
    lastWarned = Date.now()
    console.warn(`[sandbox] the custom nuclei templates folder could not be read (${code}): no sandbox gets one`)
  }
  return []
}

/**
 * The relative paths of the custom templates `userId` may use, for their sandbox, sorted. No folder
 * is no template. A database failure throws, as every other read of an ensure does.
 */
export async function sandboxCustomTemplates(userId: string): Promise<string[]> {
  const root = templatesRoot()
  try {
    if (!(await stat(root)).isDirectory()) return []
  } catch (err) {
    return unreadable(err)
  }
  const rows = await prisma.nucleiTemplate.findMany({ select: { path: true, ownerUserId: true } })
  const usable = rows
    .filter(r => ownershipOf(r.ownerUserId, userId) !== 'other' && isSandboxTemplatePath(r.path))
    .map(r => r.path)
    .sort()
  try {
    const [owned, unrowed] = await Promise.all([
      existingFiles(root, usable),
      filesWithoutRow(root, new Set(rows.map(r => r.path))),
    ])
    return [...new Set([...owned, ...unrowed])].sort().slice(0, SANDBOX_TEMPLATES_MAX)
  } catch (err) {
    return unreadable(err)
  }
}
