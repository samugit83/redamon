/**
 * Turn what the user picked or dropped into folders (tar entries rooted at the
 * folder's name) and loose files.
 *
 * Browser-only: reads the File and Directory Entries API of a drop.
 */
import type { TarEntry } from './tar'

export interface FolderUpload {
  name: string
  entries: TarEntry[]
}

export interface PickedItems {
  folders: FolderUpload[]
  files: File[]
}

export interface DropSnapshot {
  entries: FileSystemEntry[]
  files: File[]
}

export const ARCHIVE_EXTENSIONS = ['.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz', '.zip', '.tar'] as const
export const ARCHIVE_ACCEPT = '.zip,.tar,.tar.gz,.tgz,.tar.bz2,.tbz2,.tar.xz,.txz'

/** The folder name an archive extracts into: its file name minus the archive extension. */
export function archiveBaseName(fileName: string): string {
  const lower = fileName.toLowerCase()
  const ext = ARCHIVE_EXTENSIONS.find((e) => lower.endsWith(e) && fileName.length > e.length)
  return ext ? fileName.slice(0, -ext.length) : fileName
}

/**
 * Folders from a `webkitdirectory` picker, grouped by their top folder. The
 * picker sends files only, so a folder with no file in it never arrives here;
 * a drop keeps those (walkEntries).
 */
export function entriesFromFileList(list: FileList | readonly File[]): PickedItems {
  const folders = new Map<string, { upload: FolderUpload; dirs: Set<string> }>()
  const files: File[] = []
  for (const file of Array.from(list)) {
    const rel = file.webkitRelativePath || ''
    const parts = rel.split('/')
    if (parts.length < 2) {
      files.push(file)
      continue
    }
    const top = parts[0]
    let folder = folders.get(top)
    if (!folder) {
      folder = { upload: { name: top, entries: [{ path: top, dir: true }] }, dirs: new Set([top]) }
      folders.set(top, folder)
    }
    for (let i = 2; i < parts.length; i++) {
      const dir = parts.slice(0, i).join('/')
      if (!folder.dirs.has(dir)) {
        folder.dirs.add(dir)
        folder.upload.entries.push({ path: dir, dir: true })
      }
    }
    folder.upload.entries.push({ path: rel, file, mtimeMs: file.lastModified })
  }
  return { folders: Array.from(folders.values(), (f) => f.upload), files }
}

/**
 * Take the dropped entries while the drop handler runs: the browser empties
 * `dataTransfer.items` as soon as the handler returns. Falls back to
 * `dataTransfer.files` where the entries API is missing.
 */
export function snapshotDrop(dt: DataTransfer): DropSnapshot {
  const items = dt.items
  if (items && items.length > 0 && typeof items[0]?.webkitGetAsEntry === 'function') {
    const entries: FileSystemEntry[] = []
    const files: File[] = []
    for (let i = 0; i < items.length; i++) {
      const item = items[i]
      if (item.kind && item.kind !== 'file') continue
      const entry = item.webkitGetAsEntry()
      if (entry) {
        entries.push(entry)
        continue
      }
      const file = item.getAsFile?.()
      if (file) files.push(file)
    }
    return { entries, files }
  }
  return { entries: [], files: Array.from(dt.files ?? []) }
}

function fileOf(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => entry.file(resolve, reject))
}

/** Every child of a directory: readEntries hands them out in batches (100 in Chrome) until an empty one. */
async function readAll(dir: FileSystemDirectoryEntry): Promise<FileSystemEntry[]> {
  const reader = dir.createReader()
  const all: FileSystemEntry[] = []
  for (;;) {
    const batch = await new Promise<FileSystemEntry[]>((resolve, reject) => reader.readEntries(resolve, reject))
    if (batch.length === 0) return all
    all.push(...batch)
  }
}

async function walkDirectory(dir: FileSystemDirectoryEntry, prefix: string, out: TarEntry[]): Promise<void> {
  const children = await readAll(dir)
  const files = await Promise.all(children.map((c) => (c.isFile ? fileOf(c as FileSystemFileEntry) : null)))
  for (let i = 0; i < children.length; i++) {
    const child = children[i]
    const path = `${prefix}/${child.name}`
    const file = files[i]
    if (file) {
      out.push({ path, file, mtimeMs: file.lastModified })
    } else if (child.isDirectory) {
      out.push({ path, dir: true })
      await walkDirectory(child as FileSystemDirectoryEntry, path, out)
    }
  }
}

export async function walkEntries(snapshot: DropSnapshot): Promise<PickedItems> {
  const folders: FolderUpload[] = []
  const files = [...snapshot.files]
  for (const entry of snapshot.entries) {
    if (entry.isDirectory) {
      const entries: TarEntry[] = [{ path: entry.name, dir: true }]
      await walkDirectory(entry as FileSystemDirectoryEntry, entry.name, entries)
      folders.push({ name: entry.name, entries })
    } else if (entry.isFile) {
      files.push(await fileOf(entry as FileSystemFileEntry))
    }
  }
  return { folders, files }
}
