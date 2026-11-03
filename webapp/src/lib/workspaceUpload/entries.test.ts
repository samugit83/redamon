import { describe, test, expect, vi } from 'vitest'
import { archiveBaseName, entriesFromFileList, snapshotDrop, walkEntries } from './entries'

// Fake File and Directory System entries: the shapes webkitGetAsEntry() returns.

function fileEntry(name: string, content = name): FileSystemFileEntry {
  const file = new File([content], name, { lastModified: 1_700_000_000_000 })
  return {
    isFile: true, isDirectory: false, name, fullPath: `/${name}`,
    file: (ok: (f: File) => void) => ok(file),
  } as unknown as FileSystemFileEntry
}

/** A directory whose reader hands out its children `batchSize` at a time, as Chrome does (100 per call). */
function dirEntry(name: string, children: FileSystemEntry[], batchSize = 100) {
  const readEntries = vi.fn()
  const entry = {
    isFile: false, isDirectory: true, name, fullPath: `/${name}`,
    createReader: () => {
      let pos = 0
      readEntries.mockImplementation((ok: (batch: FileSystemEntry[]) => void) => {
        const batch = children.slice(pos, pos + batchSize)
        pos += batch.length
        setTimeout(() => ok(batch), 0)
      })
      return { readEntries }
    },
  } as unknown as FileSystemDirectoryEntry
  return { entry, readEntries }
}

function dataTransferOf(entries: (FileSystemEntry | null)[], files: File[] = []): DataTransfer {
  const items = entries.map((entry) => ({
    kind: 'file',
    webkitGetAsEntry: () => entry,
    getAsFile: () => (entry ? null : files[0] ?? null),
  }))
  return { items, files, types: ['Files'] } as unknown as DataTransfer
}

describe('walkEntries', () => {
  test('reads directories in batches until an empty batch', async () => {
    const children = Array.from({ length: 250 }, (_, i) => fileEntry(`f${i}.txt`))
    const { entry, readEntries } = dirEntry('big', children)

    const result = await walkEntries(snapshotDrop(dataTransferOf([entry])))

    // 100 + 100 + 50, then the empty batch that ends the listing.
    expect(readEntries).toHaveBeenCalledTimes(4)
    expect(result.folders).toHaveLength(1)
    const files = result.folders[0].entries.filter((e) => !e.dir)
    expect(files).toHaveLength(250)
    expect(files[249].path).toBe('big/f249.txt')
  })

  test('keeps nested and empty directories', async () => {
    const empty = dirEntry('empty', []).entry
    const inner = dirEntry('inner', [fileEntry('deep.txt', 'deep')]).entry
    const css = dirEntry('css', [inner, empty]).entry
    const site = dirEntry('site', [fileEntry('index.html'), css]).entry

    const { folders } = await walkEntries(snapshotDrop(dataTransferOf([site])))

    expect(folders).toHaveLength(1)
    expect(folders[0].name).toBe('site')
    expect(folders[0].entries.map((e) => [e.path, !!e.dir])).toEqual([
      ['site', true],
      ['site/index.html', false],
      ['site/css', true],
      ['site/css/inner', true],
      ['site/css/inner/deep.txt', false],
      ['site/css/empty', true],
    ])
    const deep = folders[0].entries.find((e) => e.path === 'site/css/inner/deep.txt')
    expect(await deep!.file!.text()).toBe('deep')
    expect(deep!.mtimeMs).toBe(1_700_000_000_000)
  })

  test('separates files from folders', async () => {
    const site = dirEntry('site', [fileEntry('a.txt')]).entry
    const loose = fileEntry('notes.md')
    const docs = dirEntry('docs', []).entry

    const { folders, files } = await walkEntries(snapshotDrop(dataTransferOf([site, loose, docs])))

    expect(folders.map((f) => f.name)).toEqual(['site', 'docs'])
    expect(files.map((f) => f.name)).toEqual(['notes.md'])
    expect(folders[1].entries).toEqual([{ path: 'docs', dir: true }])
  })

  test('falls back to dt.files', async () => {
    const a = new File(['a'], 'a.txt')
    const b = new File(['b'], 'b.txt')
    // No items at all (older browsers, synthetic events), then items without webkitGetAsEntry.
    const bare = { files: [a, b], types: ['Files'] } as unknown as DataTransfer
    const noEntryApi = { items: [{ kind: 'file', getAsFile: () => a }], files: [a], types: ['Files'] } as unknown as DataTransfer

    expect(await walkEntries(snapshotDrop(bare))).toEqual({ folders: [], files: [a, b] })
    expect(await walkEntries(snapshotDrop(noEntryApi))).toEqual({ folders: [], files: [a] })
    // An item the browser cannot turn into an entry still yields its File.
    expect((await walkEntries(snapshotDrop(dataTransferOf([null], [b])))).files).toEqual([b])
  })

  test('snapshotDrop reads every entry before the handler returns', () => {
    const getters = [vi.fn(() => fileEntry('a')), vi.fn(() => fileEntry('b'))]
    const dt = { items: getters.map((g) => ({ kind: 'file', webkitGetAsEntry: g })), files: [], types: ['Files'] }
    snapshotDrop(dt as unknown as DataTransfer)
    expect(getters.every((g) => g.mock.calls.length === 1)).toBe(true)
  })
})

describe('entriesFromFileList', () => {
  test('builds entries from webkitRelativePath', () => {
    const withPath = (content: string, name: string, rel: string) => {
      const f = new File([content], name, { lastModified: 1_600_000_000_000 })
      Object.defineProperty(f, 'webkitRelativePath', { value: rel })
      return f
    }
    const index = withPath('i', 'index.html', 'site/index.html')
    const app = withPath('a', 'app.js', 'site/js/lib/app.js')
    const style = withPath('s', 'style.css', 'site/js/style.css')
    const loose = new File(['x'], 'loose.txt')

    const { folders, files } = entriesFromFileList([index, app, style, loose])

    expect(files).toEqual([loose])
    expect(folders).toHaveLength(1)
    expect(folders[0].name).toBe('site')
    expect(folders[0].entries.map((e) => [e.path, !!e.dir])).toEqual([
      ['site', true],
      ['site/index.html', false],
      ['site/js', true],
      ['site/js/lib', true],
      ['site/js/lib/app.js', false],
      ['site/js/style.css', false],
    ])
    expect(folders[0].entries[1].file).toBe(index)
    expect(folders[0].entries[1].mtimeMs).toBe(1_600_000_000_000)
  })
})

describe('archiveBaseName', () => {
  test('strips the archive extension', () => {
    expect(archiveBaseName('site.tar.gz')).toBe('site')
    expect(archiveBaseName('site.TGZ')).toBe('site')
    expect(archiveBaseName('dump.tar.bz2')).toBe('dump')
    expect(archiveBaseName('dump.tbz2')).toBe('dump')
    expect(archiveBaseName('x.tar.xz')).toBe('x')
    expect(archiveBaseName('x.txz')).toBe('x')
    expect(archiveBaseName('repo-main.zip')).toBe('repo-main')
    expect(archiveBaseName('a.b.tar')).toBe('a.b')
    expect(archiveBaseName('.zip')).toBe('.zip')
    expect(archiveBaseName('notes.txt')).toBe('notes.txt')
  })
})
