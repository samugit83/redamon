/**
 * A tar writer for folder uploads (ustar headers, PAX records for what ustar
 * cannot hold). The Blob is assembled from header bytes and the original File
 * objects, so a folder of any size is packed without reading it into memory.
 *
 * Browser-safe; no Node APIs.
 */

export interface TarEntry {
  /** Relative path, '/'-separated, no trailing slash (directories get theirs here). */
  path: string
  file?: Blob
  dir?: boolean
  mtimeMs?: number
}

const BLOCK = 512
const NAME_FIELD = 100
// The ustar size and mtime fields hold 11 octal digits.
const OCTAL_11_MAX = 0o77777777777
const FILE_MODE = 0o644
const DIR_MODE = 0o755
// What Python's tarfile names its extended headers; readers never extract it.
const PAX_HEADER_NAME = '././@PaxHeader'

const encoder = new TextEncoder()

/** Throws unless `path` is relative, has no empty, '.' or '..' segment, and no NUL. */
export function assertTarPath(path: string): void {
  if (!path || path.startsWith('/') || path.includes('\0')) {
    throw new Error(`Cannot pack the path "${path}": it must be relative and contain no NUL.`)
  }
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') {
      throw new Error(`Cannot pack the path "${path}": it has an empty, "." or ".." segment.`)
    }
  }
}

function writeBytes(block: Uint8Array, offset: number, length: number, value: Uint8Array): void {
  block.set(value.subarray(0, length), offset)
}

function writeAscii(block: Uint8Array, offset: number, length: number, value: string): void {
  for (let i = 0; i < Math.min(length, value.length); i++) block[offset + i] = value.charCodeAt(i) & 0x7f
}

/** `length - 1` zero-padded octal digits and a NUL. */
function writeOctal(block: Uint8Array, offset: number, length: number, value: number): void {
  writeAscii(block, offset, length, `${value.toString(8).padStart(length - 1, '0')}\0`)
}

function ustarHeader(name: Uint8Array, opts: { mode: number; size: number; mtime: number; type: string }): Uint8Array {
  const block = new Uint8Array(BLOCK)
  writeBytes(block, 0, NAME_FIELD, name)
  writeOctal(block, 100, 8, opts.mode)
  writeOctal(block, 108, 8, 0)
  writeOctal(block, 116, 8, 0)
  writeOctal(block, 124, 12, opts.size)
  writeOctal(block, 136, 12, opts.mtime)
  block[156] = opts.type.charCodeAt(0)
  writeAscii(block, 257, 6, 'ustar\0')
  writeAscii(block, 263, 2, '00')
  // The checksum is computed with its own field read as eight spaces.
  block.fill(0x20, 148, 156)
  let sum = 0
  for (const b of block) sum += b
  writeAscii(block, 148, 8, `${sum.toString(8).padStart(6, '0')}\0 `)
  return block
}

/** One "<len> key=value\n" record; <len> counts the whole record, its own digits included. */
function paxRecord(key: string, value: string): Uint8Array {
  const body = encoder.encode(` ${key}=${value}\n`)
  let len = body.length + 1
  while (String(len).length + body.length !== len) len = String(len).length + body.length
  const out = new Uint8Array(len)
  out.set(encoder.encode(String(len)), 0)
  out.set(body, len - body.length)
  return out
}

function padding(size: number): Uint8Array | null {
  const rest = size % BLOCK
  return rest === 0 ? null : new Uint8Array(BLOCK - rest)
}

/** An ASCII stand-in for the ustar name field when the real name travels in a PAX record. */
function fallbackName(name: string, isDir: boolean): Uint8Array {
  const ascii = name.replace(/[^\x20-\x7e]/g, '_')
  const short = ascii.length <= NAME_FIELD ? ascii
    : isDir ? `${ascii.slice(0, NAME_FIELD - 1)}/` : ascii.slice(0, NAME_FIELD)
  return encoder.encode(short)
}

export function buildTarBlob(entries: TarEntry[]): { blob: Blob; size: number } {
  const parts: BlobPart[] = []
  let size = 0
  const push = (part: Uint8Array | Blob) => {
    parts.push(part as BlobPart)
    size += part instanceof Blob ? part.size : part.length
  }

  for (const entry of entries) {
    assertTarPath(entry.path)
    const isDir = !!entry.dir
    const name = isDir ? `${entry.path}/` : entry.path
    const nameBytes = encoder.encode(name)
    const dataSize = isDir ? 0 : entry.file?.size ?? 0
    const mtimeMs = entry.mtimeMs ?? (entry.file instanceof File ? entry.file.lastModified : Date.now())
    const mtime = Math.min(Math.max(Math.floor(mtimeMs / 1000), 0), OCTAL_11_MAX)

    const records: Uint8Array[] = []
    const needsPath = nameBytes.length > NAME_FIELD || /[^\x20-\x7e]/.test(name)
    if (needsPath) records.push(paxRecord('path', name))
    if (dataSize > OCTAL_11_MAX) records.push(paxRecord('size', String(dataSize)))
    if (records.length) {
      const paxLength = records.reduce((n, r) => n + r.length, 0)
      push(ustarHeader(encoder.encode(PAX_HEADER_NAME), { mode: FILE_MODE, size: paxLength, mtime, type: 'x' }))
      for (const r of records) push(r)
      const pad = padding(paxLength)
      if (pad) push(pad)
    }

    push(ustarHeader(needsPath ? fallbackName(name, isDir) : nameBytes, {
      mode: isDir ? DIR_MODE : FILE_MODE,
      size: dataSize > OCTAL_11_MAX ? 0 : dataSize,
      mtime,
      type: isDir ? '5' : '0',
    }))
    if (!isDir && entry.file && dataSize > 0) {
      push(entry.file)
      const pad = padding(dataSize)
      if (pad) push(pad)
    }
  }

  push(new Uint8Array(2 * BLOCK))
  return { blob: new Blob(parts, { type: 'application/x-tar' }), size }
}
