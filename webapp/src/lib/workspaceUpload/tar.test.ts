import { describe, test, expect } from 'vitest'
import { buildTarBlob, type TarEntry } from './tar'

const BLOCK = 512
const decoder = new TextDecoder()

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer())
}

function field(block: Uint8Array, offset: number, length: number): string {
  const raw = block.subarray(offset, offset + length)
  const end = raw.indexOf(0)
  return decoder.decode(end === -1 ? raw : raw.subarray(0, end))
}

function octal(block: Uint8Array, offset: number, length: number): number {
  return parseInt(field(block, offset, length).trim() || '0', 8)
}

function checksumOf(block: Uint8Array): number {
  let sum = 0
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : block[i]
  return sum
}

function parsePax(data: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {}
  let pos = 0
  while (pos < data.length) {
    const space = data.indexOf(0x20, pos)
    const len = parseInt(decoder.decode(data.subarray(pos, space)), 10)
    const record = decoder.decode(data.subarray(space + 1, pos + len - 1))
    const eq = record.indexOf('=')
    out[record.slice(0, eq)] = record.slice(eq + 1)
    pos += len
  }
  return out
}

interface ReadEntry { name: string; type: string; data: Uint8Array; mode: number }

/** A minimal tar reader: ustar headers plus PAX `path` and `size` records. */
function readTar(bytes: Uint8Array): ReadEntry[] {
  const out: ReadEntry[] = []
  let pos = 0
  let pax: Record<string, string> = {}
  while (pos + BLOCK <= bytes.length) {
    const header = bytes.subarray(pos, pos + BLOCK)
    if (header.every((b) => b === 0)) break
    expect(octal(header, 148, 8)).toBe(checksumOf(header))
    const type = String.fromCharCode(header[156])
    const size = pax.size !== undefined ? Number(pax.size) : octal(header, 124, 12)
    const data = bytes.subarray(pos + BLOCK, pos + BLOCK + size)
    pos += BLOCK + Math.ceil(size / BLOCK) * BLOCK
    if (type === 'x') {
      pax = parsePax(data)
      continue
    }
    out.push({ name: pax.path ?? field(header, 0, 100), type, data, mode: octal(header, 100, 8) })
    pax = {}
  }
  return out
}

describe('buildTarBlob', () => {
  test('writes a valid ustar header with checksum', async () => {
    const file = new File(['hello'], 'a.txt')
    const { blob, size } = buildTarBlob([{ path: 'site/a.txt', file, mtimeMs: 1_700_000_000_000 }])
    const bytes = await bytesOf(blob)
    const header = bytes.subarray(0, BLOCK)

    expect(blob.size).toBe(size)
    expect(field(header, 0, 100)).toBe('site/a.txt')
    expect(field(header, 100, 8)).toBe('0000644')
    expect(field(header, 124, 12)).toBe('00000000005')
    expect(octal(header, 136, 12)).toBe(1_700_000_000)
    expect(String.fromCharCode(header[156])).toBe('0')
    expect(field(header, 257, 6)).toBe('ustar')
    expect(field(header, 263, 2)).toBe('00')
    // Six octal digits, NUL, space: the layout GNU tar and Python's tarfile write.
    expect(header[154]).toBe(0)
    expect(header[155]).toBe(0x20)
    expect(octal(header, 148, 6)).toBe(checksumOf(header))
  })

  test('adds a PAX path record for long and non-ASCII names', async () => {
    const longPath = `site/${'x'.repeat(120)}.txt`
    const accented = 'site/café-ü.txt'
    const { blob } = buildTarBlob([
      { path: longPath, file: new File(['1'], 'l') },
      { path: accented, file: new File(['2'], 'u') },
      { path: 'site/plain.txt', file: new File(['3'], 'p') },
    ])
    const bytes = await bytesOf(blob)

    const first = bytes.subarray(0, BLOCK)
    expect(String.fromCharCode(first[156])).toBe('x')
    const paxSize = octal(first, 124, 12)
    const paxData = bytes.subarray(BLOCK, BLOCK + paxSize)
    const record = decoder.decode(paxData)
    // The length prefix counts the whole record, its own digits included.
    const len = parseInt(record.slice(0, record.indexOf(' ')), 10)
    expect(len).toBe(paxData.length)
    expect(record).toBe(`${len} path=${longPath}\n`)

    const entries = readTar(bytes)
    expect(entries.map((e) => e.name)).toEqual([longPath, accented, 'site/plain.txt'])
    // A plain ASCII name under 100 bytes gets no PAX header of its own.
    const typeflags: string[] = []
    for (let pos = 0; pos < bytes.length; pos += BLOCK) {
      const block = bytes.subarray(pos, pos + BLOCK)
      if (field(block, 257, 6) === 'ustar') typeflags.push(String.fromCharCode(block[156]))
    }
    expect(typeflags).toEqual(['x', '0', 'x', '0', '0'])
  })

  test('pads data and ends with two zero blocks', async () => {
    const { blob, size } = buildTarBlob([{ path: 'a.txt', file: new File(['hello'], 'a.txt') }])
    const bytes = await bytesOf(blob)

    expect(size).toBe(BLOCK + BLOCK + 2 * BLOCK)
    expect(bytes.length).toBe(size)
    expect(decoder.decode(bytes.subarray(BLOCK, BLOCK + 5))).toBe('hello')
    expect(bytes.subarray(BLOCK + 5, 2 * BLOCK).every((b) => b === 0)).toBe(true)
    expect(bytes.subarray(2 * BLOCK).every((b) => b === 0)).toBe(true)

    const exact = buildTarBlob([{ path: 'b.bin', file: new File([new Uint8Array(BLOCK)], 'b.bin') }])
    expect(exact.size).toBe(BLOCK + BLOCK + 2 * BLOCK)
    const empty = buildTarBlob([])
    expect(empty.size).toBe(2 * BLOCK)
  })

  test('writes directory entries', async () => {
    const { blob } = buildTarBlob([{ path: 'site', dir: true }, { path: 'site/empty', dir: true }])
    const bytes = await bytesOf(blob)
    const header = bytes.subarray(0, BLOCK)

    expect(field(header, 0, 100)).toBe('site/')
    expect(String.fromCharCode(header[156])).toBe('5')
    expect(octal(header, 124, 12)).toBe(0)
    expect(field(header, 100, 8)).toBe('0000755')
    // No data block: the next header follows directly.
    expect(field(bytes.subarray(BLOCK, 2 * BLOCK), 0, 100)).toBe('site/empty/')
    expect(bytes.length).toBe(4 * BLOCK)
  })

  test('rejects absolute, dot-dot and empty segments', () => {
    const bad = ['/etc/passwd', '../x', 'a/../b', 'a/..', 'a//b', '', 'a/', './a', 'a\0b']
    for (const path of bad) {
      expect(() => buildTarBlob([{ path, file: new File(['x'], 'x') }]), path).toThrow()
    }
    expect(() => buildTarBlob([{ path: 'a/b..c/.hidden', file: new File(['x'], 'x') }])).not.toThrow()
  })

  test('round-trips through a minimal reader', async () => {
    const entries: TarEntry[] = [
      { path: 'site', dir: true },
      { path: 'site/index.html', file: new File(['<h1>hi</h1>'], 'index.html') },
      { path: 'site/empty', dir: true },
      { path: 'site/zero.txt', file: new File([], 'zero.txt') },
      { path: 'site/assets', dir: true },
      { path: 'site/assets/big.bin', file: new File([new Uint8Array(1300).fill(7)], 'big.bin') },
      { path: `site/assets/${'deep/'.repeat(25)}leaf.txt`, file: new File(['leaf'], 'leaf.txt') },
      { path: 'site/日本語.txt', file: new File(['utf8'], 'jp.txt') },
    ]
    const { blob } = buildTarBlob(entries)
    const read = readTar(await bytesOf(blob))

    expect(read.map((e) => e.name)).toEqual([
      'site/', 'site/index.html', 'site/empty/', 'site/zero.txt', 'site/assets/',
      'site/assets/big.bin', `site/assets/${'deep/'.repeat(25)}leaf.txt`, 'site/日本語.txt',
    ])
    expect(read.map((e) => e.type)).toEqual(['5', '0', '5', '0', '5', '0', '0', '0'])
    expect(decoder.decode(read[1].data)).toBe('<h1>hi</h1>')
    expect(read[3].data.length).toBe(0)
    expect(Array.from(read[5].data)).toEqual(new Array(1300).fill(7))
    expect(decoder.decode(read[6].data)).toBe('leaf')
    expect(decoder.decode(read[7].data)).toBe('utf8')
  })
})
