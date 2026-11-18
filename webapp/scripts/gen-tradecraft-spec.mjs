/**
 * Keep the agent's copies of the Tradecraft settings spec and vocabulary equal to the
 * webapp's, byte for byte.
 *
 *   node scripts/gen-tradecraft-spec.mjs           write the copies, print what changed
 *   node scripts/gen-tradecraft-spec.mjs --check   change nothing, exit 1 if a copy differs
 *
 * Run from webapp/. The webapp's files are the source (src/lib/tradecraft/settingsSpec.json,
 * vocab.json); the agent image bakes agentic/tradecraft/ and cannot read webapp/, so it
 * carries copies, and agentic/tradecraft/settings.py clamps every value again with them.
 */
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const WEBAPP = join(dirname(fileURLToPath(import.meta.url)), '..')

export const COPIES = [
  { source: 'src/lib/tradecraft/settingsSpec.json', target: '../agentic/tradecraft/settings_spec.json' },
  { source: 'src/lib/tradecraft/vocab.json', target: '../agentic/tradecraft/vocab.json' },
]

/** Returns the targets that differ from their source (and writes them unless `check`). */
export function run({ check = false, root = WEBAPP } = {}) {
  const stale = []
  for (const { source, target } of COPIES) {
    const want = readFileSync(join(root, source))
    const path = join(root, target)
    const have = existsSync(path) ? readFileSync(path) : null
    if (have && Buffer.compare(have, want) === 0) continue
    stale.push(relative(root, path))
    if (!check) writeFileSync(path, want)
  }
  return stale
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const check = process.argv.includes('--check')
  const stale = run({ check })
  if (check) {
    if (stale.length) {
      console.error(`stale: ${stale.join(', ')}; run node scripts/gen-tradecraft-spec.mjs`)
      process.exit(1)
    }
    console.log('tradecraft spec copies up to date')
  } else {
    console.log(stale.length ? `wrote ${stale.join(', ')}` : 'tradecraft spec copies up to date')
  }
}
