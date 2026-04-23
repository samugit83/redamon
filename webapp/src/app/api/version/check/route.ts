import { parseChangelog, filterChangelog } from '@/lib/parseChangelog'
import { readFileSync } from 'fs'
import { join } from 'path'

const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/samugit83/redamon/master'
const FETCH_TIMEOUT = 5000

function readLocalVersion(): string {
  const candidates = [
    join(process.cwd(), 'VERSION'),
    join(process.cwd(), '..', 'VERSION'),
  ]
  for (const p of candidates) {
    try {
      return readFileSync(p, 'utf-8').trim()
    } catch { /* try next */ }
  }
  return '0.0.0'
}

async function fetchGitHub(path: string): Promise<string | null> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT)
    const res = await fetch(`${GITHUB_RAW_BASE}/${path}`, {
      signal: controller.signal,
      cache: 'no-store',
    })
    clearTimeout(timer)
    if (!res.ok) return null
    return res.text()
  } catch {
    return null
  }
}

export async function GET() {
  const currentVersion = readLocalVersion()

  const [versionRaw, changelogRaw] = await Promise.all([
    fetchGitHub('VERSION'),
    fetchGitHub('CHANGELOG.md'),
  ])

  const latestVersion = versionRaw ? versionRaw.trim() : null

  let changelog: ReturnType<typeof filterChangelog> = []
  if (latestVersion && changelogRaw) {
    const allEntries = parseChangelog(changelogRaw)
    changelog = filterChangelog(allEntries, currentVersion)
  }

  return Response.json(
    {
      current_version: currentVersion,
      latest_version: latestVersion,
      changelog,
    },
    {
      headers: { 'Cache-Control': 'no-store' },
    }
  )
}
