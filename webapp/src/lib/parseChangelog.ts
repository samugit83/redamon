import { compareSemver } from './semver'

export interface ChangelogSection {
  title: string
  items: string[]
}

export interface ChangelogEntry {
  version: string
  date: string
  sections: ChangelogSection[]
}

/**
 * Parse a Keep a Changelog formatted markdown string into structured entries.
 * Expects headers like: ## [3.1.2] - 2026-03-28
 * And sections like: ### Added, ### Fixed, ### Changed
 */
export function parseChangelog(raw: string): ChangelogEntry[] {
  const entries: ChangelogEntry[] = []
  const lines = raw.split('\n')

  let currentEntry: ChangelogEntry | null = null
  let currentSection: ChangelogSection | null = null

  for (const line of lines) {
    // Match version header: ## [3.1.2] - 2026-03-28
    const versionMatch = line.match(/^## \[(\d+\.\d+\.\d+)\]\s*-\s*(\d{4}-\d{2}-\d{2})/)
    if (versionMatch) {
      if (currentSection && currentEntry) currentEntry.sections.push(currentSection)
      if (currentEntry) entries.push(currentEntry)
      currentEntry = { version: versionMatch[1], date: versionMatch[2], sections: [] }
      currentSection = null
      continue
    }

    // Match section header: ### Added, ### Fixed, ### Changed
    const sectionMatch = line.match(/^### (.+)/)
    if (sectionMatch && currentEntry) {
      if (currentSection) currentEntry.sections.push(currentSection)
      currentSection = { title: sectionMatch[1].trim(), items: [] }
      continue
    }

    // Match list items (top-level only, starting with "- ")
    if (line.match(/^- /) && currentSection) {
      currentSection.items.push(line.slice(2).trim())
    }
  }

  // Flush remaining
  if (currentSection && currentEntry) currentEntry.sections.push(currentSection)
  if (currentEntry) entries.push(currentEntry)

  return entries
}

/**
 * Filter changelog entries to only those newer than `fromVersion`.
 * Returns entries sorted newest first.
 */
export function filterChangelog(entries: ChangelogEntry[], fromVersion: string): ChangelogEntry[] {
  return entries
    .filter(e => compareSemver(e.version, fromVersion) > 0)
    .sort((a, b) => compareSemver(b.version, a.version))
}
