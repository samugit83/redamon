/**
 * Repositories, secrets and sensitive files the GitHub hunt found, counted the
 * same way by the client report and the Insights page. A secret whose pattern
 * names a key that is public by design (a publishable or browser key committed
 * to a repository) is counted apart, never as an exposed secret.
 */
import { notMuted } from '@/lib/graphMute'
import { reportCountable } from '@/lib/triage/reportable'
import { publicClientKeyCypher } from './publicClientKeys'

export interface GithubSecretCounts {
  repos: number
  secrets: number
  publicClientKeys: number
  sensitiveFiles: number
}

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

/** Binds `$pid` (and `$uid` when given, matching the `(user_id, project_id)` composite index). */
export function githubSecretCountsCypher(uid?: string): string {
  const pub = publicClientKeyCypher('sec')
  const domainScope = uid ? 'user_id: $uid, project_id: $pid' : 'project_id: $pid'
  return `OPTIONAL MATCH (d:Domain {${domainScope}})-[:HAS_GITHUB_HUNT]->()-[:HAS_REPOSITORY]->(r:GithubRepository)
     OPTIONAL MATCH (r)-[:HAS_PATH]->()-[:CONTAINS_SECRET]->(sec:GithubSecret)
       WHERE ${notMuted('sec')} AND ${reportCountable('sec')}
     OPTIONAL MATCH (r)-[:HAS_PATH]->()-[:CONTAINS_SENSITIVE_FILE]->(sf:GithubSensitiveFile)
       WHERE ${notMuted('sf')} AND ${reportCountable('sf')}
     RETURN count(DISTINCT r) AS repos,
            count(DISTINCT CASE WHEN NOT ${pub} THEN sec END) AS secrets,
            count(DISTINCT CASE WHEN ${pub} THEN sec END) AS publicClientKeys,
            count(DISTINCT sf) AS sensitiveFiles`
}

/** The counts from the query's one row, or zeros when there is none. */
export function githubSecretCounts(rec: { get: (key: string) => unknown } | undefined | null): GithubSecretCounts {
  if (!rec) return { repos: 0, secrets: 0, publicClientKeys: 0, sensitiveFiles: 0 }
  return {
    repos: toNum(rec.get('repos')),
    secrets: toNum(rec.get('secrets')),
    publicClientKeys: toNum(rec.get('publicClientKeys')),
    sensitiveFiles: toNum(rec.get('sensitiveFiles')),
  }
}
