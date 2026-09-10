import { NextRequest, NextResponse } from 'next/server'
import { rowCap } from '../rowCap'
import { guardProject } from '@/lib/access'
import { getGraphSession } from '@/app/api/graph/neo4j'
import { notMuted } from '@/lib/graphMute'

function toNum(val: unknown): number {
  if (val && typeof val === 'object' && 'low' in val) return (val as { low: number }).low
  return typeof val === 'number' ? val : 0
}

/** Chain finding types where the credential was actually USED, not just seen. */
const CREDENTIAL_PROVEN_TYPES = new Set([
  'exploit_success', 'access_gained', 'privilege_escalation', 'session_hijacked',
])

/** Pin a file finding to its line and commit when the scanner recorded them. */
function withPosition(location: string | null, line: unknown, commit: string | null): string | null {
  if (!location) return location
  const parts = [location]
  if (line != null && toNum(line) > 0) parts.push(`:${toNum(line)}`)
  if (commit) parts.push(` @${commit.slice(0, 7)}`)
  return parts.join('')
}

/**
 * GitHub Hunt is pure regex with no verification step, so its nodes carry no
 * severity of their own and something has to assign one here.
 *
 * Flattening every hit to one level is the wrong answer in both directions: a
 * leaked private key and a private RFC1918 address in a compose file are not
 * the same finding, and on a full-org scan the low-value families are the bulk
 * of the rows. Keyword families, matching the pattern names the scanner emits.
 *
 * Keyword matching, so it is approximate by construction and deliberately
 * conservative: a bare "<vendor> Key" stays low because that bucket holds
 * publishable ones (a reCAPTCHA site key is meant to ship in the page). The
 * named URL families are here because their VALUE carries inline auth
 * (`redis://user:pass@`, `cloudinary://key:secret@`, `https://user:token@`)
 * which no keyword in the name would reveal.
 */
function githubSeverity(secretType: string): string {
  const t = (secretType || '').toLowerCase()
  if (t.includes('private key') || t.includes('connection string')
      || t.includes('credential') || t.includes('pkcs12') || t.includes('keystore')
      || t === 'redis url' || t === 'cloudinary url'
      || (t.includes('aws') && t.includes('key')) || t.includes('gcp')
      || t.includes('azure') || t.includes('token')) return 'high'
  if (t.includes('password') || t.includes('api key') || t.includes('secret')
      || t.includes('webhook') || t.includes('oauth') || t.includes('env leak')) return 'medium'
  return 'low'
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  const __denied = await guardProject(projectId || '')
  if (__denied) return __denied
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const session = getGraphSession()
  try {
    // Secrets in RedAmon always live in the :Secret node. They can be attached via
    //   (BaseURL)-[:HAS_SECRET]->(Secret)              // resource_mixin
    //   (JsReconFinding {finding_type:'js_file'})-[:HAS_SECRET]->(Secret)  // js_recon_mixin
    // Union both traversals and keep each Secret once.
    const result = await session.run(
      `MATCH (s:Secret {project_id: $pid})
       WHERE ${notMuted('s')}
       OPTIONAL MATCH (buDirect:BaseURL)-[:HAS_SECRET]->(s)
       OPTIONAL MATCH (j:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s)
       OPTIONAL MATCH (buJs:BaseURL)-[:HAS_JS_FILE]->(j)
       WITH s, j, coalesce(buDirect, buJs) AS bu
       OPTIONAL MATCH (sd:Subdomain)-[:HAS_BASE_URL]->(bu)
       RETURN s.id                                      AS id,
              coalesce(s.secret_type, s.pattern)        AS secretType,
              s.sample                                  AS valueSample,
              s.matched_text                            AS matchedText,
              s.entropy                                 AS entropy,
              s.confidence                              AS confidence,
              s.severity                                AS severity,
              s.source                                  AS sourceModule,
              s.source_url                              AS sourceUrl,
              s.base_url                                AS secretBaseUrl,
              s.key_type                                AS keyType,
              s.detection_method                        AS detectionMethod,
              s.validation_status                       AS validationStatus,
              bu.url                                    AS baseUrl,
              sd.name                                   AS subdomain,
              j.source_url                              AS jsFileUrl,
              CASE WHEN j IS NOT NULL THEN 'JsReconFinding' ELSE 'Secret' END AS origin,
              null                                      AS trufflehogSource,
              null                                      AS asset,
              null                                      AS location,
              s.updated_at                              AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    // TruffleHog findings were graph-only until now: the operator had to open
    // /graph to see a credential the scanner had CONFIRMED was live. They are a
    // separate traversal rather than a second label on the node, because the
    // graph renderer draws a node from labels[0] and dual-labelling would break
    // it. The asset match is untyped `(a)` on purpose — assets carry one of five
    // labels and naming one would drop every non-git source.
    const thResult = await session.run(
      `MATCH (tf:MultiscannerFinding {project_id: $pid})
       WHERE ${notMuted('tf')}
       OPTIONAL MATCH (a)-[:HAS_FINDING]->(tf)
       RETURN tf.id                AS id,
              tf.detector_name     AS secretType,
              tf.redacted          AS valueSample,
              tf.validation_status AS validationStatus,
              tf.source            AS trufflehogSource,
              tf.finding_kind      AS findingKind,
              coalesce(a.name, tf.asset) AS asset,
              tf.location          AS location,
              tf.link              AS sourceUrl,
              tf.commit            AS commit,
              tf.line              AS line,
              tf.updated_at        AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    // GitHub Secret Hunt was in the same graph-only limbo TruffleHog was in: a
    // full-org scan can land hundreds of GithubSecret nodes that this table,
    // the one place an operator looks for credentials, never queried.
    // Repository and path come off the node itself; the parent traversal is
    // only a fallback for older nodes written before those were denormalised.
    const ghResult = await session.run(
      `MATCH (gs:GithubSecret {project_id: $pid})
       WHERE ${notMuted('gs')}
       OPTIONAL MATCH (gp:GithubPath)-[:CONTAINS_SECRET]->(gs)
       OPTIONAL MATCH (gr:GithubRepository)-[:HAS_PATH]->(gp)
       RETURN gs.id                              AS id,
              gs.secret_type                     AS secretType,
              gs.sample                          AS valueSample,
              gs.matches                         AS matches,
              coalesce(gs.repository, gr.name)   AS asset,
              coalesce(gs.path, gp.path)         AS location,
              gs.updated_at                      AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    // Sensitive FILENAMES (.env, id_rsa, ...). Not a credential value — the
    // scanner never read one — so they carry no sample and sort at the bottom.
    // They are in this table because an exposed .env IS the credential story,
    // and the triage scorer already weighs them as SECRET_EXPOSED.
    const ghFileResult = await session.run(
      `MATCH (gsf:GithubSensitiveFile {project_id: $pid})
       WHERE ${notMuted('gsf')}
       OPTIONAL MATCH (gp:GithubPath)-[:CONTAINS_SENSITIVE_FILE]->(gsf)
       OPTIONAL MATCH (gr:GithubRepository)-[:HAS_PATH]->(gp)
       RETURN gsf.id                              AS id,
              coalesce(gsf.repository, gr.name)   AS asset,
              coalesce(gsf.path, gp.path)         AS location,
              gsf.updated_at                      AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    // Credentials the AGENT recovered during an attack chain — dumped by a SQLi,
    // brute-forced, or read out of a shell. These are the strongest findings the
    // platform can produce (someone logged in with them) and they were absent
    // here entirely. Matched on the property, not on finding_type: the writer
    // attaches username/password to exploit_success as well as credential_found,
    // so keying off the type alone would miss the ones that actually worked.
    const chainResult = await session.run(
      `MATCH (f:ChainFinding {project_id: $pid})
       WHERE f.username IS NOT NULL OR f.password IS NOT NULL
          OR f.finding_type = 'credential_found'
       RETURN f.finding_id   AS id,
              f.finding_type AS findingType,
              f.username     AS username,
              f.password     AS password,
              f.attack_type  AS attackType,
              f.severity     AS severity,
              f.title        AS title,
              f.target_ip    AS targetIp,
              f.target_port  AS targetPort,
              f.updated_at   AS updatedAt
       LIMIT ${rowCap()}`,
      { pid: projectId }
    )

    const rows = result.records.map(r => ({
      origin: r.get('origin') as string,
      id: (r.get('id') as string) || '',
      secretType: (r.get('secretType') as string) || 'unknown',
      valueSample: r.get('valueSample') as string | null,
      matchedText: r.get('matchedText') as string | null,
      entropy: r.get('entropy') != null ? toNum(r.get('entropy')) : null,
      confidence: (r.get('confidence') as string | number | null) ?? null,
      severity: (r.get('severity') as string) || 'medium',
      sourceModule: r.get('sourceModule') as string | null,
      sourceUrl: r.get('sourceUrl') as string | null,
      secretBaseUrl: r.get('secretBaseUrl') as string | null,
      keyType: r.get('keyType') as string | null,
      detectionMethod: r.get('detectionMethod') as string | null,
      validationStatus: r.get('validationStatus') as string | null,
      baseUrl: r.get('baseUrl') as string | null,
      subdomain: r.get('subdomain') as string | null,
      jsFileUrl: r.get('jsFileUrl') as string | null,
      trufflehogSource: null as string | null,
      asset: null as string | null,
      location: null as string | null,
      updatedAt: (r.get('updatedAt') ?? null) as unknown,
    }))

    rows.push(...thResult.records.map(r => {
      const findingKind = r.get('findingKind') as string | null
      const location = r.get('location') as string | null
      return {
        origin: 'MultiscannerFinding',
        id: (r.get('id') as string) || '',
        secretType: (r.get('secretType') as string) || 'unknown',
        valueSample: r.get('valueSample') as string | null,
        matchedText: null as string | null,
        entropy: null as number | null,
        confidence: null as string | number | null,
        // A credential the owning API confirmed is LIVE is the most severe
        // finding this table can hold; anything else is informational until
        // someone checks it.
        severity: r.get('validationStatus') === 'validated' ? 'critical' : 'medium',
        sourceModule: `trufflehog:${r.get('trufflehogSource') ?? 'unknown'}`,
        sourceUrl: r.get('sourceUrl') as string | null,
        secretBaseUrl: null as string | null,
        keyType: null as string | null,
        detectionMethod: 'trufflehog',
        validationStatus: r.get('validationStatus') as string | null,
        baseUrl: null as string | null,
        subdomain: null as string | null,
        jsFileUrl: null as string | null,
        trufflehogSource: r.get('trufflehogSource') as string | null,
        asset: r.get('asset') as string | null,
        // A build-history finding's path does not exist in the filesystem.
        // `line` and `commit` were collected by the scanner and stored on the
        // node but never surfaced, so a repo hit pointed at a file and left the
        // reader to search it by hand.
        location: findingKind === 'image_history'
          ? 'Dockerfile (build history)'
          : withPosition(location, r.get('line'), r.get('commit') as string | null),
        updatedAt: (r.get('updatedAt') ?? null) as unknown,
      }
    }))

    rows.push(...ghResult.records.map(r => {
      const secretType = (r.get('secretType') as string) || 'unknown'
      const matches = r.get('matches') != null ? toNum(r.get('matches')) : null
      return {
        origin: 'GithubSecret',
        id: (r.get('id') as string) || '',
        secretType,
        valueSample: r.get('valueSample') as string | null,
        matchedText: null as string | null,
        entropy: null as number | null,
        // The scanner counts how many times the pattern hit in that file. It is
        // not a confidence score, but it is the only per-finding weight the hunt
        // produces and the column is otherwise dead for these rows.
        confidence: matches,
        severity: githubSeverity(secretType),
        sourceModule: 'github_hunt',
        sourceUrl: null as string | null,
        secretBaseUrl: null as string | null,
        keyType: null as string | null,
        detectionMethod: 'regex',
        // Regex match, nothing verified it. `unverified` (not `unvalidated`)
        // because nobody looked — `unvalidated` would read as checked-and-dead.
        validationStatus: 'unverified',
        baseUrl: null as string | null,
        subdomain: null as string | null,
        jsFileUrl: null as string | null,
        trufflehogSource: null as string | null,
        asset: r.get('asset') as string | null,
        location: r.get('location') as string | null,
        updatedAt: (r.get('updatedAt') ?? null) as unknown,
      }
    }))

    rows.push(...ghFileResult.records.map(r => ({
      origin: 'GithubSensitiveFile',
      id: (r.get('id') as string) || '',
      secretType: 'Sensitive File',
      valueSample: null as string | null,
      matchedText: null as string | null,
      entropy: null as number | null,
      confidence: null as string | number | null,
      severity: 'low',
      sourceModule: 'github_hunt',
      sourceUrl: null as string | null,
      secretBaseUrl: null as string | null,
      keyType: null as string | null,
      detectionMethod: 'filename',
      validationStatus: 'unverified',
      baseUrl: null as string | null,
      subdomain: null as string | null,
      jsFileUrl: null as string | null,
      trufflehogSource: null as string | null,
      asset: r.get('asset') as string | null,
      location: r.get('location') as string | null,
      updatedAt: (r.get('updatedAt') ?? null) as unknown,
    })))

    rows.push(...chainResult.records.map(r => {
      const findingType = (r.get('findingType') as string) || ''
      const username = r.get('username') as string | null
      const targetIp = r.get('targetIp') as string | null
      const targetPort = r.get('targetPort') != null ? toNum(r.get('targetPort')) : null
      return {
        origin: 'ChainFinding',
        id: (r.get('id') as string) || '',
        secretType: username && r.get('password') ? 'Credential Pair' : 'Credential',
        valueSample: r.get('password') as string | null,
        matchedText: null as string | null,
        entropy: null as number | null,
        confidence: null as string | number | null,
        severity: (r.get('severity') as string) || 'high',
        sourceModule: 'attack_chain',
        sourceUrl: null as string | null,
        secretBaseUrl: null as string | null,
        keyType: r.get('attackType') as string | null,
        detectionMethod: 'exploitation',
        // The agent did not pattern-match this, it USED it: an exploit_success
        // carrying a password is a credential someone logged in with. Anything
        // merely observed (credential_found) has not been proven live.
        validationStatus: CREDENTIAL_PROVEN_TYPES.has(findingType) ? 'validated' : 'unvalidated',
        baseUrl: null as string | null,
        subdomain: null as string | null,
        jsFileUrl: null as string | null,
        trufflehogSource: null as string | null,
        asset: targetIp ? (targetPort ? `${targetIp}:${targetPort}` : targetIp)
                        : ((r.get('title') as string) || null),
        location: username ? `user: ${username}` : null,
        updatedAt: (r.get('updatedAt') ?? null) as unknown,
      }
    }))

    // Priority weighting. `secret_type` in RedAmon is the pattern-family name
    // (e.g. "AWS Secret Key", "GitHub Token Classic", "JWT Token", ...). Match
    // priority by keyword on the lower-cased label.
    const typePriority = (rawType: string): number => {
      const t = (rawType || '').toLowerCase()
      // A username/password the agent recovered by exploiting the target. It
      // ranks with the private keys rather than falling through to the default,
      // where it tied with everything else and the order came down to which
      // query happened to run first.
      if (t.includes('credential')) return 0
      if (t.includes('aws') && (t.includes('secret') || t.includes('key'))) return 0
      if (t.includes('private') && t.includes('key')) return 0
      if (t.includes('gcp') || t.includes('azure')) return 1
      if (t.includes('github') && t.includes('token')) return 1
      if (t.includes('jwt') || t.includes('db') || t.includes('database')) return 2
      if (t.includes('api') && t.includes('key')) return 3
      if (t.includes('token') || t.includes('bearer')) return 3
      if (t.includes('password')) return 4
      return 5
    }

    // Prefer validated > format_validated > unvalidated, then by type priority,
    // then higher entropy first.
    // Shared with SecretsTable's VALIDATION_CLASS. `verify_error` outranks
    // `unvalidated`: the verify call failed, which is NOT proof the credential is
    // dead. `unverified` (verification switched off) sits below both — nobody
    // looked, so it must never read as "checked and safe".
    const VALIDATION_RANK: Record<string, number> = {
      validated: 0, format_validated: 1, verify_error: 2, unvalidated: 3,
      unverified: 4, skipped: 5, invalid: 6,
    }
    rows.sort((a, b) => {
      const va = VALIDATION_RANK[a.validationStatus ?? 'unvalidated'] ?? 3
      const vb = VALIDATION_RANK[b.validationStatus ?? 'unvalidated'] ?? 3
      if (va !== vb) return va - vb
      const ta = typePriority(a.secretType)
      const tb = typePriority(b.secretType)
      if (ta !== tb) return ta - tb
      return (b.entropy ?? 0) - (a.entropy ?? 0)
    })

    return NextResponse.json({ rows, meta: { totalRows: rows.length } })
  } catch (error) {
    console.error('Red-zone secrets error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}
