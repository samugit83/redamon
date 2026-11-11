import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { createHash } from 'crypto'

// Reuse the graph API's Neo4j driver
import { getGraphSession } from '../../../graph/neo4j'
import { notMuted } from '@/lib/graphMute'
import { jsReconSecretFromRecord } from '@/lib/secrets/jsReconSecret'
import { internalError } from '@/lib/routeErrors'

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

/** A neo4j Integer arrives as {low, high}; absent stays null. */
function toNum(value: unknown): number | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'object' && 'low' in (value as object)) return (value as { low: number }).low
  return typeof value === 'number' ? value : null
}

/** `@acme` for `@acme/ui`; null for an unscoped name. */
function npmScopeOf(packageName: unknown): string | null {
  return typeof packageName === 'string' && /^@[^/]+\//.test(packageName) ? packageName.split('/')[0] : null
}

// Simple in-memory cache (same pattern as graph route)
interface CacheEntry {
  data: JsReconResponse
  etag: string
  timestamp: number
}
const cache = new Map<string, CacheEntry>()
const TTL = 10_000 // 10s

interface JsReconResponse {
  scan_metadata: { js_files_analyzed: number }
  secrets: any[]
  endpoints: any[]
  dependencies: any[]
  source_maps: any[]
  dom_sinks: any[]
  frameworks: any[]
  dev_comments: any[]
  emails: any[]
  ip_addresses: any[]
  dev_references: any[]
  object_references: any[]
  cloud_assets: any[]
  external_domains: any[]
  summary: {
    total_secrets: number
    total_endpoints: number
    total_findings: number
    validated_keys?: { live: number }
  }
}

/**
 * Bump when the answer gains or changes fields. The browser revalidates its
 * cached body by tag alone, so without it a body cached before the change gets
 * a 304 and stays in use until the graph itself next changes.
 */
const RESPONSE_SHAPE = 3

function generateEtag(data: JsReconResponse): string {
  const raw = `shape${RESPONSE_SHAPE}:${data.secrets.length}:${data.endpoints.length}:${data.dependencies.length}:${data.dom_sinks.length}:${data.frameworks.length}:${data.source_maps.length}:${data.dev_comments.length}:${data.emails.length}:${data.ip_addresses.length}:${data.dev_references.length}:${data.object_references.length}:${data.cloud_assets.length}:${data.external_domains.length}`
  const hash = createHash('md5').update(raw)
  // A rescan recreates the nodes, usually with the same counts but new ids. A
  // count-only tag would 304 and leave the Node ID column pointing at deleted
  // nodes, so the ids are part of the tag.
  for (const list of [
    data.secrets, data.endpoints, data.dependencies, data.dom_sinks, data.frameworks,
    data.source_maps, data.dev_comments, data.emails, data.ip_addresses, data.dev_references,
    data.object_references, data.cloud_assets, data.external_domains,
  ]) {
    // updatedAt too: a rescan that re-rates the same nodes keeps their ids.
    for (const row of list) hash.update(`${row.nodeId ?? ''}@${row.updatedAt ?? ''},`)
    hash.update('|')
  }
  return hash.digest('hex').slice(0, 16)
}

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  if (!PROJECT_ID_RE.test(projectId)) {
    return new NextResponse(null, { status: 400 })
  }

  const fresh = request.nextUrl.searchParams.get('fresh') === '1'
  if (fresh) cache.delete(projectId)

  // ETag conditional request
  const ifNoneMatch = request.headers.get('if-none-match')

  // Check cache
  const cached = cache.get(projectId)
  if (cached && Date.now() - cached.timestamp < TTL) {
    if (ifNoneMatch && ifNoneMatch === `"${cached.etag}"`) {
      return new NextResponse(null, { status: 304, headers: { 'ETag': `"${cached.etag}"`, 'Cache-Control': 'private, no-cache' } })
    }
    return NextResponse.json(cached.data, { headers: { 'ETag': `"${cached.etag}"`, 'Cache-Control': 'private, no-cache' } })
  }
  cache.delete(projectId)

  const session = getGraphSession()
  try {
    // 1. JsReconFinding nodes (files + findings)
    const findingsResult = await session.run(
      `
      MATCH (jf:JsReconFinding {project_id: $pid})
      WHERE ${notMuted('jf')}
      RETURN toString(id(jf)) AS nodeId,
             jf.finding_type AS findingType,
             jf.severity AS severity,
             jf.confidence AS confidence,
             jf.title AS title,
             jf.detail AS detail,
             jf.evidence AS evidence,
             jf.source_url AS sourceUrl,
             jf.base_url AS baseUrl,
             jf.id AS id,
             jf.cloud_provider AS cloudProvider,
             jf.cloud_asset_type AS cloudAssetType,
             jf.times_seen AS timesSeen,
             jf.sample_urls AS sampleUrls,
             jf.potential_idor AS potentialIdor,
             jf.map_url AS mapUrl,
             jf.accessible AS accessible,
             jf.fetch_result AS fetchResult,
             jf.discovery_method AS discoveryMethod,
             jf.files_count AS filesCount,
             jf.first_party_files AS firstPartyFiles,
             jf.source_files AS sourceFiles,
             jf.secrets_in_source AS secretsInSource,
             jf.third_party AS thirdParty,
             jf.line AS line,
             jf.user_source AS userSource,
             jf.vendor AS vendor,
             jf.package_name AS packageName,
             jf.package_scope AS packageScope,
             jf.npm_exists AS npmExists,
             jf.recommendation AS recommendation,
             coalesce(jf.source_urls, [jf.source_url]) AS sourceUrls,
             jf.updated_at AS updatedAt
      `,
      { pid: projectId }
    )

    // 2. Secrets with source='js_recon'
    const secretsResult = await session.run(
      `
      MATCH (s:Secret {project_id: $pid, source: 'js_recon'})
      WHERE ${notMuted('s')}
      RETURN toString(id(s)) AS nodeId,
             s.id AS id,
             s.secret_type AS name,
             s.severity AS severity,
             s.sample AS redacted_value,
             s.matched_text AS matched_text,
             coalesce(s.secret_value, s.matched_text) AS secret_value,
             s.paired_secret AS paired_secret,
             s.context AS context,
             s.raw_context AS raw_context,
             s.key_type AS category,
             s.source_url AS source_url,
             s.line_number AS line_number,
             s.confidence AS confidence,
             s.detection_method AS detection_method,
             s.alternate_names AS alternate_names,
             s.validation_status AS validation_status,
             s.validation_info AS validation_info,
             s.public_client_key AS public_client_key,
             s.updated_at AS updatedAt
      `,
      { pid: projectId }
    )

    // 3. Endpoints with source='js_recon' or js_recon_source=true
    //    Traverse HAS_ENDPOINT to get the source JS file URL
    const endpointsResult = await session.run(
      `
      MATCH (e:Endpoint {project_id: $pid})
      WHERE e.source = 'js_recon' OR e.js_recon_source = true
      OPTIONAL MATCH (jf:JsReconFinding {finding_type: 'js_file'})-[:HAS_ENDPOINT]->(e)
        WHERE ${notMuted('jf')}
      RETURN toString(id(e)) AS nodeId,
             e.path AS path,
             e.method AS method,
             e.full_url AS full_url,
             e.endpoint_type AS type,
             e.category AS category,
             e.baseurl AS base_url,
             jf.source_url AS source_js,
             e.updated_at AS updatedAt
      `,
      { pid: projectId }
    )

    // Map findings by type
    const dependencies: any[] = []
    const source_maps: any[] = []
    const dom_sinks: any[] = []
    const frameworks: any[] = []
    const dev_comments: any[] = []
    const emails: any[] = []
    const ip_addresses: any[] = []
    const dev_references: any[] = []
    const object_references: any[] = []
    const cloud_assets: any[] = []
    const external_domains: any[] = []
    let jsFilesCount = 0

    for (const record of findingsResult.records) {
      const type = record.get('findingType')
      const base = {
        nodeId: record.get('nodeId') ?? null,
        id: record.get('id'),
        severity: record.get('severity'),
        confidence: record.get('confidence'),
        title: record.get('title'),
        detail: record.get('detail'),
        evidence: record.get('evidence'),
        source_url: record.get('sourceUrl'),
        base_url: record.get('baseUrl'),
        finding_type: type,
        updatedAt: record.get('updatedAt') ?? null,
      }

      switch (type) {
        case 'js_file':
          jsFilesCount++
          break
        case 'dependency_confusion': {
          // A node written before source_urls carries only source_url, often
          // empty; one written before package_name is named by its title.
          // One written before package_scope / npm_exists gets its scope from
          // the package name and npm_exists null: unknown, never "not on npm".
          const urls = record.get('sourceUrls')
          const packageName = record.get('packageName')
          const npmExists = record.get('npmExists')
          dependencies.push({
            ...base,
            package_name: packageName ?? base.title,
            scope: record.get('packageScope') ?? npmScopeOf(packageName),
            npm_exists: typeof npmExists === 'boolean' ? npmExists : null,
            recommendation: record.get('recommendation') ?? null,
            source_urls: Array.isArray(urls) ? urls.filter((u: unknown) => typeof u === 'string' && u !== '') : [],
          })
          break
        }
        case 'source_map_exposure':
        case 'source_map_reference':
          source_maps.push({
            ...base,
            js_url: base.source_url,
            map_url: record.get('mapUrl') ?? null,
            accessible: record.get('accessible') ?? null,
            fetch_result: record.get('fetchResult') ?? null,
            discovery_method: record.get('discoveryMethod') ?? null,
            files_count: toNum(record.get('filesCount')),
            first_party_files: toNum(record.get('firstPartyFiles')),
            source_files: record.get('sourceFiles') ?? [],
            secrets_in_source: toNum(record.get('secretsInSource')),
            third_party: record.get('thirdParty') ?? null,
          })
          break
        case 'dom_sink':
          dom_sinks.push({
            ...base,
            type: base.title,
            pattern: base.evidence,
            description: base.detail,
            line: toNum(record.get('line')),
            user_source: record.get('userSource') ?? null,
            vendor: record.get('vendor') ?? null,
          })
          break
        case 'framework':
          frameworks.push({
            ...base,
            name: base.evidence || base.title,
            version: base.title?.replace(base.evidence || '', '').trim() || null,
          })
          break
        case 'dev_comment':
          dev_comments.push({
            ...base,
            type: base.title,
            content: base.detail || base.evidence,
          })
          break
        case 'email':
          emails.push({
            nodeId: base.nodeId,
            email: base.title,
            category: 'unknown',
            source_url: base.source_url,
            context: base.detail,
            updatedAt: base.updatedAt,
          })
          break
        case 'dev_reference':
          dev_references.push({
            nodeId: base.nodeId,
            type: base.title,
            value: base.evidence,
            source_url: base.source_url,
            line: toNum(record.get('line')),
            context: base.detail,
            updatedAt: base.updatedAt,
          })
          break
        case 'internal_ip':
          ip_addresses.push({
            nodeId: base.nodeId,
            ip: base.title,
            type: base.evidence || 'private',
            source_url: base.source_url,
            context: base.detail,
            updatedAt: base.updatedAt,
          })
          break
        case 'object_reference':
          object_references.push({
            nodeId: base.nodeId,
            type: base.evidence || 'uuid',
            value: base.title,
            source_url: base.source_url,
            context: base.detail,
            potential_idor: record.get('potentialIdor') ?? false,
            updatedAt: base.updatedAt,
          })
          break
        case 'cloud_asset':
          cloud_assets.push({
            nodeId: base.nodeId,
            provider: record.get('cloudProvider') || base.evidence,
            type: record.get('cloudAssetType') || 'cloud_asset',
            url: base.title,
            source_url: base.source_url,
            updatedAt: base.updatedAt,
          })
          break
        case 'external_domain': {
          const ts = record.get('timesSeen')
          external_domains.push({
            nodeId: base.nodeId,
            domain: base.title,
            source: 'js_recon',
            urls: record.get('sampleUrls') || [],
            times_seen: typeof ts === 'object' && ts !== null && 'low' in ts ? ts.low : (ts ?? 1),
            updatedAt: base.updatedAt,
          })
          break
        }
      }
    }

    // Map secrets
    const secrets = secretsResult.records.map((r: any) => jsReconSecretFromRecord(k => r.get(k)))

    // Map endpoints
    const endpoints = endpointsResult.records.map((r: any) => ({
      nodeId: r.get('nodeId') ?? null,
      method: r.get('method'),
      path: r.get('path'),
      full_url: r.get('full_url'),
      type: r.get('type'),
      category: r.get('category'),
      base_url: r.get('base_url'),
      source_js: r.get('source_js') || '',
      updatedAt: r.get('updatedAt') ?? null,
    }))

    // Check if any data exists (any of the persisted finding types)
    const hasAnyData =
      jsFilesCount > 0 ||
      secrets.length > 0 ||
      endpoints.length > 0 ||
      emails.length > 0 ||
      ip_addresses.length > 0 ||
      dev_references.length > 0 ||
      object_references.length > 0 ||
      cloud_assets.length > 0 ||
      external_domains.length > 0
    if (!hasAnyData) {
      return NextResponse.json(
        { error: 'No JS Recon data. Run a recon scan with JS Recon enabled.' },
        { status: 404 }
      )
    }

    const liveCount = secrets.filter((s: any) => s.validation?.status === 'validated').length

    const data: JsReconResponse = {
      scan_metadata: { js_files_analyzed: jsFilesCount },
      secrets,
      endpoints,
      dependencies,
      source_maps,
      dom_sinks,
      frameworks,
      dev_comments,
      emails,
      ip_addresses,
      dev_references,
      object_references,
      cloud_assets,
      external_domains,
      summary: {
        total_secrets: secrets.length,
        total_endpoints: endpoints.length,
        total_findings: dependencies.length + source_maps.length + dom_sinks.length + frameworks.length
          + dev_comments.length + emails.length + ip_addresses.length + dev_references.length + object_references.length
          + cloud_assets.length + external_domains.length,
        ...(liveCount > 0 ? { validated_keys: { live: liveCount } } : {}),
      },
    }

    const etag = generateEtag(data)
    cache.set(projectId, { data, etag, timestamp: Date.now() })

    if (ifNoneMatch && ifNoneMatch === `"${etag}"`) {
      return new NextResponse(null, { status: 304, headers: { 'ETag': `"${etag}"`, 'Cache-Control': 'private, no-cache' } })
    }

    return NextResponse.json(data, {
      headers: { 'ETag': `"${etag}"`, 'Cache-Control': 'private, no-cache' },
    })
  } catch (error) {
    return internalError(error, 'JS Recon query failed', { log: 'JS Recon query error' })
  } finally {
    await session.close()
  }
}

export async function HEAD(_request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  if (!PROJECT_ID_RE.test(projectId)) {
    return new NextResponse(null, { status: 400 })
  }

  const session = getGraphSession()
  try {
    const result = await session.run(
      `MATCH (jf:JsReconFinding {project_id: $pid}) WHERE ${notMuted('jf')}
       RETURN count(jf) AS cnt LIMIT 1`,
      { pid: projectId }
    )
    const count = result.records[0]?.get('cnt')?.low ?? 0
    return new NextResponse(null, { status: count > 0 ? 200 : 404 })
  } catch {
    return new NextResponse(null, { status: 500 })
  } finally {
    await session.close()
  }
}
