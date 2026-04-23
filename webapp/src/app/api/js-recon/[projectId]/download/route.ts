import { NextRequest, NextResponse } from 'next/server'
import { createHash } from 'crypto'

// Reuse the graph API's Neo4j driver
import { getSession } from '../../../graph/neo4j'

const PROJECT_ID_RE = /^[a-zA-Z0-9_-]+$/

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

function generateEtag(data: JsReconResponse): string {
  const raw = `${data.secrets.length}:${data.endpoints.length}:${data.dependencies.length}:${data.dom_sinks.length}:${data.frameworks.length}:${data.source_maps.length}:${data.dev_comments.length}:${data.emails.length}:${data.ip_addresses.length}:${data.object_references.length}:${data.cloud_assets.length}:${data.external_domains.length}`
  return createHash('md5').update(raw).digest('hex').slice(0, 16)
}

interface RouteParams {
  params: Promise<{ projectId: string }>
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
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

  const session = getSession()
  try {
    // 1. JsReconFinding nodes (files + findings)
    const findingsResult = await session.run(
      `
      MATCH (jf:JsReconFinding {project_id: $pid})
      RETURN jf.finding_type AS findingType,
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
             jf.potential_idor AS potentialIdor
      `,
      { pid: projectId }
    )

    // 2. Secrets with source='js_recon'
    const secretsResult = await session.run(
      `
      MATCH (s:Secret {project_id: $pid, source: 'js_recon'})
      RETURN s.id AS id,
             s.secret_type AS name,
             s.severity AS severity,
             s.sample AS redacted_value,
             s.matched_text AS matched_text,
             s.key_type AS category,
             s.source_url AS source_url,
             s.confidence AS confidence,
             s.detection_method AS detection_method,
             s.validation_status AS validation_status,
             s.validation_info AS validation_info
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
      RETURN e.path AS path,
             e.method AS method,
             e.full_url AS full_url,
             e.endpoint_type AS type,
             e.category AS category,
             e.baseurl AS base_url,
             jf.source_url AS source_js
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
    const object_references: any[] = []
    const cloud_assets: any[] = []
    const external_domains: any[] = []
    let jsFilesCount = 0

    for (const record of findingsResult.records) {
      const type = record.get('findingType')
      const base = {
        id: record.get('id'),
        severity: record.get('severity'),
        confidence: record.get('confidence'),
        title: record.get('title'),
        detail: record.get('detail'),
        evidence: record.get('evidence'),
        source_url: record.get('sourceUrl'),
        base_url: record.get('baseUrl'),
        finding_type: type,
      }

      switch (type) {
        case 'js_file':
          jsFilesCount++
          break
        case 'dependency_confusion':
          dependencies.push({
            ...base,
            package_name: base.title,
          })
          break
        case 'source_map_exposure':
          source_maps.push({
            ...base,
            js_url: base.source_url,
          })
          break
        case 'dom_sink':
          dom_sinks.push({
            ...base,
            type: base.title,
            pattern: base.evidence,
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
            email: base.title,
            category: 'unknown',
            source_url: base.source_url,
            context: base.detail,
          })
          break
        case 'internal_ip':
          ip_addresses.push({
            ip: base.title,
            type: base.evidence || 'private',
            source_url: base.source_url,
            context: base.detail,
          })
          break
        case 'object_reference':
          object_references.push({
            type: base.evidence || 'uuid',
            value: base.title,
            source_url: base.source_url,
            context: base.detail,
            potential_idor: record.get('potentialIdor') ?? false,
          })
          break
        case 'cloud_asset':
          cloud_assets.push({
            provider: record.get('cloudProvider') || base.evidence,
            type: record.get('cloudAssetType') || 'cloud_asset',
            url: base.title,
            source_url: base.source_url,
          })
          break
        case 'external_domain': {
          const ts = record.get('timesSeen')
          external_domains.push({
            domain: base.title,
            source: 'js_recon',
            urls: record.get('sampleUrls') || [],
            times_seen: typeof ts === 'object' && ts !== null && 'low' in ts ? ts.low : (ts ?? 1),
          })
          break
        }
      }
    }

    // Map secrets
    const secrets = secretsResult.records.map((r: any) => {
      let validation: Record<string, any> = { status: r.get('validation_status') || 'unvalidated' }
      const vi = r.get('validation_info')
      if (vi) {
        try { validation = JSON.parse(vi) } catch {}
      }
      return {
        id: r.get('id'),
        name: r.get('name'),
        severity: r.get('severity'),
        redacted_value: r.get('redacted_value'),
        matched_text: r.get('matched_text'),
        category: r.get('category'),
        source_url: r.get('source_url'),
        confidence: r.get('confidence'),
        detection_method: r.get('detection_method'),
        validation,
      }
    })

    // Map endpoints
    const endpoints = endpointsResult.records.map((r: any) => ({
      method: r.get('method'),
      path: r.get('path'),
      full_url: r.get('full_url'),
      type: r.get('type'),
      category: r.get('category'),
      base_url: r.get('base_url'),
      source_js: r.get('source_js') || '',
    }))

    // Check if any data exists (any of the persisted finding types)
    const hasAnyData =
      jsFilesCount > 0 ||
      secrets.length > 0 ||
      endpoints.length > 0 ||
      emails.length > 0 ||
      ip_addresses.length > 0 ||
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
      object_references,
      cloud_assets,
      external_domains,
      summary: {
        total_secrets: secrets.length,
        total_endpoints: endpoints.length,
        total_findings: dependencies.length + source_maps.length + dom_sinks.length + frameworks.length
          + dev_comments.length + emails.length + ip_addresses.length + object_references.length
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
    console.error('JS Recon query error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Query failed' },
      { status: 500 }
    )
  } finally {
    await session.close()
  }
}

export async function HEAD(_request: NextRequest, { params }: RouteParams) {
  const { projectId } = await params
  if (!PROJECT_ID_RE.test(projectId)) {
    return new NextResponse(null, { status: 400 })
  }

  const session = getSession()
  try {
    const result = await session.run(
      `MATCH (jf:JsReconFinding {project_id: $pid}) RETURN count(jf) AS cnt LIMIT 1`,
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
