import { NextRequest, NextResponse } from 'next/server'
import { internalKeyHeaders } from '@/lib/agentAuth'
import { Prisma } from '@prisma/client'
import prisma from '@/lib/prisma'
import { isBlankModelField } from '@/components/projects/ProjectForm/projectLlmGate.logic'
import { requireEffectiveUser, ownerScope } from '@/lib/access'
import { validateJevEngineChange } from '@/lib/reconSettings/jevEngine'
import { numericBoundsRefusal } from '@/lib/reconSettings/numericBounds'
import { normalizeUserSkillToggles, UserSkillError } from '@/lib/userSkills'
import { describeInvalid, normalizeHost, splitWildcard, validateDomainBatch } from '@/lib/domainBatch'
import { resolveScopeGroups, scopeGuardrailNames, softGuardrailNames } from '@/lib/scopeGroups'
import { seedDomainNames, seedProjectDomains } from '@/lib/graphSeedDomains'
import { firstHardBlocked } from '@/lib/hard-guardrail'
import { crossOriginResponse, sameOrigin } from '@/lib/plugins/sameOrigin'
import { actingAdminId } from '@/lib/roe/actor'
import { buildCreateRoeArtefacts, stripRoeArtefacts } from '@/lib/roe/createRoe'
import { extractRoeText, ExtractError, type ExtractedDocument } from '@/lib/roe/extractText'
import { ALLOWED_EXTENSIONS_LABEL, MAX_FILE_SIZE, classifyRoeFile, type RoeFileKind } from '@/lib/roe/limits'
import { contentLengthProblem } from '@/lib/roe/upload'
import { internalError } from '@/lib/routeErrors'
import { cleanOpenApiSources, normalizeOpenApiSourceIds, validateOpenApiSettings } from '@/lib/validation/openapiSettings'
import { projectModelProblem } from '@/lib/agentInTheLoop'
import { ownershipTokenForCreate } from '@/lib/ownershipToken'

const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8080'
const SOFT_GUARDRAIL_TIMEOUT_MS = 10_000

// GET /api/projects - List the effective user's projects.
// The client-supplied ?userId is ignored as an auth input: the list is always
// scoped to the caller's effective user (admin -> own, unless simulating X).
export async function GET() {
  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    const projects = await prisma.project.findMany({
      where: ownerScope(eff),
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        userId: true,
        name: true,
        description: true,
        targetDomain: true,
        // The scope fields, so a card names a batch by its scope groups (a
        // batch row's targetDomain is empty).
        subdomainList: true,
        ipMode: true,
        targetIps: true,
        domainBatchMode: true,
        domainBatchHosts: true,
        captureProxyEnabled: true,
        createdAt: true,
        updatedAt: true,
        user: {
          select: {
            id: true,
            name: true,
            email: true
          }
        }
      }
    })

    return NextResponse.json(projects)
  } catch (error) {
    return internalError(error, 'Failed to fetch projects')
  }
}

// POST /api/projects - Create a new project
// Accepts either JSON or multipart/form-data (when RoE document is attached)
export async function POST(request: NextRequest) {
  try {
    // The new project is owned by the caller's effective user; the body-supplied
    // userId is ignored so a caller cannot create a project under another user.
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    let body: Record<string, unknown>
    let roeFile: { name: string; kind: RoeFileKind; bytes: Buffer } | null = null
    let roeDoc: ExtractedDocument | null = null

    const contentType = request.headers.get('content-type') || ''

    if (contentType.includes('multipart/form-data')) {
      // The multipart create carries the RoE document: the same origin check and
      // size limit as the RoE routes, checked before the body is parsed.
      if (!sameOrigin(request)) return crossOriginResponse()
      const lengthProblem = contentLengthProblem(request)
      if (lengthProblem) return lengthProblem
      const formData = await request.formData()
      const jsonStr = formData.get('data') as string
      body = JSON.parse(jsonStr)

      const file = formData.get('roeDocument')
      if (file instanceof File) {
        const kind = classifyRoeFile(file.name, file.type)
        if (!kind) {
          return NextResponse.json({ error: `Unsupported RoE file type. Use ${ALLOWED_EXTENSIONS_LABEL}.` }, { status: 400 })
        }
        if (file.size > MAX_FILE_SIZE) {
          return NextResponse.json({ error: `The RoE file is larger than ${MAX_FILE_SIZE / 1024 / 1024} MB.` }, { status: 413 })
        }
        roeFile = { name: file.name, kind, bytes: Buffer.from(await file.arrayBuffer()) }
        // The stored text is the server's own extraction, never the client's copy.
        try {
          roeDoc = await extractRoeText(roeFile.bytes, kind)
        } catch (e) {
          if (e instanceof ExtractError) return NextResponse.json({ error: e.message, code: e.code }, { status: e.status })
          throw e
        }
      }
    } else {
      body = await request.json()
    }

    if ('openapiSources' in body) body.openapiSources = cleanOpenApiSources(body.openapiSources)
    const openapiError = validateOpenApiSettings(body)
    if (openapiError) {
      return NextResponse.json({ error: openapiError }, { status: 400 })
    }
    if ('openapiSources' in body) {
      body.openapiSources = normalizeOpenApiSourceIds(body.openapiSources)
    }

    const { userId: _bodyUserId, name, targetDomain, ipMode, domainBatchMode,
      id: clientId, ...optionalParams } = body as {
      userId: string
      name: string
      targetDomain?: string
      ipMode?: boolean
      domainBatchMode?: boolean
      id?: string
      [key: string]: unknown
    }

    const loopProblem = projectModelProblem(optionalParams)
    if (loopProblem) {
      return NextResponse.json({ error: loopProblem, code: 'loop_model_not_allowed' }, { status: 400 })
    }

    // Domain batch: the groups are ALWAYS re-derived here from the raw host list.
    // A client-supplied domainBatchGroups is discarded, so the list the operator
    // approved in the preview is the only thing that can define scope.
    // Read BEFORE the STRING_ARRAY_FIELDS sanitizer runs (it is further down), so
    // accept the comma-separated string form an LLM-parsed body can carry.
    const rawBatchHosts = optionalParams.domainBatchHosts
    const batchHosts = Array.isArray(rawBatchHosts)
      ? (rawBatchHosts as unknown[]).filter((h): h is string => typeof h === 'string')
      : typeof rawBatchHosts === 'string'
        ? rawBatchHosts.split(',')
        : []
    const batch = domainBatchMode ? validateDomainBatch(batchHosts) : null
    if (batch && !batch.ok) {
      return NextResponse.json({ error: batch.errors.join(' ') }, { status: 400 })
    }

    // Owner is the effective user, never the client-supplied body value.
    const userId = eff.userId
    void _bodyUserId

    if (!name) {
      return NextResponse.json(
        { error: 'name is required' },
        { status: 400 }
      )
    }

    // A client-supplied id becomes the project's primary key AND a path/pattern
    // component downstream (recon output filenames, the orchestrator's
    // /project/<id>/files URL, the JS-recon upload directories). Anything but a
    // plain cuid-shaped token is refused here so no consumer has to defend
    // against separators or match metacharacters in an id.
    if (clientId !== undefined && !/^[a-z0-9]{20,32}$/.test(String(clientId))) {
      return NextResponse.json(
        { error: 'Invalid project id.' },
        { status: 400 }
      )
    }

    // targetDomain is required only when the target is a single domain: IP mode
    // carries targetIps, Domain batch carries its host list (validated above).
    if (!ipMode && !domainBatchMode && !targetDomain) {
      return NextResponse.json(
        { error: 'targetDomain is required when not in IP mode' },
        { status: 400 }
      )
    }
    if (ipMode && domainBatchMode) {
      return NextResponse.json(
        { error: 'A project cannot be in both IP mode and Domain batch mode.' },
        { status: 400 }
      )
    }

    // Verify user exists
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    const rawSubdomains = optionalParams.subdomainList
    const scopeFields = {
      ipMode, domainBatchMode, domainBatchHosts: batchHosts, targetDomain,
      subdomainList: Array.isArray(rawSubdomains)
        ? rawSubdomains.filter((s): s is string => typeof s === 'string')
        : typeof rawSubdomains === 'string' ? rawSubdomains.split(',') : [],
    }
    // The single-domain target and prefixes get the same rules as a batch entry
    // (no public suffix, no IP, prefixes of any depth): a direct POST bypasses
    // the form's own check.
    const scope = resolveScopeGroups(scopeFields)
    if (!ipMode && !domainBatchMode && scope.invalid.length > 0) {
      return NextResponse.json({ error: describeInvalid(scope.invalid) }, { status: 400 })
    }

    // Hard guardrail: deterministic, non-disableable - always blocks government/public domains.
    // Checks every host AND every group root the project would scan, so a batch
    // cannot smuggle one in, and the refusal names the host that was listed.
    const blocked = firstHardBlocked(scopeGuardrailNames(scopeFields))
    if (blocked) {
      return NextResponse.json(
        { error: `Target permanently blocked: ${blocked.name}: ${blocked.reason}` },
        { status: 403 }
      )
    }

    // Soft guardrail (LLM-based): check if domain/IPs are allowed before creating
    if (optionalParams.targetGuardrailEnabled !== false) {
      try {
        const guardrailResponse = await fetch(`${AGENT_API_URL}/guardrail/check-target`, {
          method: 'POST',
          headers: internalKeyHeaders({ 'Content-Type': 'application/json' }),
          // Fail-open by design, so a hung agent must not stall the create either.
          signal: AbortSignal.timeout(SOFT_GUARDRAIL_TIMEOUT_MS),
          body: JSON.stringify({
            // Batch mode has no single targetDomain. Send the orgs and scan roots
            // as a LIST: joining them into target_domain feeds a singular prompt
            // that can approve the set despite one blocked member. A single
            // target adds its org and, for a private-section org, the platform
            // owner, so the model judges the company rather than a hostname.
            target_domain: (ipMode || domainBatchMode) ? '' : (scope.groups[0]?.scanRoot ?? ''),
            target_domains: ipMode ? [] : softGuardrailNames(scope.groups)
              .filter(n => domainBatchMode || n !== scope.groups[0]?.scanRoot),
            target_ips: ipMode ? (optionalParams.targetIps || []) : [],
            user_id: userId,
          }),
        })

        if (guardrailResponse.ok) {
          const guardrailResult = await guardrailResponse.json()
          if (guardrailResult.allowed === false) {
            return NextResponse.json(
              { error: `Target blocked by guardrail: ${guardrailResult.reason}` },
              { status: 403 }
            )
          }
        }
        // If guardrail is unreachable or returns non-OK, fail open (allow)
      } catch (guardrailError) {
        console.warn('Guardrail check failed, proceeding with project creation:', guardrailError)
      }
    }

    // Sanitize array fields - LLM parsing may return strings instead of arrays
    // String[] fields: split comma-separated strings into arrays
    const STRING_ARRAY_FIELDS = [
      'subdomainList', 'targetIps', 'domainBatchHosts', 'scanModules', 'nucleiSeverity',
      'nucleiTemplates', 'nucleiExcludeTemplates', 'nucleiCustomTemplates',
      'nucleiTags', 'nucleiExcludeTags',
      'httpxPaths', 'httpxCustomHeaders', 'httpxMatchCodes', 'httpxFilterCodes',
      'katanaExcludePatterns', 'katanaCustomHeaders',
      'jsReconEndpointCustomHeaders',
      'gauProviders', 'gauBlacklistExtensions', 'gauYearRange',
      'kiterunnerWordlists', 'kiterunnerHeaders', 'kiterunnerBruteforceMethods',
      'roeExcludedHosts', 'roeExcludedHostReasons', 'roeTimeWindowDays',
      'roeForbiddenTools', 'roeForbiddenCategories',
      'roeThirdPartyProviders', 'roeComplianceFrameworks',
    ]
    for (const key of STRING_ARRAY_FIELDS) {
      if (key in optionalParams && typeof optionalParams[key] === 'string') {
        optionalParams[key] = (optionalParams[key] as string).split(',').map((s: string) => s.trim()).filter(Boolean)
      }
    }
    // Int[] fields: ensure elements are numbers, not strings
    const INT_ARRAY_FIELDS = [
      'jsReconEndpointAcceptStatus',
      'gauVerifyAcceptStatus', 'kiterunnerIgnoreStatus', 'kiterunnerMatchStatus',
    ]
    for (const key of INT_ARRAY_FIELDS) {
      if (key in optionalParams) {
        const val = optionalParams[key]
        if (typeof val === 'string') {
          optionalParams[key] = val.split(',').map((s: string) => parseInt(s.trim(), 10)).filter((n: number) => !isNaN(n))
        } else if (Array.isArray(val)) {
          optionalParams[key] = val.map((v: unknown) => typeof v === 'string' ? parseInt(v, 10) : v).filter((n: unknown) => typeof n === 'number' && !isNaN(n))
        }
      }
    }

    // Strip unknown keys + coerce types (LLM may return strings for Int/Boolean fields)
    const VALID_FIELDS = new Set(Object.values(Prisma.ProjectScalarFieldEnum))
    // `roeEnabled` joins these because it is DERIVED from whether any engagement
    // limit is set, and nothing writes it. Creating a project with it set would
    // store a value that disagrees with the derivation from the first moment.
    // `domainBatchGroups` is always derived from the host list below, so a
    // client value is never stored, not even on a project that is not a batch.
    const NON_SETTABLE = new Set([
      'id', 'userId', 'name', 'targetDomain', 'ipMode', 'createdAt', 'updatedAt',
      'roeEnabled', 'domainBatchGroups',
    ])

    // Build type map from Prisma DMMF for type coercion
    const projectModel = Prisma.dmmf.datamodel.models.find((m: { name: string }) => m.name === 'Project')
    const fieldTypeMap = new Map<string, string>()
    if (projectModel) {
      for (const f of projectModel.fields as readonly { name: string; type: string }[]) {
        fieldTypeMap.set(f.name, f.type)
      }
    }

    const sanitizedParams: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(optionalParams)) {
      if (!VALID_FIELDS.has(key as Prisma.ProjectScalarFieldEnum) || NON_SETTABLE.has(key) || value === null || value === undefined) {
        continue
      }
      // LLM model fields must never be persisted blank: an empty string would
      // override the schema @default("claude-opus-4-6") with "", leaving the
      // project permanently model-unconfigured. Drop blanks so Prisma applies
      // the default. Server-side backstop for the client model-gate.
      if (isBlankModelField(key, value)) {
        continue
      }
      const fieldType = fieldTypeMap.get(key)
      // Coerce string → Boolean
      if (fieldType === 'Boolean' && typeof value === 'string') {
        sanitizedParams[key] = value.toLowerCase() === 'true'
      // Coerce string → Int
      } else if (fieldType === 'Int' && typeof value === 'string') {
        const num = parseInt(value, 10)
        if (!isNaN(num)) sanitizedParams[key] = num
      // Coerce string → Float
      } else if (fieldType === 'Float' && typeof value === 'string') {
        const num = parseFloat(value)
        if (!isNaN(num)) sanitizedParams[key] = num
      // Parse string → Json
      } else if (fieldType === 'Json' && typeof value === 'string') {
        try { sanitizedParams[key] = JSON.parse(value) } catch { /* skip invalid JSON */ }
      } else {
        sanitizedParams[key] = value
      }
    }

    // Sanitize string inputs that are used as hostnames/IPs (trailing spaces break DNS)
    if (typeof sanitizedParams.subdomainList === 'object' && Array.isArray(sanitizedParams.subdomainList)) {
      sanitizedParams.subdomainList = (sanitizedParams.subdomainList as string[]).map(s => s.trim()).filter(Boolean)
    }
    if (typeof sanitizedParams.targetIps === 'object' && Array.isArray(sanitizedParams.targetIps)) {
      sanitizedParams.targetIps = (sanitizedParams.targetIps as string[]).map(s => s.trim()).filter(Boolean)
    }

    // Judged after the coercion above, so a number an LLM-parsed body sent as
    // text gets the same verdict create_project gives it.
    const outOfBounds = numericBoundsRefusal(sanitizedParams)
    if (outOfBounds) {
      return NextResponse.json({ ...outOfBounds, code: 'setting_rejected' }, { status: 400 })
    }

    // The user-skill toggles may name only the creator's own skills, at most 20 of them on.
    if ('attackSkillConfig' in sanitizedParams) {
      try {
        sanitizedParams.attackSkillConfig = await normalizeUserSkillToggles(prisma, userId, sanitizedParams.attackSkillConfig)
      } catch (e) {
        if (e instanceof UserSkillError) return NextResponse.json({ error: e.message, code: e.code }, { status: 400 })
        throw e
      }
    }

    // The document's artefacts come from the server, never from the body: the
    // text is the extraction above, and the parse is rebuilt from the confirmed
    // keys a document may write. A create without a document stores none.
    const clientRoeParsed = sanitizedParams.roeParsedJson
    stripRoeArtefacts(sanitizedParams)
    if (roeFile && roeDoc) {
      Object.assign(sanitizedParams, buildCreateRoeArtefacts({
        doc: roeDoc,
        file: roeFile,
        clientParsed: clientRoeParsed,
        appliedById: userId,
        actingAdminId: await actingAdminId(eff),
      }))
    }

    // A new project starts with every engine on the LLM, so any Jev flag in the
    // body is a switch-on and needs a Jev provider of the creating user selected.
    // Judged on the coerced values: the string "true" becomes true above, and
    // checking the raw body let it through.
    const jevError = await validateJevEngineChange(null, sanitizedParams, userId)
    if (jevError) {
      return NextResponse.json({ error: jevError }, { status: 400 })
    }

    sanitizedParams.ownershipToken = ownershipTokenForCreate(sanitizedParams.ownershipToken)

    // Create project with required fields and valid optional params.
    // If the frontend provided a pre-generated ID (for uploads during creation), use it.
    const project = await prisma.project.create({
      data: {
        ...(clientId ? { id: clientId } : {}),
        userId,
        name: name.trim(),
        // A wildcard here means what an empty prefix list already means, so it is
        // normalized rather than refused. Unstripped it would reach `subfinder -d`,
        // the crt.sh URL, a puredns filename and a Cypher MERGE, and the in-scope
        // test `endswith('.' + domain)` would then match nothing - a green scan
        // that finds zero hosts.
        targetDomain: (ipMode || domainBatchMode) ? '' : splitWildcard(normalizeHost(targetDomain || '')).rest,
        ipMode: ipMode || false,
        ...sanitizedParams,
        // After sanitizedParams so a client-supplied domainBatchGroups cannot win.
        domainBatchMode: domainBatchMode || false,
        // A non-batch project keeps no batch scope: recon's auth scope and the
        // agent's replay read these columns whatever the mode.
        ...(batch ? { domainBatchHosts: batch.entries,
                      domainBatchGroups: batch.legacy as unknown as Prisma.InputJsonValue }
                  : { domainBatchHosts: [] }),
      }
    })

    // Create the Domain nodes (one per org) so the target is visible in the graph
    // immediately. Best-effort; the first full recon writes them anyway.
    await seedProjectDomains(seedDomainNames(resolveScopeGroups(project).groups), project.userId, project.id)

    // Sync JS Recon files uploaded during creation (before project existed in DB)
    if (clientId) {
      try {
        const { existsSync } = await import('fs')
        const { readdir } = await import('fs/promises')
        const path = await import('path')

        const JS_RECON_UPLOAD_PATH = process.env.JS_RECON_UPLOAD_PATH || '/data/js-recon-uploads'
        const JS_RECON_CUSTOM_PATH = process.env.JS_RECON_CUSTOM_PATH || '/data/js-recon-custom'

        const updateData: Record<string, unknown> = {}

        // Sync uploaded JS files
        const uploadDir = path.join(JS_RECON_UPLOAD_PATH, clientId)
        if (existsSync(uploadDir)) {
          const files = (await readdir(uploadDir)).filter(f => !f.startsWith('.'))
          if (files.length > 0) updateData.jsReconUploadedFiles = files
        }

        // Sync custom extension files
        const customDir = path.join(JS_RECON_CUSTOM_PATH, clientId)
        const FILE_TYPE_MAP: Record<string, string> = {
          patterns: 'jsReconCustomPatterns',
          'sourcemap-paths': 'jsReconCustomSourcemapPaths',
          packages: 'jsReconCustomPackages',
          'endpoint-keywords': 'jsReconCustomEndpointKeywords',
          frameworks: 'jsReconCustomFrameworks',
        }
        for (const [dirName, prismaField] of Object.entries(FILE_TYPE_MAP)) {
          const typeDir = path.join(customDir, dirName)
          if (existsSync(typeDir)) {
            const entries = await readdir(typeDir)
            if (entries.length > 0) {
              updateData[prismaField] = path.join(typeDir, entries[0])
            }
          }
        }

        if (Object.keys(updateData).length > 0) {
          await prisma.project.update({ where: { id: clientId }, data: updateData })
        }
      } catch (e) {
        console.warn('Failed to sync JS Recon uploads on project creation:', e)
      }
    }

    return NextResponse.json(project, { status: 201 })
  } catch (error) {
    return internalError(error, 'Failed to create project')
  }
}
