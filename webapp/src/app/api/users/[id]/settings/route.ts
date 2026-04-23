import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

/** Mask a secret string to show only the last 4 characters. */
function maskSecret(value: string): string {
  if (!value || value.length <= 4) return value ? '••••' : ''
  return '••••••••' + value.slice(-4)
}

const TUNNEL_FIELDS = ['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const
const TOOL_NAMES = ['tavily', 'shodan', 'serp', 'nvd', 'vulners', 'urlscan', 'censys', 'fofa', 'otx', 'netlas', 'virustotal', 'zoomeye', 'criminalip', 'quake', 'hunter', 'publicwww', 'hunterhow', 'onyphe', 'driftnet'] as const

// GET /api/users/[id]/settings
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const internal = request.nextUrl.searchParams.get('internal') === 'true'

    let settings = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    // Fetch rotation configs
    const rotationRows = await prisma.apiKeyRotationConfig.findMany({
      where: { userId: id },
    })

    // Build rotationConfigs object
    const rotationConfigs: Record<string, { extraKeys?: string[]; extraKeyCount: number; rotateEveryN: number }> = {}
    for (const row of rotationRows) {
      const keys = row.extraKeys ? row.extraKeys.split('\n').filter(k => k.trim()) : []
      if (internal) {
        rotationConfigs[row.toolName] = { extraKeys: keys, extraKeyCount: keys.length, rotateEveryN: row.rotateEveryN }
      } else {
        rotationConfigs[row.toolName] = { extraKeyCount: keys.length, rotateEveryN: row.rotateEveryN }
      }
    }

    if (!settings) {
      return NextResponse.json({
        githubAccessToken: '',
        tavilyApiKey: '',
        shodanApiKey: '',
        serpApiKey: '',
        nvdApiKey: '',
        vulnersApiKey: '',
        urlscanApiKey: '',
        censysApiToken: '',
        censysOrgId: '',
        fofaApiKey: '',
        otxApiKey: '',
        netlasApiKey: '',
        virusTotalApiKey: '',
        zoomEyeApiKey: '',
        criminalIpApiKey: '',
        quakeApiKey: '',
        hunterApiKey: '',
        publicWwwApiKey: '',
        hunterHowApiKey: '',
        googleApiKey: '',
        googleApiCx: '',
        onypheApiKey: '',
        driftnetApiKey: '',
        ngrokAuthtoken: '',
        chiselServerUrl: '',
        chiselAuth: '',
        rotationConfigs,
      })
    }

    if (!internal) {
      settings = {
        ...settings,
        githubAccessToken: maskSecret(settings.githubAccessToken),
        tavilyApiKey: maskSecret(settings.tavilyApiKey),
        shodanApiKey: maskSecret(settings.shodanApiKey),
        serpApiKey: maskSecret(settings.serpApiKey),
        nvdApiKey: maskSecret(settings.nvdApiKey),
        vulnersApiKey: maskSecret(settings.vulnersApiKey),
        urlscanApiKey: maskSecret(settings.urlscanApiKey),
        censysApiToken: maskSecret(settings.censysApiToken),
        censysOrgId: maskSecret(settings.censysOrgId),
        fofaApiKey: maskSecret(settings.fofaApiKey),
        otxApiKey: maskSecret(settings.otxApiKey),
        netlasApiKey: maskSecret(settings.netlasApiKey),
        virusTotalApiKey: maskSecret(settings.virusTotalApiKey),
        zoomEyeApiKey: maskSecret(settings.zoomEyeApiKey),
        criminalIpApiKey: maskSecret(settings.criminalIpApiKey),
        quakeApiKey: maskSecret(settings.quakeApiKey),
        hunterApiKey: maskSecret(settings.hunterApiKey),
        publicWwwApiKey: maskSecret(settings.publicWwwApiKey),
        hunterHowApiKey: maskSecret(settings.hunterHowApiKey),
        googleApiKey: maskSecret(settings.googleApiKey),
        googleApiCx: maskSecret(settings.googleApiCx),
        onypheApiKey: maskSecret(settings.onypheApiKey),
        driftnetApiKey: maskSecret(settings.driftnetApiKey),
        wpscanApiToken: maskSecret(settings.wpscanApiToken),
        ngrokAuthtoken: maskSecret(settings.ngrokAuthtoken),
        chiselAuth: maskSecret(settings.chiselAuth),
      }
    }

    return NextResponse.json({ ...settings, rotationConfigs })
  } catch (error) {
    console.error('Failed to fetch user settings:', error)
    return NextResponse.json(
      { error: 'Failed to fetch user settings' },
      { status: 500 }
    )
  }
}

// PUT /api/users/[id]/settings - Upsert user settings
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const body = await request.json()

    // If a masked value is sent back, preserve the existing value
    const existing = await prisma.userSettings.findUnique({
      where: { userId: id },
    })

    const data: Record<string, string> = {}
    const fields = ['githubAccessToken', 'tavilyApiKey', 'shodanApiKey', 'serpApiKey', 'nvdApiKey', 'vulnersApiKey', 'urlscanApiKey', 'censysApiToken', 'censysOrgId', 'fofaApiKey', 'otxApiKey', 'netlasApiKey', 'virusTotalApiKey', 'zoomEyeApiKey', 'criminalIpApiKey', 'quakeApiKey', 'hunterApiKey', 'publicWwwApiKey', 'hunterHowApiKey', 'googleApiKey', 'googleApiCx', 'onypheApiKey', 'driftnetApiKey', 'wpscanApiToken', 'ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'] as const

    for (const field of fields) {
      if (field in body) {
        const val = body[field] as string
        // If the value starts with '••••', keep existing
        if (val.startsWith('••••') && existing) {
          data[field] = existing[field]
        } else {
          data[field] = val
        }
      }
    }

    const settings = await prisma.userSettings.upsert({
      where: { userId: id },
      update: data,
      create: { userId: id, ...data },
    })

    // Push tunnel config to kali-sandbox if any tunnel field actually changed.
    // A field "changed" if: (a) it's in the request body, AND (b) the new value
    // written to `data[f]` differs from the previous DB value in `existing[f]`.
    // Note: masked values (••••) are resolved to existing values above, so
    // unchanged masked fields correctly compare as equal here.
    const tunnelChanged = TUNNEL_FIELDS.some(f => f in body && data[f] !== (existing?.[f] ?? ''))
    if (tunnelChanged) {
      try {
        await fetch('http://kali-sandbox:8015/tunnel/configure', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ngrokAuthtoken: settings.ngrokAuthtoken,
            chiselServerUrl: settings.chiselServerUrl,
            chiselAuth: settings.chiselAuth,
          }),
        })
      } catch (e) {
        console.warn('Failed to push tunnel config to kali-sandbox:', e)
      }
    }

    // Handle rotation configs if provided
    const rotationConfigs: Record<string, { extraKeys?: string[]; extraKeyCount: number; rotateEveryN: number }> = {}
    if (body.rotationConfigs && typeof body.rotationConfigs === 'object') {
      for (const toolName of TOOL_NAMES) {
        const cfg = body.rotationConfigs[toolName]
        if (!cfg) continue

        const extraKeysRaw = (cfg.extraKeys || '') as string
        const rotateEveryN = Math.max(1, parseInt(cfg.rotateEveryN, 10) || 10)

        // If extraKeys is a masked marker, preserve existing
        if (extraKeysRaw.startsWith('••••')) {
          const existing = await prisma.apiKeyRotationConfig.findUnique({
            where: { userId_toolName: { userId: id, toolName } },
          })
          if (existing) {
            const keys = existing.extraKeys.split('\n').filter(k => k.trim())
            rotationConfigs[toolName] = { extraKeyCount: keys.length, rotateEveryN: existing.rotateEveryN }
            // Update only rotateEveryN if it changed
            if (rotateEveryN !== existing.rotateEveryN) {
              await prisma.apiKeyRotationConfig.update({
                where: { userId_toolName: { userId: id, toolName } },
                data: { rotateEveryN },
              })
              rotationConfigs[toolName].rotateEveryN = rotateEveryN
            }
          }
          continue
        }

        const keys = extraKeysRaw.split('\n').filter((k: string) => k.trim())
        if (keys.length === 0) {
          // No extra keys — delete rotation config if exists
          await prisma.apiKeyRotationConfig.deleteMany({
            where: { userId: id, toolName },
          })
        } else {
          await prisma.apiKeyRotationConfig.upsert({
            where: { userId_toolName: { userId: id, toolName } },
            update: { extraKeys: keys.join('\n'), rotateEveryN },
            create: { userId: id, toolName, extraKeys: keys.join('\n'), rotateEveryN },
          })
          rotationConfigs[toolName] = { extraKeyCount: keys.length, rotateEveryN }
        }
      }
    }

    // Also fetch any rotation configs not in the request (to return full state)
    const allRotationRows = await prisma.apiKeyRotationConfig.findMany({
      where: { userId: id },
    })
    for (const row of allRotationRows) {
      if (!rotationConfigs[row.toolName]) {
        const keys = row.extraKeys.split('\n').filter(k => k.trim())
        rotationConfigs[row.toolName] = { extraKeyCount: keys.length, rotateEveryN: row.rotateEveryN }
      }
    }

    // Return masked (chiselServerUrl is not a secret)
    return NextResponse.json({
      ...settings,
      githubAccessToken: maskSecret(settings.githubAccessToken),
      tavilyApiKey: maskSecret(settings.tavilyApiKey),
      shodanApiKey: maskSecret(settings.shodanApiKey),
      serpApiKey: maskSecret(settings.serpApiKey),
      nvdApiKey: maskSecret(settings.nvdApiKey),
      vulnersApiKey: maskSecret(settings.vulnersApiKey),
      urlscanApiKey: maskSecret(settings.urlscanApiKey),
      censysApiToken: maskSecret(settings.censysApiToken),
      censysOrgId: maskSecret(settings.censysOrgId),
      fofaApiKey: maskSecret(settings.fofaApiKey),
      otxApiKey: maskSecret(settings.otxApiKey),
      netlasApiKey: maskSecret(settings.netlasApiKey),
      virusTotalApiKey: maskSecret(settings.virusTotalApiKey),
      zoomEyeApiKey: maskSecret(settings.zoomEyeApiKey),
      criminalIpApiKey: maskSecret(settings.criminalIpApiKey),
      quakeApiKey: maskSecret(settings.quakeApiKey),
      hunterApiKey: maskSecret(settings.hunterApiKey),
      publicWwwApiKey: maskSecret(settings.publicWwwApiKey),
      hunterHowApiKey: maskSecret(settings.hunterHowApiKey),
      googleApiKey: maskSecret(settings.googleApiKey),
      googleApiCx: maskSecret(settings.googleApiCx),
      onypheApiKey: maskSecret(settings.onypheApiKey),
      driftnetApiKey: maskSecret(settings.driftnetApiKey),
      ngrokAuthtoken: maskSecret(settings.ngrokAuthtoken),
      chiselAuth: maskSecret(settings.chiselAuth),
      rotationConfigs,
    })
  } catch (error) {
    console.error('Failed to update user settings:', error)
    return NextResponse.json(
      { error: 'Failed to update user settings' },
      { status: 500 }
    )
  }
}
