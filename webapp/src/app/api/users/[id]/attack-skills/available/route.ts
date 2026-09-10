import { NextRequest, NextResponse } from 'next/server'
import { requireUserAccess } from '@/lib/session'
import prisma from '@/lib/prisma'

interface RouteParams {
  params: Promise<{ id: string }>
}

const BUILT_IN_SKILLS = [
  {
    id: 'cve_exploit',
    name: 'CVE (MSF)',
    description: 'Exploit known CVEs using Metasploit Framework modules against target services',
  },
  {
    id: 'sql_injection',
    name: 'SQL Injection',
    description: 'SQL injection testing with SQLMap, WAF bypass, blind injection, and OOB DNS exfiltration',
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    description: 'Reflected, stored, DOM-based, and blind XSS testing with dalfox, kxss, Playwright, and CSP-bypass guidance',
  },
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    description: 'SSRF detection, internal-network probing, cloud-metadata pivots, protocol smuggling, DNS rebinding, and Redis/FastCGI/Docker RCE chains',
  },
  {
    id: 'rce',
    name: 'Remote Code Execution',
    description: 'RCE / command injection, SSTI across templating engines, deserialization gadget chains (ysoserial), eval / OGNL / SpEL injection, and media-pipeline RCE',
  },
  {
    id: 'path_traversal',
    name: 'Path Traversal / LFI / RFI',
    description: 'Arbitrary file read via path traversal, Local File Inclusion, Remote File Inclusion, PHP wrapper chains (php://filter, data://, expect://), log poisoning, and Zip Slip archive-extraction tests',
  },
  {
    id: 'access_control',
    name: 'Broken Access Control',
    description: 'Authorization bypass: forced browsing, IDOR / BOLA, vertical/horizontal privilege escalation, HTTP verb tampering, 401/403 path-normalization and trust-header bypass, hidden-field / role tampering, JWT attacks, and CORS/GraphQL authz flaws',
  },
  {
    id: 'xxe',
    name: 'XML External Entity',
    description: 'XXE testing against XML parsers: in-band file read, php-filter source read, error-based and out-of-band exfiltration via external/local DTD, SSRF via entities, XInclude, content-type switching, and XXE in SVG/DOCX/SAML uploads',
  },
  {
    id: 'crypto_attack',
    name: 'Cryptographic Attacks',
    description: 'Break trusted crypto: CBC padding oracles and bit-flipping, ECB analysis, stream/nonce reuse (two-time pad), JWT signature attacks (alg:none, HS/RS confusion, weak-secret cracking, kid/jwk/jku), hash length extension, RSA weaknesses, and predictable-token/PRNG reconstruction',
  },
  {
    id: 'brute_force_credential_guess',
    name: 'Credential Testing',
    description: 'Credential policy validation using Hydra against login services',
  },
  {
    id: 'phishing_social_engineering',
    name: 'Social Engineering Simulation',
    description: 'Payload generation, document crafting, and email delivery for authorized awareness testing',
  },
  {
    id: 'denial_of_service',
    name: 'Availability Testing',
    description: 'Assess service resilience using flooding, resource exhaustion, and crash vectors',
  },
]

// GET /api/users/[id]/attack-skills/available - Built-in + user skills for project toggle UI
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params
    const __denied = await requireUserAccess(request, id)
    if (__denied) return __denied

    const userSkills = await prisma.userAttackSkill.findMany({
      where: { userId: id },
      select: { id: true, name: true, description: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
    })

    return NextResponse.json({
      builtIn: BUILT_IN_SKILLS,
      user: userSkills,
    })
  } catch (error) {
    console.error('Failed to fetch available attack skills:', error)
    return NextResponse.json(
      { error: 'Failed to fetch available attack skills' },
      { status: 500 }
    )
  }
}
