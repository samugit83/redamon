import { Shield, Target, Zap } from 'lucide-react'

/** Recursively extract plain text from React children (for copy-to-clipboard). */
export function extractTextFromChildren(children: any): string {
  if (children == null) return ''
  if (typeof children === 'string') return children
  if (typeof children === 'number') return String(children)
  if (Array.isArray(children)) return children.map(extractTextFromChildren).join('')
  if (children?.props?.children) return extractTextFromChildren(children.props.children)
  return ''
}

/** Format prefixed model names for display (e.g. "openrouter/meta-llama/llama-4" → "llama-4 (OR)") */
export function formatModelDisplay(model: string): string {
  if (model.startsWith('openai_compat/')) {
    const parts = model.slice('openai_compat/'.length).split('/')
    return `${parts[parts.length - 1]} (OA-Compat)`
  }
  if (model.startsWith('openrouter/')) {
    const parts = model.slice('openrouter/'.length).split('/')
    return `${parts[parts.length - 1]} (OR)`
  }
  if (model.startsWith('bedrock/')) {
    const simplified = model.slice('bedrock/'.length).replace(/^[^.]+\./, '').replace(/-\d{8}-v\d+:\d+$/, '')
    return `${simplified} (Bedrock)`
  }
  if (model.startsWith('deepseek/')) {
    return `${model.slice('deepseek/'.length)} (DeepSeek)`
  }
  return model
}

export const PHASE_CONFIG = {
  informational: {
    label: 'Informational',
    icon: Shield,
    color: '#059669',
    bgColor: 'rgba(5, 150, 105, 0.1)',
  },
  exploitation: {
    label: 'Exploitation',
    icon: Target,
    color: 'var(--status-warning)',
    bgColor: 'rgba(245, 158, 11, 0.1)',
  },
  post_exploitation: {
    label: 'Post-Exploitation',
    icon: Zap,
    color: 'var(--status-error)',
    bgColor: 'rgba(239, 68, 68, 0.1)',
  },
}

export const KNOWN_ATTACK_PATH_CONFIG: Record<string, { label: string; shortLabel: string; color: string; bgColor: string }> = {
  cve_exploit: {
    label: 'CVE (MSF)',
    shortLabel: 'CVE/MSF',
    color: 'var(--status-warning)',
    bgColor: 'rgba(245, 158, 11, 0.15)',
  },
  brute_force_credential_guess: {
    label: 'Credential Testing',
    shortLabel: 'CRED',
    color: 'var(--accent-secondary, #8b5cf6)',
    bgColor: 'rgba(139, 92, 246, 0.15)',
  },
  phishing_social_engineering: {
    label: 'Social Engineering Simulation',
    shortLabel: 'SE',
    color: 'var(--accent-tertiary, #ec4899)',
    bgColor: 'rgba(236, 72, 153, 0.15)',
  },
  denial_of_service: {
    label: 'Availability Testing',
    shortLabel: 'AVAIL',
    color: 'var(--status-error, #ef4444)',
    bgColor: 'rgba(239, 68, 68, 0.15)',
  },
  sql_injection: {
    label: 'SQL Injection',
    shortLabel: 'SQLi',
    color: 'var(--accent-info, #06b6d4)',
    bgColor: 'rgba(6, 182, 212, 0.15)',
  },
  xss: {
    label: 'Cross-Site Scripting',
    shortLabel: 'XSS',
    color: 'var(--accent-success, #10b981)',
    bgColor: 'rgba(16, 185, 129, 0.15)',
  },
  ssrf: {
    label: 'Server-Side Request Forgery',
    shortLabel: 'SSRF',
    color: 'var(--accent-orange, #f97316)',
    bgColor: 'rgba(249, 115, 22, 0.15)',
  },
  rce: {
    label: 'Remote Code Execution',
    shortLabel: 'RCE',
    color: 'var(--accent-rose, #f43f5e)',
    bgColor: 'rgba(244, 63, 94, 0.15)',
  },
  path_traversal: {
    label: 'Path Traversal / LFI / RFI',
    shortLabel: 'PATH',
    color: 'var(--accent-teal, #14b8a6)',
    bgColor: 'rgba(20, 184, 166, 0.15)',
  },
  access_control: {
    label: 'Broken Access Control',
    shortLabel: 'AUTHZ',
    color: 'var(--accent-indigo, #6366f1)',
    bgColor: 'rgba(99, 102, 241, 0.15)',
  },
  xxe: {
    label: 'XML External Entity',
    shortLabel: 'XXE',
    color: 'var(--accent-teal, #14b8a6)',
    bgColor: 'rgba(20, 184, 166, 0.15)',
  },
  crypto_attack: {
    label: 'Cryptographic Attacks',
    shortLabel: 'CRYPT',
    color: 'var(--accent-violet, #a855f7)',
    bgColor: 'rgba(168, 85, 247, 0.15)',
  },
}

/** Derive display config for any attack skill type (known, user, or unclassified). */
export function getAttackPathConfig(type: string): { label: string; shortLabel: string; color: string; bgColor: string } {
  if (KNOWN_ATTACK_PATH_CONFIG[type]) {
    return KNOWN_ATTACK_PATH_CONFIG[type]
  }
  if (type.startsWith('user_skill:')) {
    return {
      label: 'User Skill',
      shortLabel: 'SKILL',
      color: 'var(--accent-primary, #3b82f6)',
      bgColor: 'rgba(59, 130, 246, 0.15)',
    }
  }
  const cleanName = type.replace(/-unclassified$/, '').replace(/_/g, ' ')
  const words = cleanName.split(' ').map((w: string) => w.charAt(0).toUpperCase() + w.slice(1))
  const label = words.join(' ')
  const shortLabel = words.length === 1
    ? label.slice(0, 5).toUpperCase()
    : words.map((w: string) => w[0]).join('').toUpperCase()
  return {
    label: `${label} (Unclassified)`,
    shortLabel,
    color: 'var(--text-secondary, #6b7280)',
    bgColor: 'rgba(107, 114, 128, 0.15)',
  }
}
