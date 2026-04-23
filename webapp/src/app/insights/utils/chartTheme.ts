'use client'

function getCssVar(name: string): string {
  if (typeof window === 'undefined') return ''
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

export function getSeverityPalette() {
  return {
    critical: getCssVar('--color-crimson-500') || '#e53935',
    high: getCssVar('--color-orange-500') || '#f97316',
    medium: getCssVar('--color-amber-500') || '#f59e0b',
    low: getCssVar('--color-blue-500') || '#3b82f6',
    info: getCssVar('--color-gray-400') || '#a1a1aa',
    unknown: getCssVar('--color-gray-500') || '#71717a',
  }
}

export function getNodeTypePalette() {
  return {
    Domain: getCssVar('--node-domain') || '#1e3a8a',
    Subdomain: getCssVar('--node-subdomain') || '#2563eb',
    IP: getCssVar('--node-ip') || '#0d9488',
    Port: getCssVar('--node-port') || '#0e7490',
    Service: getCssVar('--node-service') || '#06b6d4',
    BaseURL: getCssVar('--node-baseurl') || '#6366f1',
    Endpoint: getCssVar('--node-endpoint') || '#8b5cf6',
    Parameter: getCssVar('--node-parameter') || '#c026d3',
    Technology: getCssVar('--node-technology') || '#22c55e',
    Vulnerability: getCssVar('--node-vulnerability') || '#ef4444',
    CVE: getCssVar('--node-cve') || '#dc2626',
    Certificate: getCssVar('--node-certificate') || '#d97706',
    Header: getCssVar('--node-header') || '#71717a',
    DNSRecord: getCssVar('--color-cyan-600') || '#0891b2',
    GithubSecret: getCssVar('--color-amber-500') || '#f59e0b',
    AttackChain: getCssVar('--color-crimson-400') || '#ef5350',
    ChainStep: getCssVar('--color-crimson-300') || '#ef9a9a',
    ChainFinding: getCssVar('--color-orange-500') || '#f97316',
  }
}

export function getChartPalette(): string[] {
  return [
    getCssVar('--color-blue-500') || '#3b82f6',
    getCssVar('--color-crimson-500') || '#e53935',
    getCssVar('--color-green-500') || '#22c55e',
    getCssVar('--color-amber-500') || '#f59e0b',
    getCssVar('--color-purple-500') || '#a855f7',
    getCssVar('--color-cyan-500') || '#06b6d4',
    getCssVar('--color-orange-500') || '#f97316',
    getCssVar('--color-indigo-500') || '#6366f1',
    getCssVar('--color-teal-500') || '#14b8a6',
    getCssVar('--color-pink-500') || '#ec4899',
  ]
}

export function getChartChrome() {
  return {
    axisColor: getCssVar('--text-tertiary') || '#71717a',
    gridColor: getCssVar('--border-subtle') || '#1f1f23',
    tooltipBg: getCssVar('--bg-elevated') || '#27272a',
    tooltipText: getCssVar('--text-primary') || '#fafafa',
    tooltipBorder: getCssVar('--border-default') || '#27272a',
    cursorFill: getCssVar('--bg-tertiary') || '#2a2a2e',
  }
}

export function getTooltipStyle(): Record<string, string | number> {
  const chrome = getChartChrome()
  return {
    backgroundColor: chrome.tooltipBg,
    border: `1px solid ${chrome.tooltipBorder}`,
    borderRadius: '6px',
    color: chrome.tooltipText,
    fontSize: '12px',
    padding: '8px 12px',
  }
}

export function getTooltipItemStyle(): Record<string, string | number> {
  const chrome = getChartChrome()
  return { color: chrome.tooltipText }
}

export function getTooltipLabelStyle(): Record<string, string | number> {
  const chrome = getChartChrome()
  return { color: chrome.tooltipText }
}

export function getCursorStyle(): { fill: string; opacity: number } {
  const chrome = getChartChrome()
  return { fill: chrome.cursorFill, opacity: 0.5 }
}

export function severityColor(severity: string): string {
  const palette = getSeverityPalette()
  const key = severity?.toLowerCase() as keyof ReturnType<typeof getSeverityPalette>
  return palette[key] || palette.unknown
}
