/**
 * AI Assistant Drawer - WebSocket Version
 *
 * Real-time bidirectional communication with the agent using WebSocket.
 * Features streaming thoughts, tool executions, and beautiful timeline UI.
 * Single scrollable chat with all messages, thinking, and tool executions inline.
 */

'use client'

import React, { useState, useRef, useEffect, useCallback, KeyboardEvent } from 'react'
import { Send, Bot, User, Loader2, AlertCircle, AlertTriangle, Sparkles, Plus, Shield, ShieldAlert, Target, Zap, HelpCircle, WifiOff, Wifi, Square, Play, Download, Wrench, History, ChevronDown, EyeOff, Eye, Copy, Check, Swords, Lightbulb, Settings, X, Radiation } from 'lucide-react'
import { StealthIcon } from '@/components/icons/StealthIcon'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'
import styles from './AIAssistantDrawer.module.css'
import { type ModelOption, formatContextLength, getDisplayName } from './modelUtils'
import { useAgentWebSocket } from '@/hooks/useAgentWebSocket'
import {
  MessageType,
  ConnectionStatus,
  type ServerMessage,
  type ApprovalRequestPayload,
  type QuestionRequestPayload,
  type ToolConfirmationRequestPayload,
  type TodoItem
} from '@/lib/websocket-types'
import { AgentTimeline } from './AgentTimeline'
import { FileDownloadCard } from './FileDownloadCard'
import { TodoListWidget } from './TodoListWidget'
import { ConversationHistory } from './ConversationHistory'
import { useConversations } from '@/hooks/useConversations'
import { useChatPersistence } from '@/hooks/useChatPersistence'
import type { Conversation } from '@/hooks/useConversations'
import { Tooltip } from '@/components/ui/Tooltip/Tooltip'
import { AgentBehaviourSection } from '@/components/projects/ProjectForm/sections/AgentBehaviourSection'
import { AttackSkillsSection } from '@/components/projects/ProjectForm/sections/AttackSkillsSection'
import { ToolMatrixSection } from '@/components/projects/ProjectForm/sections/ToolMatrixSection'
import type { Project } from '@prisma/client'
import type { ThinkingItem, ToolExecutionItem, PlanWaveItem, DeepThinkItem } from './AgentTimeline'

type Phase = 'informational' | 'exploitation' | 'post_exploitation'

/** Recursively extract plain text from React children (for copy-to-clipboard). */
function extractTextFromChildren(children: any): string {
  if (children == null) return ''
  if (typeof children === 'string') return children
  if (typeof children === 'number') return String(children)
  if (Array.isArray(children)) return children.map(extractTextFromChildren).join('')
  if (children?.props?.children) return extractTextFromChildren(children.props.children)
  return ''
}

interface Message {
  type: 'message'
  id: string
  role: 'user' | 'assistant'
  content: string
  toolUsed?: string | null
  toolOutput?: string | null
  error?: string | null
  phase?: Phase
  timestamp: Date
  isGuidance?: boolean
  isReport?: boolean
  responseTier?: 'conversational' | 'summary' | 'full_report'
}

interface FileDownloadItem {
  type: 'file_download'
  id: string
  timestamp: Date
  filepath: string
  filename: string
  description: string
  source: string
}

type ChatItem = Message | ThinkingItem | ToolExecutionItem | PlanWaveItem | FileDownloadItem | DeepThinkItem

/** Format prefixed model names for display (e.g. "openrouter/meta-llama/llama-4" → "llama-4 (OR)") */
function formatModelDisplay(model: string): string {
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
  return model
}

interface AIAssistantDrawerProps {
  isOpen: boolean
  onClose: () => void
  userId: string
  projectId: string
  sessionId: string
  onResetSession?: () => string
  onSwitchSession?: (sessionId: string) => void
  modelName?: string
  onModelChange?: (modelId: string) => void
  toolPhaseMap?: Record<string, string[]>
  stealthMode?: boolean
  onToggleStealth?: (newValue: boolean) => void
  deepThinkEnabled?: boolean
  onToggleDeepThink?: (newValue: boolean) => void
  onRefetchGraph?: () => void
  isOtherChainsHidden?: boolean
  onToggleOtherChains?: () => void
  hasOtherChains?: boolean
  requireToolConfirmation?: boolean
}

const PHASE_CONFIG = {
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

const KNOWN_ATTACK_PATH_CONFIG: Record<string, { label: string; shortLabel: string; color: string; bgColor: string }> = {
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
}

/** Derive display config for any attack skill type (known, user, or unclassified). */
function getAttackPathConfig(type: string): { label: string; shortLabel: string; color: string; bgColor: string } {
  if (KNOWN_ATTACK_PATH_CONFIG[type]) {
    return KNOWN_ATTACK_PATH_CONFIG[type]
  }
  // User skill: "user_skill:<id>" — derive from the skill name embedded in the type
  if (type.startsWith('user_skill:')) {
    return {
      label: 'User Skill',
      shortLabel: 'SKILL',
      color: 'var(--accent-primary, #3b82f6)',
      bgColor: 'rgba(59, 130, 246, 0.15)',
    }
  }
  // Unclassified: derive label from the type string
  // e.g. "sql_injection-unclassified" -> label "Sql Injection", shortLabel "SI"
  const cleanName = type.replace(/-unclassified$/, '').replace(/_/g, ' ')
  const words = cleanName.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1))
  const label = words.join(' ')
  const shortLabel = words.length === 1
    ? label.slice(0, 5).toUpperCase()
    : words.map(w => w[0]).join('').toUpperCase()
  return {
    label: `${label} (Unclassified)`,
    shortLabel,
    color: 'var(--text-secondary, #6b7280)',
    bgColor: 'rgba(107, 114, 128, 0.15)',
  }
}

// =============================================================================
// SUGGESTION TYPE DEFINITIONS
// =============================================================================

interface SESuggestion { label: string; prompt: string }
interface SESection { osLabel?: string; suggestions: SESuggestion[] }
interface SESubGroup { id: string; title: string; items: SESection[] }

// =============================================================================
// INFORMATIONAL SUGGESTION DATA
// =============================================================================

const INFORMATIONAL_GROUPS: SESubGroup[] = [
  {
    id: 'attack_surface',
    title: 'Attack Surface Overview',
    items: [
      {
        suggestions: [
          { label: 'Full attack surface map', prompt: 'Query the graph to list all domains, subdomains, IP addresses, open ports, and running services. Organize results by domain hierarchy and highlight internet-facing assets.' },
          { label: 'Subdomain enumeration summary', prompt: 'Query the graph for all subdomains and their DNS records (A, AAAA, CNAME, MX, NS, TXT). Identify wildcard DNS, dangling CNAMEs, and potential subdomain takeover candidates.' },
          { label: 'External IP and port inventory', prompt: 'Query the graph for all IP addresses and their open ports with service/version detection. Group by IP and flag uncommon or high-risk ports (e.g., 445, 3389, 6379, 27017).' },
          { label: 'ASN and network mapping', prompt: 'Query the graph for all ASN information, IP ranges, and reverse DNS records. Map out which networks and hosting providers are in scope.' },
          { label: 'CDN and WAF detection summary', prompt: 'Query the graph for all CDN/WAF detections. Identify which assets are behind Cloudflare, Akamai, AWS CloudFront, etc., and which are directly exposed.' },
        ],
      },
    ],
  },
  {
    id: 'vuln_analysis',
    title: 'Vulnerability Analysis',
    items: [
      {
        suggestions: [
          { label: 'Critical and high severity CVEs', prompt: 'Query the graph for all vulnerabilities with CVSS >= 7.0, sorted by severity. For each, show the CVE ID, CVSS score, affected service/technology, and the host where it was found.' },
          { label: 'CISA KEV matches', prompt: 'Query the graph for all discovered CVEs, then use web_search to check which ones appear in the CISA Known Exploited Vulnerabilities catalog. List matches with their required remediation dates.' },
          { label: 'Exploitable CVEs with Metasploit modules', prompt: 'Query the graph for all CVEs found, then use web_search to identify which ones have known Metasploit exploit modules. List the module path, target service, and affected host.' },
          { label: 'Prioritized risk summary', prompt: 'Query the graph for all vulnerabilities, technologies, and exposed services. Create a prioritized risk assessment ranked by: 1) CVSS score, 2) exploit availability, 3) exposure level. Include a top-10 most critical findings table.' },
          { label: 'CVEs with public exploit code', prompt: 'Query the graph for all CVEs, then use web_search to find which have public exploit code on GitHub or ExploitDB. List the CVE, affected asset, and exploit URL for each.' },
        ],
      },
    ],
  },
  {
    id: 'tech_intel',
    title: 'Technology & Version Intelligence',
    items: [
      {
        suggestions: [
          { label: 'Outdated software inventory', prompt: 'Query the graph for all detected technologies with version numbers and CPE identifiers. Use web_search to check each for known CVEs and end-of-life status. Flag any outdated or unsupported versions.' },
          { label: 'Web server and framework versions', prompt: 'Query the graph for all web technologies (Apache, Nginx, IIS, Tomcat, WordPress, Drupal, etc.) with their versions. Identify which versions have known critical vulnerabilities.' },
          { label: 'Database and cache services', prompt: 'Query the graph for all database and cache services (MySQL, PostgreSQL, Redis, MongoDB, Memcached, Elasticsearch). List their versions, exposed ports, and whether authentication is required.' },
          { label: 'CMS and application detection', prompt: 'Query the graph for CMS platforms (WordPress, Joomla, Drupal, etc.) and web frameworks. Use web_search to find known vulnerabilities for each detected version.' },
          { label: 'Technology stack by host', prompt: 'Query the graph to build a complete technology stack (OS, web server, language, framework, database, CDN) for each host. Identify mismatches and unusual configurations.' },
        ],
      },
    ],
  },
  {
    id: 'web_recon',
    title: 'Web Application Recon',
    items: [
      {
        suggestions: [
          { label: 'Discovered endpoints and parameters', prompt: 'Query the graph for all web endpoints, their HTTP methods, parameters, and response codes. Highlight endpoints with user-input parameters that could be injection targets.' },
          { label: 'Admin panels and login pages', prompt: 'Query the graph for endpoints matching common admin/login paths (/admin, /login, /wp-admin, /manager, /console, /dashboard). Use execute_curl to verify which are accessible and identify the technology behind them.' },
          { label: 'API endpoint discovery', prompt: 'Query the graph for all endpoints that look like API routes (/api/, /v1/, /graphql, /rest/). Use execute_curl to probe a sample of them for authentication requirements, response formats, and exposed data.' },
          { label: 'Sensitive file and directory exposure', prompt: 'Use execute_curl to probe for common sensitive paths: /.git/config, /.env, /robots.txt, /sitemap.xml, /.well-known/, /backup/, /debug/, /phpinfo.php on all discovered web hosts.' },
          { label: 'Form and input analysis', prompt: 'Query the graph for all discovered parameters and forms. Categorize them by input type (search, login, upload, comment, API) and flag candidates for SQLi, XSS, SSRF, and file upload testing.' },
        ],
      },
    ],
  },
  {
    id: 'network_recon',
    title: 'Network Reconnaissance',
    items: [
      {
        suggestions: [
          { label: 'Deep Nmap scan on key targets', prompt: 'Identify the top 5 most interesting hosts from the graph (those with most services or vulnerabilities), then run execute_nmap with -sV -sC -O for detailed service detection, default script scanning, and OS fingerprinting.' },
          { label: 'UDP service discovery', prompt: 'Run execute_nmap with -sU --top-ports 50 against the primary targets to discover UDP services like DNS (53), SNMP (161), TFTP (69), NTP (123), and IPMI (623).' },
          { label: 'Quick port scan on new targets', prompt: 'Use execute_naabu to perform a fast SYN scan on all in-scope IPs, then compare results with the graph data to identify any newly discovered open ports.' },
          { label: 'SMB and NetBIOS enumeration', prompt: 'Run execute_nmap with --script smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode against any hosts with port 445/139 open. Report accessible shares and security configuration.' },
          { label: 'Nmap NSE vulnerability scripts', prompt: 'Run execute_nmap with --script vuln against the top targets to discover additional vulnerabilities not found by Nuclei. Compare with existing graph data to identify new findings.' },
        ],
      },
    ],
  },
  {
    id: 'cred_exposure',
    title: 'Credential & Secret Exposure',
    items: [
      {
        suggestions: [
          { label: 'GitHub leaked secrets inventory', prompt: 'Query the graph for all GitHub secrets found (API keys, tokens, passwords, private keys). Categorize by type, affected service, and assess which ones could still be valid.' },
          { label: 'Validate leaked credentials', prompt: 'Query the graph for all discovered GitHub secrets and credentials. Use execute_curl or execute_code to test which API keys and tokens are still active without triggering rate limits.' },
          { label: 'Brute-forceable service inventory', prompt: 'Query the graph for all services that expose authentication (SSH, FTP, RDP, SMB, MySQL, PostgreSQL, HTTP Basic/Form Auth, Tomcat Manager). List host, port, and service type for each.' },
          { label: 'Default credential lookup', prompt: 'Query the graph for all discovered services and technologies. Use web_search to look up default credentials for each vendor/product, then compile a list of default username/password pairs to test.' },
        ],
      },
    ],
  },
  {
    id: 'tls_security',
    title: 'TLS & Security Configuration',
    items: [
      {
        suggestions: [
          { label: 'TLS certificate audit', prompt: 'Query the graph for all TLS certificates. Report expired or soon-to-expire certs, self-signed certs, wildcard certs, weak key sizes, and JARM fingerprint anomalies.' },
          { label: 'HTTP security headers analysis', prompt: 'Query the graph for all security headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy). Flag missing or misconfigured headers per host.' },
          { label: 'SSL/TLS weakness scan', prompt: 'Run execute_nmap with --script ssl-enum-ciphers on all HTTPS hosts. Identify weak ciphers (RC4, DES, export), deprecated protocols (SSLv3, TLS 1.0/1.1), and missing features like PFS.' },
          { label: 'CORS and cookie security audit', prompt: 'Use execute_curl to check CORS headers (Access-Control-Allow-Origin) and cookie attributes (Secure, HttpOnly, SameSite) on all discovered web applications. Flag overly permissive configurations.' },
        ],
      },
    ],
  },
  {
    id: 'osint_research',
    title: 'OSINT & Research',
    items: [
      {
        suggestions: [
          { label: 'Research top CVEs in depth', prompt: 'Query the graph for the 5 highest CVSS vulnerabilities. For each, use web_search to find: exploit PoCs, Metasploit modules, affected versions, patch status, and real-world exploitation reports.' },
          { label: 'Search for exploit PoCs', prompt: 'Query the graph for all CVEs found, then use web_search to search GitHub and ExploitDB for proof-of-concept exploit code. Summarize available PoCs with links and assess reliability.' },
          { label: 'Searchsploit local lookup', prompt: 'Query the graph for all technologies and versions, then use kali_shell to run searchsploit against each technology/version combination. Report all matching exploits from ExploitDB.' },
          { label: 'CVE exploit chain analysis', prompt: 'Query the graph for all vulnerabilities on each host. Use web_search to research whether any combination of findings could be chained into a multi-step attack (e.g., info disclosure + auth bypass + RCE).' },
        ],
      },
    ],
  },
  {
    id: 'shodan_dork',
    title: 'Shodan & Google Dork OSINT',
    items: [
      {
        osLabel: 'Shodan',
        suggestions: [
          { label: 'Full Shodan host profile', prompt: 'Use shodan with action="host" on all in-scope IP addresses to get detailed info: open ports, service banners, SSL certificates, known CVEs, OS detection, and organization. Compare findings with the graph data to identify gaps.' },
          { label: 'Search for exposed services in target org', prompt: 'Use shodan with action="search" and query "org:<target-organization>" to discover all internet-facing devices belonging to the target. Identify shadow IT, forgotten servers, and services not found by active scanning.' },
          { label: 'Find vulnerable hosts (has_vuln filter)', prompt: 'Use shodan with action="search" and query "net:<target-range> has_vuln:true" to find hosts with known CVEs. Cross-reference with graph data to prioritize exploitation targets.' },
          { label: 'Subdomain discovery via Shodan DNS', prompt: 'Use shodan with action="dns_domain" on the target domain to enumerate subdomains and DNS records. Compare with graph data to find subdomains missed by other recon tools.' },
          { label: 'Reverse DNS on target IPs', prompt: 'Use shodan with action="dns_reverse" on all discovered IP addresses to find hostnames and identify shared hosting or virtual hosts that could expand the attack surface.' },
          { label: 'Count exposed services before deep scan', prompt: 'Use shodan with action="count" and queries like "net:<range> port:22", "net:<range> port:3389", "net:<range> port:445" to estimate the attack surface size without consuming search credits.' },
        ],
      },
      {
        osLabel: 'Google Dork',
        suggestions: [
          { label: 'Find exposed sensitive files', prompt: 'Use google_dork with query "site:<target-domain> filetype:sql OR filetype:env OR filetype:log OR filetype:bak OR filetype:conf" to discover publicly indexed sensitive files like database dumps, environment configs, and logs.' },
          { label: 'Discover admin panels and login pages', prompt: 'Use google_dork with query "site:<target-domain> inurl:admin OR inurl:login OR inurl:dashboard OR inurl:console OR intitle:\"admin panel\"" to find exposed management interfaces indexed by Google.' },
          { label: 'Find directory listings', prompt: 'Use google_dork with query "site:<target-domain> intitle:\"index of /\" OR intitle:\"directory listing\"" to discover open directory listings that may expose sensitive files, source code, or backups.' },
          { label: 'Discover exposed API docs and endpoints', prompt: 'Use google_dork with query "site:<target-domain> inurl:swagger OR inurl:api-docs OR inurl:graphql OR filetype:json \"openapi\"" to find publicly indexed API documentation and endpoint schemas.' },
          { label: 'Find configuration and credential leaks', prompt: 'Use google_dork with query "site:<target-domain> filetype:xml OR filetype:yaml OR filetype:ini OR filetype:cfg \"password\" OR \"secret\" OR \"api_key\"" to discover leaked configuration files containing credentials.' },
          { label: 'Discover error pages with stack traces', prompt: 'Use google_dork with query "site:<target-domain> \"stack trace\" OR \"fatal error\" OR \"exception\" OR \"debug\" OR \"traceback\"" to find error pages that leak internal paths, framework versions, and database details.' },
          { label: 'Find exposed Git and SVN repositories', prompt: 'Use google_dork with query "site:<target-domain> inurl:.git OR inurl:.svn OR inurl:.hg OR intitle:\"index of /.git\"" to discover exposed version control repositories that may contain source code and secrets.' },
          { label: 'Comprehensive dork sweep', prompt: 'Run a comprehensive Google dork sweep against the target domain: search for exposed files (sql, env, log, bak), admin panels, directory listings, error pages, API docs, and git repos. Compile all findings into a prioritized report.' },
        ],
      },
    ],
  },
  {
    id: 'active_verify',
    title: 'Active Verification',
    items: [
      {
        suggestions: [
          { label: 'Nuclei verification of top CVEs', prompt: 'Query the graph for the 10 highest severity vulnerabilities, then use execute_nuclei to re-verify each one with targeted template IDs. Confirm which are true positives and provide proof.' },
          { label: 'Probe for exposed admin interfaces', prompt: 'Use execute_curl to probe all discovered web hosts for common admin paths (/admin, /manager/html, /wp-admin, /phpmyadmin, /console). Record response codes, redirects, and page content.' },
          { label: 'Version fingerprinting via curl', prompt: 'Use execute_curl to collect detailed HTTP response headers and body content from all web servers. Extract exact version strings from Server headers, X-Powered-By, generator meta tags, and error pages.' },
          { label: 'Nuclei full template scan', prompt: 'Run execute_nuclei with a broad template set (cves, misconfiguration, exposure, default-logins) against the top 3 targets. Report all findings categorized by severity.' },
          { label: 'Test for path traversal', prompt: 'Use execute_curl to test path traversal payloads (../../../etc/passwd, ..\\..\\..\\windows\\win.ini) against all discovered web endpoints that accept file path parameters. Report any successful reads.' },
        ],
      },
    ],
  },
]

// =============================================================================
// EXPLOITATION SUGGESTION DATA
// =============================================================================

const EXPLOITATION_GROUPS: SESubGroup[] = [
  {
    id: 'cve_exploit',
    title: 'CVE (MSF)',
    items: [
      {
        suggestions: [
          { label: 'Exploit the most critical CVE', prompt: 'Query the graph for the highest CVSS vulnerability with a known Metasploit module. Set up and launch the exploit using metasploit_console to gain a remote shell on the target.' },
          { label: 'Exploit a critical CVE and open a session', prompt: 'Find the most critical CVE on the target, exploit it with Metasploit, and open a Meterpreter shell session. Confirm the session is stable and report the access level obtained.' },
          { label: 'Exploit a known RCE vulnerability', prompt: 'Query the graph for Remote Code Execution (RCE) CVEs, select the most promising one, search for its Metasploit module, configure it, and exploit the target to gain a shell.' },
          { label: 'Chain vulnerabilities for RCE', prompt: 'Analyze all discovered vulnerabilities on the target. Chain multiple lower-severity findings together (e.g., info disclosure + auth bypass + injection) to achieve remote code execution.' },
          { label: 'Exploit a web server CVE', prompt: 'Query the graph for CVEs affecting web servers (Apache, Nginx, IIS, Tomcat). Find the Metasploit module, configure it for the target, and exploit it to gain a shell.' },
        ],
      },
    ],
  },
  {
    id: 'brute_force',
    title: 'Credential Testing',
    items: [
      {
        suggestions: [
          { label: 'Test SSH credentials and explore the server', prompt: 'Use execute_hydra to test SSH credentials on the target using common username/password lists. Once access is gained, enumerate sensitive files, users, and configuration.' },
          { label: 'Test default credentials on all services', prompt: 'Query the graph for all services with authentication (Tomcat, Jenkins, phpMyAdmin, databases, FTP, SSH). Use execute_hydra and execute_curl to test default and common credentials on each.' },
          { label: 'Leverage GitHub secrets to access the server', prompt: 'Query the graph for GitHub secrets (credentials, API keys, tokens). Use any discovered credentials to attempt SSH, FTP, database, or web admin access. Report what access was gained.' },
          { label: 'Test web login form credentials', prompt: 'Query the graph for login form endpoints. Use execute_hydra with http-post-form to test credentials using common wordlists. Report any successful logins.' },
          { label: 'Database credential testing', prompt: 'Query the graph for exposed database ports (MySQL 3306, PostgreSQL 5432, MSSQL 1433, MongoDB 27017). Use execute_hydra to test common credentials, then connect and enumerate databases.' },
          { label: 'FTP anonymous and credential testing', prompt: 'Query the graph for all FTP services. Test for anonymous access first, then use execute_hydra to test common credentials. Enumerate any accessible files and directories.' },
        ],
      },
    ],
  },
  {
    id: 'web_attacks',
    title: 'Web Application Attacks',
    items: [
      {
        suggestions: [
          { label: 'Exploit SQL injection on web forms', prompt: 'Query the graph for web endpoints with input parameters. Use kali_shell with sqlmap to test for SQL injection vulnerabilities, then extract database schema, tables, and sensitive data.' },
          { label: 'Upload a web shell via file upload', prompt: 'Query the graph for file upload endpoints. Craft and upload a PHP/JSP/ASPX web shell using execute_curl with various bypass techniques (extension tricks, content-type manipulation). Confirm remote command execution.' },
          { label: 'Test for command injection', prompt: 'Query the graph for endpoints with parameters that could interact with OS commands. Use execute_curl to test command injection payloads (;id, |whoami, $(id), `id`). Escalate any confirmed injection to a reverse shell.' },
          { label: 'Exploit SSRF vulnerabilities', prompt: 'Query the graph for endpoints that accept URL parameters. Use execute_curl to test SSRF payloads targeting internal services (http://127.0.0.1, http://169.254.169.254 for cloud metadata, internal admin panels).' },
          { label: 'Test for directory traversal and LFI', prompt: 'Query the graph for endpoints with file path parameters. Use execute_curl to test directory traversal payloads to read /etc/passwd, /etc/shadow, application config files, and attempt LFI to RCE via log poisoning.' },
          { label: 'Exploit XSS for session hijacking', prompt: 'Query the graph for endpoints with reflected or stored XSS potential. Craft XSS payloads using execute_curl to test for JavaScript execution and demonstrate session cookie theft.' },
        ],
      },
    ],
  },
  {
    id: 'dos',
    title: 'Availability Testing',
    items: [
      {
        suggestions: [
          { label: 'Test service availability (auto-select best vector)', prompt: 'Perform an availability test against the target. Analyze the discovered services and vulnerabilities from the graph, select the most effective test vector (known CVE, HTTP application, Layer 4 flood, or application logic), execute the test, and verify the service impact.' },
          { label: 'Test web server resilience', prompt: 'Test the web server resilience on the target. Choose the best approach based on the server type and version — try slowloris, slow POST, known CVE modules, or crafted crash requests. Verify the service impact.' },
          { label: 'Stress test target service availability', prompt: 'Test the resilience of the target service to availability disruption. Try multiple test vectors (up to the configured max attempts), document which ones succeed and which fail, and report whether the service is resilient or vulnerable.' },
        ],
      },
      {
        osLabel: 'Known CVE Availability Tests',
        suggestions: [
          { label: 'Test RDP resilience via MS12-020', prompt: 'Use Metasploit auxiliary/dos/windows/rdp/ms12_020_maxchannelids to test the RDP service on the target. First verify vulnerability with nmap --script rdp-ms12-020, then execute the module and verify the service impact.' },
          { label: 'Test IIS via MS15-034 (HTTP.sys)', prompt: 'Use Metasploit auxiliary/dos/http/ms15_034_ulonglongadd to test IIS on the target via the HTTP.sys Range header vulnerability. Verify the web server availability impact.' },
          { label: 'Test Apache via Range header', prompt: 'Use Metasploit auxiliary/dos/http/apache_range_dos to test an Apache web server (< 2.2.21) by sending overlapping Range header requests. Verify the service impact.' },
          { label: 'Search for availability test modules for target service', prompt: 'Search Metasploit for DoS modules matching the target service (search auxiliary/dos/<service>). Select the most applicable module, configure it, and execute to test the service.' },
        ],
      },
      {
        osLabel: 'HTTP Application Testing',
        suggestions: [
          { label: 'Slowloris (incomplete headers)', prompt: 'Use slowhttptest in Slowloris mode (-H) to test the web server connection pool by sending incomplete HTTP headers. Keep connections open and verify the web server availability impact.' },
          { label: 'Slow POST body (R.U.D.Y.)', prompt: 'Use slowhttptest in Slow POST mode (-B) to send HTTP POST requests with an extremely slow body transmission rate. Target form endpoints and verify the web server availability impact.' },
          { label: 'Range header test', prompt: 'Use slowhttptest in Range mode (-R) to send requests with multiple overlapping Range header values, testing server memory handling. Verify the Apache web server availability impact.' },
          { label: 'Hash collision test (PHP/Java/Python)', prompt: 'Use Metasploit auxiliary/dos/http/hashcollision_dos to send crafted POST parameters that trigger hash collision in the web framework, consuming CPU. Verify the application availability impact.' },
        ],
      },
      {
        osLabel: 'Layer 4 Flooding',
        suggestions: [
          { label: 'TCP SYN flood test', prompt: 'Use hping3 with SYN flood mode (hping3 -S --flood) against the target port to test its connection state table resilience. Run for the configured duration and verify the service availability impact.' },
          { label: 'UDP flood test', prompt: 'Use hping3 in UDP flood mode (hping3 --udp --flood) against the target UDP service (DNS, SNMP). Verify the service availability impact.' },
          { label: 'ICMP flood test', prompt: 'Use hping3 in ICMP flood mode (hping3 --icmp --flood) to test the target network link saturation resilience. Verify the availability impact on services.' },
        ],
      },
      {
        osLabel: 'Application Logic DoS',
        suggestions: [
          { label: 'ReDoS (regex backtracking test)', prompt: 'Identify an endpoint that processes regex input. Use execute_code (Python) to craft a regex-bomb payload that causes catastrophic backtracking, then send it to the endpoint and verify it hangs or times out.' },
          { label: 'XML entity expansion test', prompt: 'Use execute_code (Python) to craft an XML billion laughs payload (nested entity expansion) and POST it to an endpoint that parses XML. Verify the server availability impact.' },
          { label: 'GraphQL depth/complexity test', prompt: 'Use execute_code (Python) to craft a deeply nested GraphQL query that exceeds the server query depth limit. Send it to the GraphQL endpoint and verify it causes excessive resource consumption.' },
          { label: 'Resource exhaustion via API test', prompt: 'Use execute_code (Python) to send rapid concurrent requests to an expensive API endpoint (large file generation, complex queries, heavy computation). Verify the service availability impact.' },
        ],
      },
      {
        osLabel: 'Single-Request Crash',
        suggestions: [
          { label: 'Range header overflow test', prompt: 'Use execute_curl to send a request with an oversized Range header value (bytes=0-18446744073709551615) to test for an integer overflow vulnerability in the web server. Verify the service availability impact.' },
          { label: 'Malformed Content-Length test', prompt: 'Use execute_curl to send a POST request with an absurdly large Content-Length header to test the web server memory allocation handling. Verify the service availability impact.' },
          { label: 'Header size limit test', prompt: 'Use execute_curl to send a request with an extremely large custom header (10KB+) to test the web server header buffer handling. Verify the service availability impact.' },
        ],
      },
    ],
  },
  {
    id: 'manual_exploit',
    title: 'Manual Exploitation',
    items: [
      {
        suggestions: [
          { label: 'Nuclei-verified exploit execution', prompt: 'Query the graph for Nuclei-confirmed vulnerabilities. For the most critical one, use execute_curl or execute_code to manually craft and send the exploit payload. Confirm exploitation and demonstrate impact.' },
          { label: 'Custom exploit script from PoC', prompt: 'Query the graph for the most critical CVE, then use web_search to find a public exploit PoC. Adapt it using execute_code (Python) to work against the target, execute it, and confirm exploitation.' },
          { label: 'Reverse shell via curl exploitation', prompt: 'Identify a confirmed RCE vulnerability on a web target. Use execute_curl to manually exploit it and inject a reverse shell payload (bash, python, or netcat). Set up the listener in kali_shell.' },
          { label: 'Exploit misconfigured service', prompt: 'Query the graph for services with known misconfigurations (unauthenticated Redis, open MongoDB, exposed Docker API, Kubernetes dashboard). Use kali_shell tools to exploit the misconfiguration and gain access.' },
          { label: 'Exploit exposed management interface', prompt: 'Query the graph for management interfaces (Tomcat Manager, Jenkins, JMX, phpMyAdmin). Attempt access using discovered or default credentials, then leverage the interface to deploy a payload or execute commands.' },
        ],
      },
    ],
  },
]

// =============================================================================
// POST-EXPLOITATION SUGGESTION DATA
// =============================================================================

const POST_EXPLOITATION_GROUPS: SESubGroup[] = [
  {
    id: 'cred_harvest',
    title: 'Credential Harvesting & Cracking',
    items: [
      {
        suggestions: [
          { label: 'Hunt for secrets and credentials', prompt: 'Search the compromised server for passwords, API keys, tokens, and secrets in config files, environment variables, .env files, .bash_history, application configs, and web server configs. Report all findings.' },
          { label: 'Dump and crack password hashes', prompt: 'Extract password hashes from /etc/shadow (Linux) or SAM database (Windows via Meterpreter hashdump). Use kali_shell with john or hashcat to crack the hashes with common wordlists.' },
          { label: 'Database credential extraction', prompt: 'Search for database connection strings and credentials in web application config files (wp-config.php, .env, settings.py, application.properties, web.config). Connect to found databases and dump user/credential tables.' },
          { label: 'Extract private keys and certificates', prompt: 'Search the filesystem for SSH private keys (~/.ssh/id_rsa, /etc/ssh/), TLS private keys, PFX/P12 files, and PGP keys. Test each key for passwordless access to other systems.' },
          { label: 'Browser and application credential dump', prompt: 'Search for saved credentials in browser profiles, password managers, FTP client configs (FileZilla), email client configs, and application credential stores. Extract and organize all found credentials.' },
        ],
      },
    ],
  },
  {
    id: 'privesc',
    title: 'Privilege Escalation',
    items: [
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'SUID/SGID binary exploitation', prompt: 'Run find / -perm -4000 2>/dev/null to list all SUID binaries. Cross-reference with GTFOBins using web_search to find exploitable binaries. Attempt privilege escalation via the most promising vector.' },
          { label: 'Sudo misconfiguration exploitation', prompt: 'Run sudo -l to check sudo permissions. Identify any NOPASSWD entries, wildcard abuse, or LD_PRELOAD/LD_LIBRARY_PATH exploitation paths. Use GTFOBins to escalate to root.' },
          { label: 'Writable cron job exploitation', prompt: 'Enumerate all cron jobs (crontab -l, /etc/crontab, /etc/cron.d/*, /var/spool/cron/). Find any writable scripts executed by root. Inject a reverse shell or add a backdoor user to escalate privileges.' },
          { label: 'Linux kernel exploit check', prompt: 'Collect kernel version (uname -a), distribution info, and installed packages. Use web_search to find applicable kernel exploits (DirtyPipe, DirtyCow, etc.). Compile and run the most suitable exploit via execute_code.' },
          { label: 'Capability-based escalation', prompt: 'Run getcap -r / 2>/dev/null to find binaries with special capabilities. Check for cap_setuid, cap_dac_read_search, cap_net_raw, or cap_sys_admin. Exploit the capabilities to escalate to root.' },
        ],
      },
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Windows service misconfiguration', prompt: 'Use Meterpreter getsystem and check for unquoted service paths, writable service binaries, and modifiable service configurations. Exploit the most promising vector to escalate to SYSTEM.' },
          { label: 'Token impersonation (Potato attacks)', prompt: 'Check current privileges with whoami /priv. If SeImpersonatePrivilege is enabled, use a Potato attack (JuicyPotato, PrintSpoofer, GodPotato) via metasploit_console to escalate to SYSTEM.' },
          { label: 'Credential harvesting with Mimikatz', prompt: 'Load Mimikatz via Meterpreter (load kiwi) and run creds_all to dump plaintext passwords, NTLM hashes, and Kerberos tickets from memory. Report all harvested credentials.' },
        ],
      },
    ],
  },
  {
    id: 'lateral_movement',
    title: 'Lateral Movement',
    items: [
      {
        suggestions: [
          { label: 'Map internal network and pivot', prompt: 'Enumerate network interfaces (ifconfig/ipconfig), ARP tables (arp -a), routing tables, and /etc/hosts. Discover internal hosts and subnets, then set up Meterpreter autoroute to pivot into the internal network.' },
          { label: 'Harvest SSH keys and move laterally', prompt: 'Collect all SSH keys (~/.ssh/), known_hosts, authorized_keys, and bash_history SSH commands. Attempt to SSH into discovered internal hosts using the harvested keys and any cracked credentials.' },
          { label: 'Port forwarding for internal access', prompt: 'Set up Meterpreter port forwarding (portfwd add) to access internal services that are not directly reachable. Forward interesting internal ports (web admin panels, databases, RDP) to the attacker machine.' },
          { label: 'Internal service enumeration', prompt: 'From the compromised host, use kali_shell to scan the internal network (nmap or naabu) for additional hosts and services. Identify high-value targets like domain controllers, databases, file servers, and CI/CD systems.' },
          { label: 'SMB/WinRM lateral movement', prompt: 'Use discovered credentials to attempt lateral movement via SMB (psexec, smbexec) or WinRM to other Windows hosts. Use metasploit_console modules like exploit/windows/smb/psexec.' },
        ],
      },
    ],
  },
  {
    id: 'data_exfil',
    title: 'Data Access Verification',
    items: [
      {
        suggestions: [
          { label: 'Verify database access and enumerate data', prompt: 'Find database credentials in application config files. Connect to the database (MySQL, PostgreSQL, MongoDB) and enumerate all databases, tables, and verify access to sensitive data (users, credentials, PII, financial records). Document the scope of accessible data.' },
          { label: 'Source code and configuration exposure assessment', prompt: 'Search for application source code repositories (.git directories), deployment scripts, CI/CD configs, Dockerfiles, and Kubernetes manifests. Analyze for hardcoded secrets and document the exposure.' },
          { label: 'Backup file discovery', prompt: 'Search for backup files: *.bak, *.sql, *.dump, *.tar.gz, *.zip in common backup locations (/backup, /var/backups, /tmp, /opt, home directories). Assess and document what sensitive data is accessible via unprotected backups.' },
          { label: 'Email and document exposure assessment', prompt: 'Search for emails (Maildir, mbox), documents (*.pdf, *.docx, *.xlsx), and spreadsheets containing sensitive information. Look in home directories, /var/mail, and application data directories. Document the scope of accessible data.' },
          { label: 'Cloud credential exposure assessment', prompt: 'Search for cloud provider credentials: AWS (~/.aws/credentials), GCP (service account JSON), Azure (azure.json), and Kubernetes configs (~/.kube/config). Test validity and document accessible cloud resources.' },
        ],
      },
    ],
  },
  {
    id: 'persistence',
    title: 'Persistence Risk Assessment',
    items: [
      {
        osLabel: 'Linux',
        suggestions: [
          { label: 'Test cron job persistence vector', prompt: 'Assess whether the compromised access allows adding a cron job that would survive reboots. Add a benign test entry to crontab and verify it persists. Document the persistence risk for remediation recommendations.' },
          { label: 'Test SSH key injection vector', prompt: 'Assess whether the compromised access allows injecting an SSH public key into authorized_keys files. Generate a test key pair, inject it, and verify passwordless SSH access. Document the persistence risk.' },
          { label: 'Test unauthorized account creation', prompt: 'Assess whether the compromised access allows creating new user accounts with elevated privileges. Attempt to create a test account and verify access. Document the persistence risk for remediation.' },
          { label: 'Test systemd service persistence vector', prompt: 'Assess whether the compromised access allows creating a systemd service that executes on boot. Write a benign test service, enable it, and verify it starts on restart. Document the persistence risk.' },
        ],
      },
      {
        osLabel: 'Windows',
        suggestions: [
          { label: 'Test registry run key persistence', prompt: 'Assess whether the compromised access allows adding a registry run key (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) for persistence. Add a benign test entry and verify it executes on login. Document the risk.' },
          { label: 'Test scheduled task persistence', prompt: 'Assess whether the compromised access allows creating scheduled tasks for persistence. Create a benign test task and verify execution on startup. Document the persistence risk for remediation.' },
          { label: 'Test Meterpreter persistence mechanism', prompt: 'Use Meterpreter persistence module to assess whether the system is vulnerable to auto-starting payload persistence. Document the persistence vector and recommend mitigations.' },
        ],
      },
    ],
  },
  {
    id: 'sys_enum',
    title: 'System & Environment Enumeration',
    items: [
      {
        suggestions: [
          { label: 'Full system enumeration', prompt: 'Collect comprehensive system information: OS version, kernel, hostname, architecture, installed packages, running processes, logged-in users, environment variables, mounted filesystems, and scheduled tasks.' },
          { label: 'User and group enumeration', prompt: 'Enumerate all user accounts (/etc/passwd, net user), groups (/etc/group), sudo permissions, login history (lastlog, wtmp), and currently logged-in users. Identify service accounts and privileged users.' },
          { label: 'Network configuration mapping', prompt: 'Map all network interfaces, IP addresses, routing tables, DNS configuration, active connections (netstat/ss), listening services, firewall rules (iptables/ufw), and ARP neighbors.' },
          { label: 'Process and service audit', prompt: 'List all running processes with their owners and command lines (ps aux). Identify services running as root, unusual processes, and processes with network connections. Check for Docker/container environments.' },
          { label: 'Installed software and patch level', prompt: 'List all installed packages and their versions (dpkg -l, rpm -qa, pip list, npm list -g). Identify security patches applied and missing. Flag any software with known privilege escalation vulnerabilities.' },
          { label: 'Proof of access (web server)', prompt: 'Locate the web server document root and place a proof-of-access file (e.g., pentest-proof.txt) demonstrating write access was achieved. Take a screenshot via execute_curl to document the result for the engagement report.' },
        ],
      },
    ],
  },
]

const LOADING_STATUS_WORDS = [
  'Negotiating with the network...',
  'Asking the bits nicely...',
  'Convincing the server to talk...',
  'Reading between the packets...',
  'Shaking hands with the target...',
  'Befriending the firewall...',
  'Teaching bytes to cooperate...',
  'Untangling the topology...',
  'Letting the data settle...',
  'Whispering to the DNS...',
  'Collecting breadcrumbs...',
  'Following the wire...',
  'Connecting the dots...',
  'Pulling the threads...',
  'Unfolding the map...',
  'Warming up the graph...',
  'Chasing loose ends...',
  'Sorting through the noise...',
  'Peeking around corners...',
  'Sketching the big picture...',
  'Tuning into the signal...',
  'Piecing it together...',
  'Building the puzzle...',
  'Tracing the trail...',
  'Digging a little deeper...',
  'Almost there, probably...',
  'Making friends with the data...',
  'Sifting through the layers...',
  'Listening to the wire...',
  'Mapping the terrain...',
  'Poking around gently...',
  'Sweet-talking the endpoints...',
  'Unwrapping the responses...',
  'Decoding the conversation...',
  'Charming the routers...',
  'Nudging the services...',
  'Flipping through the records...',
  'One packet at a time...',
  'Gathering intel quietly...',
  'Reading the fine print...',
  'Checking under the hood...',
  'Knocking on every door...',
  'Stitching the fragments...',
  'Patience, the graph is cooking...',
  'Herding the results...',
  'Tiptoeing through the stack...',
  'Borrowing some bandwidth...',
  'Persuading the protocols...',
  'Turning over every stone...',
  'Measuring the surface...',
]

function useRotatingWord(words: string[], intervalMs = 2500) {
  const [index, setIndex] = useState(() => Math.floor(Math.random() * words.length))
  useEffect(() => {
    const timer = setInterval(() => {
      setIndex(prev => {
        let next: number
        do {
          next = Math.floor(Math.random() * words.length)
        } while (next === prev && words.length > 1)
        return next
      })
    }, intervalMs)
    return () => clearInterval(timer)
  }, [words.length, intervalMs])
  return words[index]
}

export function AIAssistantDrawer({
  isOpen,
  onClose,
  userId,
  projectId,
  sessionId,
  onResetSession,
  onSwitchSession,
  modelName,
  onModelChange,
  toolPhaseMap,
  stealthMode = false,
  onToggleStealth,
  deepThinkEnabled = true,
  onToggleDeepThink,
  onRefetchGraph,
  isOtherChainsHidden = false,
  onToggleOtherChains,
  hasOtherChains = false,
  requireToolConfirmation = true,
}: AIAssistantDrawerProps) {
  const statusWord = useRotatingWord(LOADING_STATUS_WORDS, 5000)
  const [chatItems, setChatItems] = useState<ChatItem[]>([])
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isStopped, setIsStopped] = useState(false)
  const [isStopping, setIsStopping] = useState(false)
  const [currentPhase, setCurrentPhase] = useState<Phase>('informational')
  const [attackPathType, setAttackPathType] = useState<string>('')
  const [iterationCount, setIterationCount] = useState(0)
  const [awaitingApproval, setAwaitingApproval] = useState(false)
  const [approvalRequest, setApprovalRequest] = useState<ApprovalRequestPayload | null>(null)
  const [modificationText, setModificationText] = useState('')

  // Tool confirmation state
  const [awaitingToolConfirmation, setAwaitingToolConfirmation] = useState(false)
  const [toolConfirmationRequest, setToolConfirmationRequest] = useState<ToolConfirmationRequestPayload | null>(null)

  // Q&A state
  const [awaitingQuestion, setAwaitingQuestion] = useState(false)
  const [questionRequest, setQuestionRequest] = useState<QuestionRequestPayload | null>(null)
  const [answerText, setAnswerText] = useState('')
  const [selectedOptions, setSelectedOptions] = useState<string[]>([])

  const [todoList, setTodoList] = useState<TodoItem[]>([])
  const [copiedMessageId, setCopiedMessageId] = useState<string | null>(null)
  const [copiedFieldKey, setCopiedFieldKey] = useState<string | null>(null)

  // API key status for tool alerts + inline key modal
  const [missingApiKeys, setMissingApiKeys] = useState<Set<string>>(new Set())
  const [apiKeyModal, setApiKeyModal] = useState<string | null>(null) // tool id
  const [apiKeyValue, setApiKeyValue] = useState('')
  const [apiKeyVisible, setApiKeyVisible] = useState(false)
  const [apiKeySaving, setApiKeySaving] = useState(false)

  // Conversation history state
  const [showHistory, setShowHistory] = useState(false)
  const [conversationId, setConversationId] = useState<string | null>(null)

  // Template dropdown state
  const [openTemplateGroup, setOpenTemplateGroup] = useState<string | null>(null)
  const [openInfoSubGroup, setOpenInfoSubGroup] = useState<string | null>(null)
  const [openExploitSubGroup, setOpenExploitSubGroup] = useState<string | null>(null)
  const [openPostSubGroup, setOpenPostSubGroup] = useState<string | null>(null)

  // Conversation hooks
  const {
    conversations,
    fetchConversations,
    createConversation,
    deleteConversation,
    loadConversation,
  } = useConversations(projectId, userId)

  const { saveMessage, updateConversation: updateConvMeta } = useChatPersistence(conversationId)

  // Fetch API key status for tool alerts
  const fetchApiKeyStatus = useCallback(() => {
    if (!userId) return
    fetch(`/api/users/${userId}/settings`)
      .then(r => r.ok ? r.json() : null)
      .then(settings => {
        if (!settings) return
        const missing = new Set<string>()
        if (!settings.tavilyApiKey) missing.add('web_search')
        if (!settings.shodanApiKey) missing.add('shodan')
        if (!settings.serpApiKey) missing.add('google_dork')
        setMissingApiKeys(missing)
      })
      .catch(() => {})
  }, [userId])

  useEffect(() => { fetchApiKeyStatus() }, [fetchApiKeyStatus])

  const API_KEY_INFO: Record<string, { field: string; label: string; hint: string; url: string }> = {
    web_search: { field: 'tavilyApiKey', label: 'Tavily', hint: 'Enables web_search tool for CVE research and exploit lookups', url: 'https://app.tavily.com/home' },
    shodan: { field: 'shodanApiKey', label: 'Shodan', hint: 'Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)', url: 'https://account.shodan.io/' },
    google_dork: { field: 'serpApiKey', label: 'SerpAPI', hint: 'Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:)', url: 'https://serpapi.com/manage-api-key' },
  }

  const openApiKeyModal = useCallback((toolId: string) => {
    setApiKeyModal(toolId)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const closeApiKeyModal = useCallback(() => {
    setApiKeyModal(null)
    setApiKeyValue('')
    setApiKeyVisible(false)
  }, [])

  const saveApiKey = useCallback(async () => {
    if (!userId || !apiKeyModal || !apiKeyValue.trim()) return
    const info = API_KEY_INFO[apiKeyModal]
    if (!info) return
    setApiKeySaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [info.field]: apiKeyValue.trim() }),
      })
      if (resp.ok) {
        closeApiKeyModal()
        fetchApiKeyStatus()
      }
    } catch { /* silent */ } finally {
      setApiKeySaving(false)
    }
  }, [userId, apiKeyModal, apiKeyValue, closeApiKeyModal, fetchApiKeyStatus])

  // Settings dropdown & modal state
  const [showSettingsDropdown, setShowSettingsDropdown] = useState(false)
  const [settingsModal, setSettingsModal] = useState<'agent' | 'toolmatrix' | 'attack' | null>(null)

  // Model picker modal state
  const [showModelModal, setShowModelModal] = useState(false)
  const [modelSearch, setModelSearch] = useState('')
  const [allModels, setAllModels] = useState<Record<string, ModelOption[]>>({})
  const [modelsLoading, setModelsLoading] = useState(false)
  const [modelsError, setModelsError] = useState(false)
  const modelSearchRef = useRef<HTMLInputElement>(null)

  // Fetch models when model modal opens
  useEffect(() => {
    if (!showModelModal) return
    let cancelled = false
    setModelsLoading(true)
    setModelsError(false)
    const params = userId ? `?userId=${userId}` : ''
    fetch(`/api/models${params}`)
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch')
        return r.json()
      })
      .then(data => {
        if (cancelled) return
        if (data && typeof data === 'object' && !data.error) {
          setAllModels(data)
        } else {
          setModelsError(true)
        }
      })
      .catch(() => { if (!cancelled) setModelsError(true) })
      .finally(() => { if (!cancelled) setModelsLoading(false) })
    return () => { cancelled = true }
  }, [showModelModal, userId])

  // Auto-focus search when model modal opens
  useEffect(() => {
    if (showModelModal) {
      setTimeout(() => modelSearchRef.current?.focus(), 0)
    } else {
      setModelSearch('')
    }
  }, [showModelModal])

  // Filter models by search
  const filteredModels: Record<string, ModelOption[]> = {}
  if (showModelModal) {
    const lowerSearch = modelSearch.toLowerCase()
    for (const [provider, models] of Object.entries(allModels)) {
      const filtered = models.filter(m =>
        m.id.toLowerCase().includes(lowerSearch) ||
        m.name.toLowerCase().includes(lowerSearch) ||
        m.description.toLowerCase().includes(lowerSearch)
      )
      if (filtered.length > 0) filteredModels[provider] = filtered
    }
  }

  const handleSelectModel = useCallback((id: string) => {
    onModelChange?.(id)
    setShowModelModal(false)
  }, [onModelChange])
  const [projectFormData, setProjectFormData] = useState<Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'> | null>(null)
  const settingsDropdownRef = useRef<HTMLDivElement>(null)

  // Close settings dropdown on outside click
  useEffect(() => {
    if (!showSettingsDropdown) return
    const handler = (e: MouseEvent) => {
      if (settingsDropdownRef.current && !settingsDropdownRef.current.contains(e.target as Node)) {
        setShowSettingsDropdown(false)
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [showSettingsDropdown])

  // Debounced save refs (must be before flushPendingSave)
  const pendingSaveRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const latestFormDataRef = useRef(projectFormData)
  latestFormDataRef.current = projectFormData

  // Flush any pending save before clearing data
  const flushPendingSave = useCallback(() => {
    if (pendingSaveRef.current) {
      clearTimeout(pendingSaveRef.current)
      pendingSaveRef.current = null
      const data = latestFormDataRef.current
      if (data && projectId) {
        fetch(`/api/projects/${projectId}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
        }).catch(() => {})
      }
    }
  }, [projectId])

  // Fetch project data when modal opens; clear stale data on switch
  useEffect(() => {
    if (!settingsModal || !projectId) {
      flushPendingSave()
      setProjectFormData(null)
      return
    }
    flushPendingSave()
    setProjectFormData(null)
    let cancelled = false
    fetch(`/api/projects/${projectId}`)
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (!cancelled && data) {
          const { id, userId: _u, createdAt, updatedAt, user, ...formData } = data
          setProjectFormData(formData)
        }
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [settingsModal, projectId, flushPendingSave])

  // Debounced save for project field updates from modal
  const updateProjectField = useCallback(<K extends keyof Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>>(
    field: K,
    value: Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>[K]
  ) => {
    setProjectFormData(prev => {
      if (!prev) return prev
      return { ...prev, [field]: value }
    })
    // Debounce the PUT request
    if (pendingSaveRef.current) clearTimeout(pendingSaveRef.current)
    pendingSaveRef.current = setTimeout(() => {
      const data = latestFormDataRef.current
      if (!data || !projectId) return
      fetch(`/api/projects/${projectId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      }).catch(() => {})
    }, 500)
  }, [projectId])

  // Attack skill data for badge tooltip
  const [skillData, setSkillData] = useState<{
    builtIn: { id: string; name: string }[]
    user: { id: string; name: string }[]
    config: { builtIn: Record<string, boolean>; user: Record<string, boolean> }
  } | null>(null)

  useEffect(() => {
    if (!userId || !projectId) return
    let cancelled = false
    async function fetchSkills() {
      try {
        const [availRes, projRes] = await Promise.all([
          fetch(`/api/users/${userId}/attack-skills/available`),
          fetch(`/api/projects/${projectId}`),
        ])
        if (cancelled) return
        if (availRes.ok && projRes.ok) {
          const avail = await availRes.json()
          const proj = await projRes.json()
          const cfg = proj.attackSkillConfig || { builtIn: {}, user: {} }
          setSkillData({
            builtIn: avail.builtIn,
            user: avail.user,
            config: {
              builtIn: cfg.builtIn || {},
              user: cfg.user || {},
            },
          })
        }
      } catch { /* silent */ }
    }
    fetchSkills()
    return () => { cancelled = true }
  }, [userId, projectId])

  const eyeRef = useRef<HTMLImageElement>(null)

  // Random heartbeat for the eye
  useEffect(() => {
    if (!isLoading) return
    let timeout: ReturnType<typeof setTimeout>
    const beat = () => {
      const el = eyeRef.current
      if (!el) return
      el.style.transition = 'transform 0.15s ease-out'
      el.style.transform = 'scale(1.25)'
      setTimeout(() => {
        el.style.transform = 'scale(1)'
        setTimeout(() => {
          el.style.transform = 'scale(1.15)'
          setTimeout(() => {
            el.style.transform = 'scale(1)'
          }, 150)
        }, 120)
      }, 150)
      // Next beat at random interval between 4s and 10s
      timeout = setTimeout(beat, 4000 + Math.random() * 6000)
    }
    timeout = setTimeout(beat, 2000 + Math.random() * 4000)
    return () => clearTimeout(timeout)
  }, [isLoading])

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const isProcessingApproval = useRef(false)
  const awaitingApprovalRef = useRef(false)
  const isProcessingQuestion = useRef(false)
  const awaitingQuestionRef = useRef(false)
  const isProcessingToolConfirmation = useRef(false)
  const awaitingToolConfirmationRef = useRef(false)
  const pendingApprovalToolId = useRef<string | null>(null)
  const pendingApprovalWaveId = useRef<string | null>(null)
  const shouldAutoScroll = useRef(true)
  const itemIdCounter = useRef(0)

  const scrollToBottom = useCallback((force = false) => {
    if (force || shouldAutoScroll.current) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [])

  // Check if user is at the bottom of the scroll
  const checkIfAtBottom = useCallback(() => {
    const container = messagesContainerRef.current
    if (!container) return true

    const threshold = 50 // pixels from bottom
    const isAtBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight < threshold

    shouldAutoScroll.current = isAtBottom
    return isAtBottom
  }, [])

  // Auto-scroll only if user is at bottom
  useEffect(() => {
    scrollToBottom()
  }, [chatItems, scrollToBottom])

  useEffect(() => {
    if (isOpen && inputRef.current && !awaitingApproval) {
      setTimeout(() => {
        inputRef.current?.focus()
        scrollToBottom(true) // Force scroll to bottom when opening
      }, 300)
    }
  }, [isOpen, awaitingApproval, scrollToBottom])

  // Fetch conversations when history panel opens, auto-refresh every 5s
  useEffect(() => {
    if (showHistory && projectId && userId) {
      fetchConversations()
      const interval = setInterval(fetchConversations, 5000)
      return () => clearInterval(interval)
    }
  }, [showHistory, projectId, userId, fetchConversations])

  // Reset state when session changes (skip if switching to a loaded conversation)
  const isRestoringConversation = useRef(false)
  useEffect(() => {
    if (isRestoringConversation.current) {
      isRestoringConversation.current = false
      return
    }
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('')
    setIterationCount(0)
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAwaitingToolConfirmation(false)
    setToolConfirmationRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    awaitingToolConfirmationRef.current = false
    isProcessingToolConfirmation.current = false
    pendingApprovalToolId.current = null
    pendingApprovalWaveId.current = null
    shouldAutoScroll.current = true // Reset to auto-scroll on new session
  }, [sessionId])

  // WebSocket message handler
  const handleWebSocketMessage = useCallback((message: ServerMessage) => {
    switch (message.type) {
      case MessageType.CONNECTED:
        break

      case MessageType.THINKING:
        // Add thinking item to chat
        const thinkingItem: ThinkingItem = {
          type: 'thinking',
          id: `thinking-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          thought: message.payload.thought || '',
          reasoning: message.payload.reasoning || '',
          action: 'thinking',
          updated_todo_list: todoList,
        }
        setChatItems(prev => [...prev, thinkingItem])
        // Don't set isLoading if any user interaction is pending — keep buttons enabled
        if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
          setIsLoading(true)
        }
        setIsStopped(false)
        break

      case MessageType.PLAN_START: {
        const pendingWaveId = pendingApprovalWaveId.current
        if (pendingWaveId) {
          // Reuse existing pending_approval PlanWaveItem — update wave_id and status to running
          pendingApprovalWaveId.current = null
          setChatItems((prev: ChatItem[]) => {
            const idx = prev.findIndex(item => item.type === 'plan_wave' && item.id === pendingWaveId)
            if (idx !== -1) {
              const wave = prev[idx] as PlanWaveItem
              // Only update wave_id and wave status — do NOT change nested tool
              // statuses. Each TOOL_START will update its own tool from
              // pending_approval → running with a fresh timestamp for the timer.
              return [
                ...prev.slice(0, idx),
                { ...wave, wave_id: message.payload.wave_id, status: 'running' as const, timestamp: new Date(), tool_count: message.payload.tool_count || wave.tool_count },
                ...prev.slice(idx + 1),
              ]
            }
            return prev
          })
        } else {
          // Normal flow — create a plan wave container with nested tools
          const waveItem: PlanWaveItem = {
            type: 'plan_wave',
            id: `wave-${Date.now()}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            wave_id: message.payload.wave_id,
            plan_rationale: message.payload.plan_rationale || '',
            tool_count: message.payload.tool_count,
            tools: [],
            status: 'running',
          }
          setChatItems((prev: ChatItem[]) => [...prev, waveItem])
        }
        if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
          setIsLoading(true)
        }
        break
      }

      case MessageType.TOOL_START: {
        const wave_id = message.payload.wave_id
        if (wave_id) {
          // Nest tool inside matching PlanWaveItem
          // Check if a pending_approval tool with this name already exists in the wave (from confirmation)
          setChatItems((prev: ChatItem[]) => {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === wave_id
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              // Try to match an existing pending_approval tool by name
              const pendingIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'pending_approval'
              )
              if (pendingIdx !== -1) {
                // Reuse — update to running with fresh timestamp
                const updatedTools = [...waveItem.tools]
                updatedTools[pendingIdx] = {
                  ...updatedTools[pendingIdx],
                  status: 'running',
                  timestamp: new Date(),
                  tool_args: message.payload.tool_args,
                  step_index: message.payload.step_index,
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
              // No pending match — add as new nested tool (non-dangerous tool in the wave)
              const nestedTool: ToolExecutionItem = {
                type: 'tool_execution',
                id: `tool-${Date.now()}-${itemIdCounter.current++}`,
                timestamp: new Date(),
                tool_name: message.payload.tool_name,
                tool_args: message.payload.tool_args,
                status: 'running',
                output_chunks: [],
                step_index: message.payload.step_index,
              }
              return [
                ...prev.slice(0, waveIndex),
                { ...waveItem, tools: [...waveItem.tools, nestedTool] },
                ...prev.slice(waveIndex + 1),
              ]
            }
            // Fallback: add as standalone if wave not found
            const fallbackTool: ToolExecutionItem = {
              type: 'tool_execution',
              id: `tool-${Date.now()}-${itemIdCounter.current++}`,
              timestamp: new Date(),
              tool_name: message.payload.tool_name,
              tool_args: message.payload.tool_args,
              status: 'running',
              output_chunks: [],
            }
            return [...prev, fallbackTool]
          })
        } else {
          // Standard single-tool execution
          const pendingToolId = pendingApprovalToolId.current
          if (pendingToolId) {
            // Reuse existing pending_approval card — update to running with fresh timestamp
            pendingApprovalToolId.current = null
            setChatItems((prev: ChatItem[]) => prev.map((item: ChatItem) =>
              'type' in item && item.type === 'tool_execution' && item.id === pendingToolId
                ? { ...item, status: 'running' as const, timestamp: new Date(), tool_args: message.payload.tool_args }
                : item
            ))
          } else {
            const toolItem: ToolExecutionItem = {
              type: 'tool_execution',
              id: `tool-${Date.now()}-${itemIdCounter.current++}`,
              timestamp: new Date(),
              tool_name: message.payload.tool_name,
              tool_args: message.payload.tool_args,
              status: 'running',
              output_chunks: [],
            }
            setChatItems((prev: ChatItem[]) => [...prev, toolItem])
          }
        }
        if (!awaitingToolConfirmationRef.current && !awaitingApprovalRef.current && !awaitingQuestionRef.current) {
          setIsLoading(true)
        }
        break
      }

      case MessageType.TOOL_OUTPUT_CHUNK: {
        const chunkWaveId = message.payload.wave_id
        setChatItems(prev => {
          if (chunkWaveId) {
            // Find tool inside PlanWaveItem
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === chunkWaveId
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const chunkStepIdx = message.payload.step_index
              const toolIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'running'
                  && (chunkStepIdx == null || t.step_index === chunkStepIdx)
              )
              if (toolIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                updatedTools[toolIdx] = {
                  ...updatedTools[toolIdx],
                  output_chunks: [...updatedTools[toolIdx].output_chunks, message.payload.chunk],
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
            }
            return prev
          }
          // Standard single-tool chunk
          const toolIndex = prev.findIndex(
            item => 'type' in item &&
                    item.type === 'tool_execution' &&
                    item.tool_name === message.payload.tool_name &&
                    item.status === 'running'
          )
          if (toolIndex !== -1) {
            const toolItem = prev[toolIndex] as ToolExecutionItem
            return [
              ...prev.slice(0, toolIndex),
              {
                ...toolItem,
                output_chunks: [...toolItem.output_chunks, message.payload.chunk],
              },
              ...prev.slice(toolIndex + 1)
            ]
          }
          return prev
        })
        break
      }

      case MessageType.TOOL_COMPLETE: {
        const completeWaveId = message.payload.wave_id
        if (completeWaveId) {
          // Update tool inside PlanWaveItem — do NOT setIsLoading(false), wait for PLAN_COMPLETE
          setChatItems(prev => {
            const waveIndex = prev.findIndex(
              item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === completeWaveId
            )
            if (waveIndex !== -1) {
              const waveItem = prev[waveIndex] as PlanWaveItem
              const completeStepIdx = message.payload.step_index
              const toolIdx = waveItem.tools.findIndex(
                t => t.tool_name === message.payload.tool_name && t.status === 'running'
                  && (completeStepIdx == null || t.step_index === completeStepIdx)
              )
              if (toolIdx !== -1) {
                const updatedTools = [...waveItem.tools]
                const toolItem = updatedTools[toolIdx]
                const elapsed = Date.now() - toolItem.timestamp.getTime()
                updatedTools[toolIdx] = {
                  ...toolItem,
                  status: message.payload.success ? 'success' : 'error',
                  final_output: message.payload.output_summary,
                  actionable_findings: message.payload.actionable_findings || [],
                  recommended_next_steps: message.payload.recommended_next_steps || [],
                  duration: elapsed,
                }
                return [
                  ...prev.slice(0, waveIndex),
                  { ...waveItem, tools: updatedTools },
                  ...prev.slice(waveIndex + 1),
                ]
              }
            }
            return prev
          })
        } else {
          // Standard single-tool completion
          setChatItems(prev => {
            const toolIndex = prev.findIndex(
              item => 'type' in item &&
                      item.type === 'tool_execution' &&
                      item.tool_name === message.payload.tool_name &&
                      item.status === 'running'
            )
            if (toolIndex !== -1) {
              const toolItem = prev[toolIndex] as ToolExecutionItem
              const elapsed = Date.now() - toolItem.timestamp.getTime()
              const updatedItem: ToolExecutionItem = {
                ...toolItem,
                status: message.payload.success ? 'success' : 'error',
                final_output: message.payload.output_summary,
                actionable_findings: message.payload.actionable_findings || [],
                recommended_next_steps: message.payload.recommended_next_steps || [],
                duration: elapsed,
              }
              return [
                ...prev.slice(0, toolIndex),
                updatedItem,
                ...prev.slice(toolIndex + 1)
              ]
            }
            return prev
          })
          setIsLoading(false)
        }
        break
      }

      case MessageType.PLAN_COMPLETE: {
        // Mark wave as complete and set final status
        // Do NOT setIsLoading(false) — think_node still needs to analyze wave outputs
        // (the LLM call takes seconds). Loading state will be managed by THINKING/RESPONSE events.
        setChatItems((prev: ChatItem[]) => {
          const waveIndex = prev.findIndex(
            (item: ChatItem) => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === message.payload.wave_id
          )
          if (waveIndex !== -1) {
            const waveItem = prev[waveIndex] as PlanWaveItem
            let status: PlanWaveItem['status'] = 'success'
            if (message.payload.failed === message.payload.total_steps) {
              status = 'error'
            } else if (message.payload.failed > 0) {
              status = 'partial'
            }
            return [
              ...prev.slice(0, waveIndex),
              { ...waveItem, status },
              ...prev.slice(waveIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.PLAN_ANALYSIS: {
        // Update PlanWaveItem with analysis from think_node
        setChatItems(prev => {
          const waveIndex = prev.findIndex(
            (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === message.payload.wave_id
          )
          if (waveIndex !== -1) {
            const waveItem = prev[waveIndex] as PlanWaveItem
            return [
              ...prev.slice(0, waveIndex),
              {
                ...waveItem,
                interpretation: message.payload.interpretation,
                actionable_findings: message.payload.actionable_findings || [],
                recommended_next_steps: message.payload.recommended_next_steps || [],
              },
              ...prev.slice(waveIndex + 1),
            ]
          }
          return prev
        })
        break
      }

      case MessageType.DEEP_THINK: {
        const deepThinkItem: DeepThinkItem = {
          type: 'deep_think',
          id: `deep-think-${Date.now()}-${itemIdCounter.current++}`,
          timestamp: new Date(),
          trigger_reason: message.payload.trigger_reason,
          analysis: message.payload.analysis,
          iteration: message.payload.iteration,
          phase: message.payload.phase,
        }
        setChatItems(prev => [...prev, deepThinkItem])
        break
      }

      case MessageType.PHASE_UPDATE:
        setCurrentPhase(message.payload.current_phase as Phase)
        setIterationCount(message.payload.iteration_count)
        if (message.payload.attack_path_type) {
          setAttackPathType(message.payload.attack_path_type)
        }
        break

      case MessageType.TODO_UPDATE:
        setTodoList(message.payload.todo_list)
        // Update the last thinking item with the new todo list
        setChatItems(prev => {
          if (prev.length === 0) return prev
          const lastItem = prev[prev.length - 1]
          if ('type' in lastItem && lastItem.type === 'thinking') {
            return [
              ...prev.slice(0, -1),
              { ...lastItem, updated_todo_list: message.payload.todo_list }
            ]
          }
          return prev
        })
        break

      case MessageType.APPROVAL_REQUEST:
        // Ignore duplicate approval requests if we're already awaiting or just processed one
        if (awaitingApprovalRef.current || isProcessingApproval.current) {
          console.log('Ignoring duplicate approval request - already processing')
          break
        }

        console.log('Received approval request:', message.payload)
        awaitingApprovalRef.current = true
        setAwaitingApproval(true)
        setApprovalRequest(message.payload)
        setIsLoading(false)
        break

      case MessageType.QUESTION_REQUEST:
        // Ignore duplicate question requests if we're already awaiting or just processed one
        if (awaitingQuestionRef.current || isProcessingQuestion.current) {
          console.log('Ignoring duplicate question request - already processing')
          break
        }

        console.log('Received question request:', message.payload)
        awaitingQuestionRef.current = true
        setAwaitingQuestion(true)
        setQuestionRequest(message.payload)
        setIsLoading(false)
        break

      case MessageType.TOOL_CONFIRMATION_REQUEST: {
        if (awaitingToolConfirmationRef.current || isProcessingToolConfirmation.current) {
          break
        }
        awaitingToolConfirmationRef.current = true
        setAwaitingToolConfirmation(true)
        setToolConfirmationRequest(message.payload)
        setIsLoading(false)

        const confMode = message.payload.mode || 'single'
        const confTools = message.payload.tools || []

        if (confMode === 'plan') {
          // Create a PlanWaveItem with pending_approval status
          const waveId = `wave-conf-${Date.now()}-${itemIdCounter.current++}`
          pendingApprovalWaveId.current = waveId
          pendingApprovalToolId.current = null
          const pendingTools: ToolExecutionItem[] = confTools.map((t: any, idx: number) => ({
            type: 'tool_execution' as const,
            id: `tool-conf-${Date.now()}-${idx}-${itemIdCounter.current++}`,
            timestamp: new Date(),
            tool_name: t.tool_name || '',
            tool_args: t.tool_args || {},
            status: 'pending_approval' as const,
            output_chunks: [],
          }))
          const waveItem: PlanWaveItem = {
            type: 'plan_wave',
            id: waveId,
            timestamp: new Date(),
            wave_id: '',  // Will be set when PLAN_START arrives after approval
            plan_rationale: message.payload.reasoning || '',
            tool_count: confTools.length,
            tools: pendingTools,
            status: 'pending_approval',
          }
          setChatItems((prev: ChatItem[]) => [...prev, waveItem])
        } else {
          // Single tool — reuse the existing 'running' card (created by TOOL_START
          // which arrived before TOOL_CONFIRMATION_REQUEST) and update its status
          // to 'pending_approval'.  This prevents a duplicate card.
          const tool = confTools[0] || {}
          pendingApprovalWaveId.current = null
          setChatItems((prev: ChatItem[]) => {
            const existingIdx = prev.findIndex(
              (item: ChatItem) => item.type === 'tool_execution'
                && (item as ToolExecutionItem).tool_name === (tool.tool_name || '')
                && (item as ToolExecutionItem).status === 'running'
            )
            if (existingIdx !== -1) {
              // Reuse existing card — just change status
              const existing = prev[existingIdx] as ToolExecutionItem
              pendingApprovalToolId.current = existing.id
              return [
                ...prev.slice(0, existingIdx),
                { ...existing, status: 'pending_approval' as const, tool_args: tool.tool_args || existing.tool_args },
                ...prev.slice(existingIdx + 1),
              ]
            }
            // No existing card (edge case) — create new one
            const toolId = `tool-conf-${Date.now()}-${itemIdCounter.current++}`
            pendingApprovalToolId.current = toolId
            const toolItem: ToolExecutionItem = {
              type: 'tool_execution',
              id: toolId,
              timestamp: new Date(),
              tool_name: tool.tool_name || '',
              tool_args: tool.tool_args || {},
              status: 'pending_approval',
              output_chunks: [],
            }
            return [...prev, toolItem]
          })
        }
        break
      }

      case MessageType.RESPONSE:
        // Add agent response message with tier-aware badge
        const tier = message.payload.response_tier || (message.payload.task_complete ? 'full_report' : 'conversational')
        const assistantMessage: Message = {
          type: 'message',
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          content: message.payload.answer,
          phase: message.payload.phase as Phase,
          timestamp: new Date(),
          isReport: tier === 'full_report',
          responseTier: tier,
        }
        setChatItems(prev => [...prev, assistantMessage])
        setIsLoading(false)
        break

      case MessageType.ERROR:
        const errorMessage: Message = {
          type: 'message',
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: message.payload.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMessage])
        setIsLoading(false)
        break

      case MessageType.TASK_COMPLETE:
        const completeMessage: Message = {
          type: 'message',
          id: `complete-${Date.now()}`,
          role: 'assistant',
          content: message.payload.message,
          phase: message.payload.final_phase as Phase,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, completeMessage])
        setIsLoading(false)
        break

      case MessageType.GUIDANCE_ACK:
        // Already shown in chat from handleSend
        break

      case MessageType.STOPPED:
        setIsLoading(false)
        setIsStopped(true)
        setIsStopping(false)
        break

      case MessageType.FILE_READY:
        const fileItem: FileDownloadItem = {
          type: 'file_download',
          id: `file-${Date.now()}`,
          timestamp: new Date(),
          filepath: message.payload.filepath,
          filename: message.payload.filename,
          description: message.payload.description,
          source: message.payload.source,
        }
        setChatItems(prev => [...prev, fileItem])
        break
    }
  }, [todoList])

  // Initialize WebSocket
  const { status, isConnected, reconnectAttempt, sendQuery, sendApproval, sendToolConfirmation, sendAnswer, sendGuidance, sendStop, sendResume } = useAgentWebSocket({
    userId: userId || process.env.NEXT_PUBLIC_USER_ID || 'default_user',
    projectId: projectId || process.env.NEXT_PUBLIC_PROJECT_ID || 'default_project',
    sessionId: sessionId || process.env.NEXT_PUBLIC_SESSION_ID || 'default_session',
    enabled: isOpen,
    onMessage: handleWebSocketMessage,
    onError: (error) => {
      // Only show connection errors once, not for every retry
      if (error.message === 'Initial connection failed') {
        const errorMsg: Message = {
          type: 'message',
          id: `error-${Date.now()}`,
          role: 'assistant',
          content: `Failed to connect to agent. Please check that the backend is running at ws://${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8090/ws/agent`,
          error: error.message,
          timestamp: new Date(),
        }
        setChatItems(prev => [...prev, errorMsg])
      }
    },
  })

  const handleSend = useCallback(async () => {
    const question = inputValue.trim()
    if (!question || !isConnected || awaitingApproval || awaitingQuestion || awaitingToolConfirmation) return

    // Auto-create conversation on first user message
    if (!conversationId && projectId && userId && sessionId) {
      const conv = await createConversation(sessionId)
      if (conv) {
        setConversationId(conv.id)
        // Title will be set by the backend persistence layer
      }
    }

    if (isLoading) {
      // Agent is working → send as guidance
      const guidanceMessage: Message = {
        type: 'message',
        id: `guidance-${Date.now()}`,
        role: 'user',
        content: question,
        isGuidance: true,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, guidanceMessage])
      setInputValue('')
      sendGuidance(question)
      saveMessage('guidance', { content: question, isGuidance: true })
    } else {
      // Normal query
      const userMessage: Message = {
        type: 'message',
        id: `user-${Date.now()}`,
        role: 'user',
        content: question,
        timestamp: new Date(),
      }
      setChatItems(prev => [...prev, userMessage])
      setInputValue('')
      setIsLoading(true)

      // Set title from first user message
      const hasUserMessage = chatItems.some((item: ChatItem) => 'role' in item && item.role === 'user')
      if (!hasUserMessage) {
        updateConvMeta({ title: question.substring(0, 100) })
      }

      try {
        sendQuery(question)
      } catch (error) {
        setIsLoading(false)
      }
    }
  }, [inputValue, isConnected, isLoading, awaitingApproval, awaitingQuestion, sendQuery, sendGuidance, conversationId, projectId, userId, sessionId, createConversation, saveMessage, updateConvMeta, chatItems])

  const handleApproval = useCallback((decision: 'approve' | 'modify' | 'abort') => {
    // Prevent double submission using ref (immediate check, not async state)
    if (!awaitingApproval || isProcessingApproval.current || !awaitingApprovalRef.current) {
      return
    }

    // Mark as processing immediately
    isProcessingApproval.current = true
    awaitingApprovalRef.current = false

    setAwaitingApproval(false)
    setApprovalRequest(null)
    setIsLoading(true)

    // Add decision message
    const decisionMessage: Message = {
      type: 'message',
      id: `decision-${Date.now()}`,
      role: 'user',
      content: decision === 'approve'
        ? 'Approved phase transition'
        : decision === 'modify'
        ? `Modified: ${modificationText}`
        : 'Aborted phase transition',
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, decisionMessage])

    try {
      sendApproval(decision, decision === 'modify' ? modificationText : undefined)
      setModificationText('')
    } catch (error) {
      setIsLoading(false)
      awaitingApprovalRef.current = false
      isProcessingApproval.current = false
    } finally {
      // Reset the processing flag after a delay to prevent backend from sending duplicate
      setTimeout(() => {
        isProcessingApproval.current = false
      }, 1000)
    }
  }, [modificationText, sendApproval, awaitingApproval])

  const handleTimelineToolConfirmation = useCallback((itemId: string, decision: 'approve' | 'reject') => {
    // Guard against double-processing
    if (isProcessingToolConfirmation.current) return
    isProcessingToolConfirmation.current = true

    // Clear confirmation state flags
    setAwaitingToolConfirmation(false)
    awaitingToolConfirmationRef.current = false
    setToolConfirmationRequest(null)
    setIsLoading(true)

    if (decision === 'reject') {
      // Reject: update card to error status
      setChatItems((prev: ChatItem[]) => prev.map((item: ChatItem) => {
        if (!('type' in item)) return item
        if (item.type === 'tool_execution' && item.id === itemId) {
          return { ...item, status: 'error' as const, final_output: 'Rejected by user' }
        }
        if (item.type === 'plan_wave' && item.id === itemId) {
          return { ...item, status: 'error' as const, interpretation: 'Rejected by user' }
        }
        return item
      }))
      pendingApprovalToolId.current = null
      pendingApprovalWaveId.current = null
    } else {
      // Approve: set refs so PLAN_START / TOOL_START can find and update the existing card
      // Use setChatItems to read current items without adding chatItems to deps
      setChatItems((prev: ChatItem[]) => {
        const matchingItem = prev.find((item: ChatItem) =>
          'type' in item && item.id === itemId && (item.type === 'plan_wave' || item.type === 'tool_execution')
        )
        if (matchingItem && 'type' in matchingItem) {
          if (matchingItem.type === 'plan_wave') {
            pendingApprovalWaveId.current = itemId
            pendingApprovalToolId.current = null
          } else {
            pendingApprovalToolId.current = itemId
            pendingApprovalWaveId.current = null
          }
        }
        return prev  // No mutation — just reading
      })
    }

    try {
      sendToolConfirmation(decision)
    } catch (error) {
      setIsLoading(false)
    } finally {
      setTimeout(() => {
        isProcessingToolConfirmation.current = false
      }, 1000)
    }
  }, [sendToolConfirmation])

  const handleAnswer = useCallback(() => {
    // Prevent double submission using ref (immediate check, not async state)
    if (!awaitingQuestion || isProcessingQuestion.current || !awaitingQuestionRef.current) {
      return
    }

    if (!questionRequest) return

    // Mark as processing immediately
    isProcessingQuestion.current = true
    awaitingQuestionRef.current = false

    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setIsLoading(true)

    const answer = questionRequest.format === 'text'
      ? answerText
      : selectedOptions.join(', ')

    // Add answer message
    const answerMessage: Message = {
      type: 'message',
      id: `answer-${Date.now()}`,
      role: 'user',
      content: `Answer: ${answer}`,
      timestamp: new Date(),
    }
    setChatItems(prev => [...prev, answerMessage])

    try {
      sendAnswer(answer)
      setAnswerText('')
      setSelectedOptions([])
    } catch (error) {
      setIsLoading(false)
      awaitingQuestionRef.current = false
      isProcessingQuestion.current = false
    } finally {
      // Reset the processing flag after a delay to prevent backend from sending duplicate
      setTimeout(() => {
        isProcessingQuestion.current = false
      }, 1000)
    }
  }, [questionRequest, answerText, selectedOptions, sendAnswer, awaitingQuestion])

  const handleStop = useCallback(() => {
    setIsStopping(true)
    sendStop()
  }, [sendStop])

  const handleResume = useCallback(() => {
    sendResume()
    setIsStopped(false)
    setIsStopping(false)
    setIsLoading(true)
  }, [sendResume])

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    e.target.style.height = 'auto'
    e.target.style.height = `${Math.min(e.target.scrollHeight, 120)}px`
  }

  const handleDownloadMarkdown = useCallback(() => {
    if (chatItems.length === 0) return

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const lines: string[] = []

    // Header
    lines.push('# AI Agent Session Report')
    lines.push('')
    lines.push(`**Date:** ${new Date().toLocaleString()}  `)
    lines.push(`**Phase:** ${PHASE_CONFIG[currentPhase].label}  `)
    if (iterationCount > 0) lines.push(`**Step:** ${iterationCount}  `)
    if (modelName) lines.push(`**Model:** ${formatModelDisplay(modelName)}  `)
    lines.push('')
    lines.push('---')
    lines.push('')

    // Todo list snapshot
    if (todoList.length > 0) {
      lines.push('## Task List')
      lines.push('')
      todoList.forEach((item: TodoItem) => {
        const icon = item.status === 'completed' ? '[x]' : item.status === 'in_progress' ? '[-]' : '[ ]'
        const desc = item.description || item.content || item.activeForm || 'No description'
        lines.push(`- ${icon} ${desc}`)
      })
      lines.push('')
      lines.push('---')
      lines.push('')
    }

    // Chat timeline
    lines.push('## Session Timeline')
    lines.push('')

    chatItems.forEach(item => {
      if ('role' in item) {
        // Message
        const time = item.timestamp.toLocaleTimeString()
        if (item.role === 'user') {
          lines.push(`### User  \`${time}\``)
          if (item.isGuidance) lines.push('> *[Guidance]*')
        } else {
          lines.push(`### Assistant  \`${time}\``)
          if (item.responseTier === 'full_report') lines.push('> **[Report]**')
          else if (item.responseTier === 'summary') lines.push('> **[Summary]**')
        }
        lines.push('')
        lines.push(item.content)
        lines.push('')
        if (item.error) {
          lines.push(`> **Error:** ${item.error}`)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'thinking') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Thinking  \`${time}\``)
        lines.push('')
        if (item.thought) {
          lines.push(`> ${item.thought}`)
          lines.push('')
        }
        if (item.reasoning) {
          lines.push('<details>')
          lines.push('<summary>Reasoning</summary>')
          lines.push('')
          lines.push(item.reasoning)
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        if (item.updated_todo_list && item.updated_todo_list.length > 0) {
          lines.push('<details>')
          lines.push('<summary>Todo List Update</summary>')
          lines.push('')
          item.updated_todo_list.forEach(todo => {
            const icon = todo.status === 'completed' ? '[x]' : todo.status === 'in_progress' ? '[-]' : '[ ]'
            const desc = todo.description || todo.content || todo.activeForm || ''
            lines.push(`- ${icon} ${desc}`)
          })
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'deep_think') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### Deep Think  \`${time}\``)
        lines.push('')
        lines.push(`> **Trigger:** ${item.trigger_reason}`)
        lines.push('')
        if (item.analysis) {
          lines.push(item.analysis)
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'tool_execution') {
        const time = item.timestamp.toLocaleTimeString()
        const statusIcon = item.status === 'success' ? 'OK' : item.status === 'error' ? 'FAIL' : 'RUNNING'
        lines.push(`### Tool: \`${item.tool_name}\`  \`${time}\`  [${statusIcon}]`)
        lines.push('')

        // Arguments
        if (item.tool_args && Object.keys(item.tool_args).length > 0) {
          lines.push('**Arguments**')
          lines.push('')
          Object.entries(item.tool_args).forEach(([key, value]) => {
            lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
          })
          lines.push('')
        }

        // Raw Output
        const rawOutput = item.output_chunks.join('')
        if (rawOutput) {
          lines.push('<details>')
          lines.push('<summary>Raw Output</summary>')
          lines.push('')
          lines.push('```')
          lines.push(rawOutput)
          lines.push('```')
          lines.push('')
          lines.push('</details>')
          lines.push('')
        }

        // Analysis
        if (item.final_output) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(item.final_output)
          lines.push('')
        }

        // Actionable Findings
        if (item.actionable_findings && item.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          item.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }

        // Recommended Next Steps
        if (item.recommended_next_steps && item.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          item.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }

        lines.push('---')
        lines.push('')
      } else if (item.type === 'plan_wave') {
        const waveItem = item as PlanWaveItem
        const time = waveItem.timestamp.toLocaleTimeString()
        const statusIcon = waveItem.status === 'success' ? 'OK' : waveItem.status === 'error' ? 'FAIL' : waveItem.status === 'partial' ? 'PARTIAL' : 'RUNNING'
        lines.push(`### Wave — ${waveItem.tool_count} tools  \`${time}\`  [${statusIcon}]`)
        lines.push('')
        if (waveItem.plan_rationale) {
          lines.push(`> ${waveItem.plan_rationale}`)
          lines.push('')
        }
        // Export each nested tool
        waveItem.tools.forEach(tool => {
          const toolStatusIcon = tool.status === 'success' ? 'OK' : tool.status === 'error' ? 'FAIL' : 'RUNNING'
          lines.push(`#### Tool: \`${tool.tool_name}\`  [${toolStatusIcon}]`)
          lines.push('')
          if (tool.tool_args && Object.keys(tool.tool_args).length > 0) {
            lines.push('**Arguments**')
            lines.push('')
            Object.entries(tool.tool_args).forEach(([key, value]) => {
              lines.push(`- **${key}:** \`${typeof value === 'string' ? value : JSON.stringify(value)}\``)
            })
            lines.push('')
          }
          const rawOutput = tool.output_chunks.join('')
          if (rawOutput) {
            lines.push('<details>')
            lines.push('<summary>Raw Output</summary>')
            lines.push('')
            lines.push('```')
            lines.push(rawOutput)
            lines.push('```')
            lines.push('')
            lines.push('</details>')
            lines.push('')
          }
          if (tool.final_output) {
            lines.push('**Analysis**')
            lines.push('')
            lines.push(tool.final_output)
            lines.push('')
          }
          if (tool.actionable_findings && tool.actionable_findings.length > 0) {
            lines.push('**Actionable Findings**')
            lines.push('')
            tool.actionable_findings.forEach(f => lines.push(`- ${f}`))
            lines.push('')
          }
          if (tool.recommended_next_steps && tool.recommended_next_steps.length > 0) {
            lines.push('**Recommended Next Steps**')
            lines.push('')
            tool.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
            lines.push('')
          }
        })
        // Wave-level analysis
        if (waveItem.interpretation) {
          lines.push('**Analysis**')
          lines.push('')
          lines.push(waveItem.interpretation)
          lines.push('')
        }
        if (waveItem.actionable_findings && waveItem.actionable_findings.length > 0) {
          lines.push('**Actionable Findings**')
          lines.push('')
          waveItem.actionable_findings.forEach(f => lines.push(`- ${f}`))
          lines.push('')
        }
        if (waveItem.recommended_next_steps && waveItem.recommended_next_steps.length > 0) {
          lines.push('**Recommended Next Steps**')
          lines.push('')
          waveItem.recommended_next_steps.forEach(s => lines.push(`- ${s}`))
          lines.push('')
        }
        lines.push('---')
        lines.push('')
      } else if (item.type === 'file_download') {
        const time = item.timestamp.toLocaleTimeString()
        lines.push(`### File Download  \`${time}\``)
        lines.push('')
        lines.push(`- **File:** ${item.filename}`)
        lines.push(`- **Path:** \`${item.filepath}\``)
        lines.push(`- **Source:** ${item.source}`)
        lines.push(`- **Description:** ${item.description}`)
        lines.push('')
        lines.push('---')
        lines.push('')
      }
    })

    // Download
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `redamon-session-${timestamp}.md`
    a.click()
    URL.revokeObjectURL(url)
  }, [chatItems, currentPhase, iterationCount, modelName, todoList])

  const handleNewChat = useCallback(() => {
    // Don't stop the running agent — let it continue in background
    // and persist messages via the backend persistence layer
    setChatItems([])
    setCurrentPhase('informational')
    setAttackPathType('')
    setIterationCount(0)
    setAwaitingApproval(false)
    setApprovalRequest(null)
    setAwaitingQuestion(false)
    setQuestionRequest(null)
    setAwaitingToolConfirmation(false)
    setToolConfirmationRequest(null)
    setAnswerText('')
    setSelectedOptions([])
    setTodoList([])
    setIsStopped(false)
    setIsLoading(false)
    awaitingApprovalRef.current = false
    isProcessingApproval.current = false
    awaitingQuestionRef.current = false
    isProcessingQuestion.current = false
    awaitingToolConfirmationRef.current = false
    isProcessingToolConfirmation.current = false
    shouldAutoScroll.current = true
    setConversationId(null)
    setShowHistory(false)
    onResetSession?.()
  }, [onResetSession])

  // Switch to a different conversation from history
  const handleSelectConversation = useCallback(async (conv: Conversation) => {
    const full = await loadConversation(conv.id)
    if (!full) return

    // Restore chat items from persisted messages
    let lastTodoList: TodoItem[] = []
    let lastApprovalRequest: any = null
    let lastQuestionRequest: any = null
    let lastToolConfirmationRequest: any = null
    let lastRenderedPhase: string = ''
    let lastAttackPathType: string = ''
    // Track whether the agent did actual WORK after the last approval/question/tool confirmation.
    // assistant_message doesn't count (it's the phase transition description that
    // arrives alongside the approval_request). Only thinking/tool_start indicate
    // the user already responded and the agent continued.
    let hasWorkAfterApproval = false
    let hasWorkAfterQuestion = false
    let hasWorkAfterToolConfirmation = false

    // --- Proper tool_start ↔ tool_complete pairing ---
    //
    // Step 1: Identify duplicate tool_starts AND tool_completes from stale
    //   re-emissions on resume.  For starts: same tool_name + tool_args within
    //   60s → duplicate.  For completes: same tool_name + raw_output[:500]
    //   within 60s → duplicate.  Keep the first, mark the rest for exclusion.
    const duplicateStartIds = new Set<string>()
    const duplicateCompleteIds = new Set<string>()
    {
      const recentStarts = new Map<string, number>()
      const recentCompletes = new Map<string, number>()
      for (const msg of full.messages) {
        const d = msg.data as any
        const t = new Date(msg.createdAt).getTime()
        if (msg.type === 'tool_start' && !d?.wave_id) {
          const fp = `${d?.tool_name || ''}::${JSON.stringify(d?.tool_args || {})}`
          const prev = recentStarts.get(fp)
          if (prev && t - prev < 60000) {
            duplicateStartIds.add(msg.id)
          } else {
            recentStarts.set(fp, t)
          }
        }
        if (msg.type === 'tool_complete' && !d?.wave_id) {
          const fp = `${d?.tool_name || ''}::${(d?.raw_output || '').slice(0, 500)}`
          const prev = recentCompletes.get(fp)
          if (prev && t - prev < 60000) {
            duplicateCompleteIds.add(msg.id)
          } else {
            recentCompletes.set(fp, t)
          }
        }
      }
    }

    // Step 2: Collect deduplicated standalone starts and completes.
    const standaloneStartsByName = new Map<string, { id: string; createdAt: string }[]>()
    const standaloneCompletesByName = new Map<string, { id: string; createdAt: string }[]>()
    for (const msg of full.messages) {
      const d = msg.data as any
      if (msg.type === 'tool_start' && !d?.wave_id && !duplicateStartIds.has(msg.id)) {
        const name = d?.tool_name || ''
        if (!standaloneStartsByName.has(name)) standaloneStartsByName.set(name, [])
        standaloneStartsByName.get(name)!.push({ id: msg.id, createdAt: msg.createdAt })
      }
      if (msg.type === 'tool_complete' && !d?.wave_id && !duplicateCompleteIds.has(msg.id)) {
        const name = d?.tool_name || ''
        if (!standaloneCompletesByName.has(name)) standaloneCompletesByName.set(name, [])
        standaloneCompletesByName.get(name)!.push({ id: msg.id, createdAt: msg.createdAt })
      }
    }

    // Step 3: Pair by position — Nth start ↔ Nth complete for each tool_name.
    const consumedStartIds = new Set<string>()        // tool_start IDs that have a matching complete
    const completeToStartTime = new Map<string, Date>() // complete.id → start.createdAt
    for (const [name, completes] of standaloneCompletesByName) {
      const starts = standaloneStartsByName.get(name) || []
      for (let i = 0; i < completes.length && i < starts.length; i++) {
        consumedStartIds.add(starts[i].id)
        completeToStartTime.set(completes[i].id, new Date(starts[i].createdAt))
      }
    }

    // Dedup sets — stale re-emissions on resume can persist duplicate
    // thinking messages at later sequenceNums.  Tool start/complete dedup
    // is handled by the pre-pass above (duplicateStartIds/duplicateCompleteIds).
    const seenThinkingKeys = new Set<string>()
    const seenRunningToolKeys = new Set<string>()

    const restored: ChatItem[] = full.messages.map((msg: { id: string; type: string; data: unknown; createdAt: string }) => {
      const data = msg.data as any

      // Track agent work after approval/question/tool confirmation requests
      if (msg.type === 'thinking' || msg.type === 'tool_start' || msg.type === 'tool_complete') {
        if (lastApprovalRequest) hasWorkAfterApproval = true
        if (lastQuestionRequest) hasWorkAfterQuestion = true
        if (lastToolConfirmationRequest) hasWorkAfterToolConfirmation = true
      }

      // Dedup thinking: skip if same thought text already seen
      if (msg.type === 'thinking') {
        const key = (data.thought || '').slice(0, 200)
        if (seenThinkingKeys.has(key)) return null
        seenThinkingKeys.add(key)
      }

      if (msg.type === 'user_message' || msg.type === 'assistant_message') {
        const restoredTier = data.response_tier || (data.task_complete ? 'full_report' : undefined)
        return {
          type: 'message',
          id: msg.id,
          role: msg.type === 'user_message' ? 'user' : 'assistant',
          content: data.content || '',
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
          isGuidance: data.isGuidance || false,
          isReport: restoredTier === 'full_report' || (!data.response_tier && (data.isReport || data.task_complete || false)),
          responseTier: restoredTier,
          error: data.error || null,
        } as Message
      } else if (msg.type === 'thinking') {
        return {
          type: 'thinking',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          thought: data.thought || '',
          reasoning: data.reasoning || '',
          action: 'thinking',
          updated_todo_list: [],
        } as ThinkingItem
      } else if (msg.type === 'tool_start') {
        // Skip wave-owned tool_start — they're nested via post-pass
        if (data.wave_id) return null
        // Skip duplicate starts (stale re-emissions identified in pre-pass)
        if (duplicateStartIds.has(msg.id)) return null
        // If this start is paired with a tool_complete, skip — the complete creates the card
        if (consumedStartIds.has(msg.id)) return null
        // Dedup remaining unpaired tool_starts by tool_name+args
        const runKey = `${data.tool_name || ''}::${JSON.stringify(data.tool_args || {})}`
        if (seenRunningToolKeys.has(runKey)) return null
        seenRunningToolKeys.add(runKey)
        // No matching tool_complete — tool was still running or never completed.
        // Show it as a running/incomplete tool card so it's not invisible.
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: 'running',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_complete') {
        // Skip wave-owned tool_complete — they're nested via post-pass
        if (data.wave_id) return null
        // Skip duplicate completes (stale re-emissions identified in pre-pass)
        if (duplicateCompleteIds.has(msg.id)) return null
        // Reconstruct full ToolExecutionItem with raw output and tool_args
        const rawOutput = data.raw_output || ''
        // Use positionally-paired tool_start for timestamp and duration
        const startTime = completeToStartTime.get(msg.id)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: data.success ? 'success' : 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
        } as ToolExecutionItem
      } else if (msg.type === 'error') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: 'An error occurred while processing your request.',
          error: data.message,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'task_complete') {
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: data.message || '',
          phase: data.final_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'guidance') {
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: data.content || '',
          isGuidance: true,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'file_ready') {
        return {
          type: 'file_download',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          filepath: data.filepath || '',
          filename: data.filename || '',
          description: data.description || '',
          source: data.source || '',
        } as FileDownloadItem
      } else if (msg.type === 'todo_update') {
        // Track last todo list for state restoration (not a chat item)
        lastTodoList = data.todo_list || []
        return null
      } else if (msg.type === 'phase_update') {
        // Track attack path type for state restoration
        if (data.attack_path_type) lastAttackPathType = data.attack_path_type
        // Only render when phase actually changes (avoid duplicate "Phase: informational" noise)
        const phase = data.current_phase || 'unknown'
        if (phase !== lastRenderedPhase) {
          lastRenderedPhase = phase
          return {
            type: 'message',
            id: msg.id,
            role: 'assistant',
            content: `**Phase:** ${phase}` + (data.iteration_count ? ` — Step ${data.iteration_count}` : ''),
            phase,
            timestamp: new Date(msg.createdAt),
          } as Message
        }
        return null
      } else if (msg.type === 'approval_request') {
        lastApprovalRequest = data
        hasWorkAfterApproval = false
        // Render as an assistant message so it appears in timeline and markdown
        const parts = [`**Phase Transition Request:** ${data.from_phase || '?'} → ${data.to_phase || '?'}`]
        if (data.reason) parts.push(`\n**Reason:** ${data.reason}`)
        if (data.planned_actions?.length) parts.push(`\n**Planned Actions:**\n${data.planned_actions.map((a: string) => `- ${a}`).join('\n')}`)
        if (data.risks?.length) parts.push(`\n**Risks:**\n${data.risks.map((r: string) => `- ${r}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: parts.join('\n'),
          phase: data.from_phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'approval_response') {
        // User's approval decision — render as a user message
        lastApprovalRequest = null
        hasWorkAfterApproval = true
        const label = data.decision === 'approve'
          ? 'Approved phase transition'
          : data.decision === 'modify'
          ? `Modified: ${data.modification || ''}`
          : 'Aborted phase transition'
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: label,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'question_request') {
        lastQuestionRequest = data
        hasWorkAfterQuestion = false
        // Render as an assistant message so it appears in timeline and markdown
        const qParts = [`**Agent Question:** ${data.question || ''}`]
        if (data.context) qParts.push(`\n> ${data.context}`)
        if (data.options?.length) qParts.push(`\n**Options:**\n${data.options.map((o: string) => `- ${o}`).join('\n')}`)
        return {
          type: 'message',
          id: msg.id,
          role: 'assistant',
          content: qParts.join('\n'),
          phase: data.phase,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'answer_response') {
        // User's answer to agent question — render as a user message
        lastQuestionRequest = null
        hasWorkAfterQuestion = true
        return {
          type: 'message',
          id: msg.id,
          role: 'user',
          content: `Answer: ${data.answer || ''}`,
          timestamp: new Date(msg.createdAt),
        } as Message
      } else if (msg.type === 'tool_confirmation_request') {
        lastToolConfirmationRequest = data
        hasWorkAfterToolConfirmation = false
        const confMode = data.mode || 'single'
        const confTools = data.tools || []
        if (confMode === 'plan') {
          return {
            type: 'plan_wave',
            id: msg.id,
            timestamp: new Date(msg.createdAt),
            wave_id: '',
            plan_rationale: data.reasoning || '',
            tool_count: confTools.length,
            tools: confTools.map((t: any, idx: number) => ({
              type: 'tool_execution' as const,
              id: `${msg.id}-tool-${idx}`,
              timestamp: new Date(msg.createdAt),
              tool_name: t.tool_name || '',
              tool_args: t.tool_args || {},
              status: 'pending_approval' as const,
              output_chunks: [],
            })),
            status: 'pending_approval',
          } as PlanWaveItem
        }
        const tool = confTools[0] || {}
        return {
          type: 'tool_execution',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          tool_name: tool.tool_name || '',
          tool_args: tool.tool_args || {},
          status: 'pending_approval',
          output_chunks: [],
        } as ToolExecutionItem
      } else if (msg.type === 'tool_confirmation_response') {
        lastToolConfirmationRequest = null
        hasWorkAfterToolConfirmation = true
        // Mark: post-process will update the preceding tool_confirmation item's status
        return { _toolConfResponse: true, decision: data.decision } as any
      } else if (msg.type === 'plan_start') {
        // Check if there's a pending_approval PlanWaveItem from tool_confirmation_request to reuse
        // If so, return a marker that the post-pass will use to update the existing wave
        return { _planStartLink: true, wave_id: data.wave_id || '', msg_id: msg.id, timestamp: new Date(msg.createdAt), plan_rationale: data.plan_rationale || '', tool_count: data.tool_count || 0 } as any
      } else if (msg.type === 'deep_think') {
        return {
          type: 'deep_think',
          id: msg.id,
          timestamp: new Date(msg.createdAt),
          trigger_reason: data.trigger_reason || '',
          analysis: data.analysis || '',
          iteration: data.iteration || 0,
          phase: data.phase || '',
        } as DeepThinkItem
      } else if (msg.type === 'plan_complete') {
        // Skip — we handle plan_complete as a post-pass below
        return null
      }
      // Skip unknown types
      return null
    }).filter((item): item is ChatItem => item !== null)

    // Post-pass: apply tool_confirmation_response decisions to preceding pending_approval items
    // Markers have { _toolConfResponse: true, decision: string } — find & update, then remove marker
    {
      const markers: number[] = []
      for (let i = 0; i < restored.length; i++) {
        const item = restored[i] as any
        if (item._toolConfResponse) {
          markers.push(i)
          for (let j = i - 1; j >= 0; j--) {
            const prev = restored[j] as any
            if (prev.status === 'pending_approval' && (prev.type === 'tool_execution' || prev.type === 'plan_wave')) {
              if (item.decision === 'approve') {
                if (prev.type === 'plan_wave') {
                  // Approved wave — clear pending tools, they'll be rebuilt from tool_complete
                  restored[j] = { ...prev, status: 'running', tools: [] }
                } else {
                  // Approved single tool — REMOVE the card entirely.
                  // The tool_complete message will create the definitive card
                  // with full output data.  Keeping this as 'running' would
                  // create a duplicate alongside the tool_complete card.
                  restored.splice(j, 1)
                  // Adjust marker indices since we removed an item before them
                  for (let m = 0; m < markers.length; m++) {
                    if (markers[m] > j) markers[m]--
                  }
                  i-- // current marker index shifted too
                }
              } else {
                restored[j] = { ...prev, status: 'error', final_output: 'Rejected by user' }
              }
              break
            }
          }
        }
      }
      for (let k = markers.length - 1; k >= 0; k--) {
        restored.splice(markers[k], 1)
      }
    }

    // Post-pass: link plan_start markers to existing PlanWaveItems (from tool_confirmation_request) or create new ones
    {
      const planStartMarkers: number[] = []
      for (let i = 0; i < restored.length; i++) {
        const item = restored[i] as any
        if (item._planStartLink) {
          planStartMarkers.push(i)
          // Find a preceding PlanWaveItem with empty wave_id (created from tool_confirmation_request)
          let linked = false
          for (let j = i - 1; j >= 0; j--) {
            const prev = restored[j] as any
            if (prev.type === 'plan_wave' && prev.wave_id === '') {
              restored[j] = {
                ...prev,
                wave_id: item.wave_id,
                plan_rationale: item.plan_rationale || prev.plan_rationale,
                tool_count: item.tool_count || prev.tool_count,
                status: prev.status === 'pending_approval' ? 'pending_approval' : 'running',
              }
              linked = true
              break
            }
          }
          if (!linked) {
            // No pending wave found — create a new PlanWaveItem in place
            restored[i] = {
              type: 'plan_wave',
              id: item.msg_id,
              timestamp: item.timestamp,
              wave_id: item.wave_id,
              plan_rationale: item.plan_rationale,
              tool_count: item.tool_count,
              tools: [],
              status: 'running',
            } as PlanWaveItem
            continue
          }
        }
      }
      for (let k = planStartMarkers.length - 1; k >= 0; k--) {
        if ((restored[planStartMarkers[k]] as any)._planStartLink) {
          restored.splice(planStartMarkers[k], 1)
        }
      }
    }

    // Post-pass: nest tool_complete items with wave_id into their PlanWaveItem containers
    // and apply plan_complete statuses (immutable updates — no direct mutation)
    // Build a lookup of tool_start timestamps by wave_id:tool_name:step_index for duration calc
    const waveToolStartTimes = new Map<string, Date>()
    for (const msg of full.messages) {
      if (msg.type === 'tool_start' && (msg.data as any)?.wave_id) {
        const d = msg.data as any
        const si = d.step_index ?? ''
        waveToolStartTimes.set(`${d.wave_id}:${d.tool_name}:${si}`, new Date(msg.createdAt))
      }
    }

    const waveToolCompletes = full.messages.filter(
      (m: any) => m.type === 'tool_complete' && (m.data as any)?.wave_id
    )
    for (const msg of waveToolCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        const rawOutput = data.raw_output || ''
        const si = data.step_index ?? ''
        const startTime = waveToolStartTimes.get(`${data.wave_id}:${data.tool_name}:${si}`)
        const completeTime = new Date(msg.createdAt)
        const duration = startTime ? completeTime.getTime() - startTime.getTime() : undefined
        const newTools = [...wave.tools, {
          type: 'tool_execution' as const,
          id: msg.id,
          timestamp: startTime || completeTime,
          tool_name: data.tool_name || '',
          tool_args: data.tool_args || {},
          status: (data.success ? 'success' : 'error') as 'success' | 'error',
          output_chunks: rawOutput ? [rawOutput] : [],
          final_output: data.output_summary,
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
          duration,
          step_index: data.step_index,
        }]
        restored[waveIdx] = {
          ...wave,
          tools: newTools,
          tool_count: Math.max(wave.tool_count, newTools.length),
        }
      }
    }

    // Apply plan_complete statuses (immutable)
    const planCompletes = full.messages.filter((m: any) => m.type === 'plan_complete')
    for (const msg of planCompletes) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        item => item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        let status: PlanWaveItem['status'] = 'success'
        if (data.failed === data.total_steps) {
          status = 'error'
        } else if (data.failed > 0) {
          status = 'partial'
        }
        restored[waveIdx] = { ...wave, status }
      }
    }

    // Apply plan_analysis data (immutable)
    const planAnalyses = full.messages.filter((m: any) => m.type === 'plan_analysis')
    for (const msg of planAnalyses) {
      const data = msg.data as any
      const waveIdx = restored.findIndex(
        (item: ChatItem) => 'type' in item && item.type === 'plan_wave' && (item as PlanWaveItem).wave_id === data.wave_id
      )
      if (waveIdx !== -1) {
        const wave = restored[waveIdx] as PlanWaveItem
        restored[waveIdx] = {
          ...wave,
          interpretation: data.interpretation || '',
          actionable_findings: data.actionable_findings || [],
          recommended_next_steps: data.recommended_next_steps || [],
        }
      }
    }

    // Sort by timestamp so items appear in chronological order regardless
    // of DB insertion order (sequenceNum).  Stable sort preserves the
    // original order for items that share the same timestamp.
    restored.sort((a: any, b: any) => {
      const ta = a.timestamp instanceof Date ? a.timestamp.getTime() : new Date(a.timestamp).getTime()
      const tb = b.timestamp instanceof Date ? b.timestamp.getTime() : new Date(b.timestamp).getTime()
      return ta - tb
    })

    const finalRestored = restored

    // Apply state
    setChatItems(finalRestored)
    setConversationId(conv.id)
    setCurrentPhase((conv.currentPhase || 'informational') as Phase)
    setAttackPathType(lastAttackPathType)
    setIterationCount(conv.iterationCount || 0)
    setIsLoading(conv.agentRunning)
    setIsStopped(false)
    setTodoList(lastTodoList)
    shouldAutoScroll.current = true
    setShowHistory(false)

    // Restore pending approval/question state if not yet acted upon.
    // The agent is NOT "running" while waiting — it finishes its task and waits
    // for the user to respond. So we check for agent work, not agentRunning.
    if (lastApprovalRequest && !hasWorkAfterApproval) {
      setAwaitingApproval(true)
      setApprovalRequest(lastApprovalRequest)
      awaitingApprovalRef.current = true
    } else {
      setAwaitingApproval(false)
      setApprovalRequest(null)
    }
    if (lastQuestionRequest && !hasWorkAfterQuestion) {
      setAwaitingQuestion(true)
      setQuestionRequest(lastQuestionRequest)
      awaitingQuestionRef.current = true
    } else {
      setAwaitingQuestion(false)
      setQuestionRequest(null)
    }
    if (lastToolConfirmationRequest && !hasWorkAfterToolConfirmation) {
      setAwaitingToolConfirmation(true)
      setToolConfirmationRequest(lastToolConfirmationRequest)
      awaitingToolConfirmationRef.current = true
      // Find the pending_approval inline card ID so approve/reject can update it
      const pendingTool = restored.findLast?.((item: any) => item.type === 'tool_execution' && item.status === 'pending_approval')
      const pendingWave = restored.findLast?.((item: any) => item.type === 'plan_wave' && item.status === 'pending_approval')
      if (pendingWave) {
        pendingApprovalWaveId.current = pendingWave.id
      } else if (pendingTool) {
        pendingApprovalToolId.current = pendingTool.id
      }
    } else {
      setAwaitingToolConfirmation(false)
      setToolConfirmationRequest(null)
    }

    // Switch WebSocket session — flag to prevent the sessionId useEffect from clearing state
    isRestoringConversation.current = true
    onSwitchSession?.(conv.sessionId)
  }, [loadConversation, onSwitchSession])

  const handleHistoryNewChat = () => {
    setShowHistory(false)
    handleNewChat()
  }

  const handleDeleteConversation = useCallback(async (id: string) => {
    await deleteConversation(id)
    onRefetchGraph?.()
    // If we just deleted the active conversation, reset to a clean state
    if (id === conversationId) {
      handleNewChat()
    }
  }, [deleteConversation, onRefetchGraph, conversationId, handleNewChat])

  const PhaseIcon = PHASE_CONFIG[currentPhase].icon

  // Connection status indicator with color
  const getConnectionStatusColor = () => {
    return status === ConnectionStatus.CONNECTED ? '#10b981' : '#ef4444' // green : red
  }

  const getConnectionStatusIcon = () => {
    const color = getConnectionStatusColor()
    if (status === ConnectionStatus.CONNECTED) {
      return <Wifi size={12} className={styles.connectionIcon} style={{ color }} />
    } else if (status === ConnectionStatus.RECONNECTING) {
      return <Loader2 size={12} className={`${styles.connectionIcon} ${styles.spinner}`} style={{ color }} />
    } else {
      return <WifiOff size={12} className={styles.connectionIcon} style={{ color }} />
    }
  }

  const getConnectionStatusText = () => {
    switch (status) {
      case ConnectionStatus.CONNECTING:
        return 'Connecting...'
      case ConnectionStatus.CONNECTED:
        return 'Connected'
      case ConnectionStatus.RECONNECTING:
        return `Reconnecting... (${reconnectAttempt}/5)`
      case ConnectionStatus.FAILED:
        return 'Connection failed'
      case ConnectionStatus.DISCONNECTED:
        return 'Disconnected'
    }
  }

  // Group timeline items by their sequence (between messages)
  const groupedChatItems: Array<{ type: 'message' | 'timeline' | 'file_download', content: Message | Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> | FileDownloadItem }> = []

  let currentTimelineGroup: Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem> = []

  chatItems.forEach((item) => {
    if ('role' in item) {
      // It's a message - push any accumulated timeline items first
      if (currentTimelineGroup.length > 0) {
        groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      // Then push the message
      groupedChatItems.push({ type: 'message', content: item })
    } else if ('type' in item && item.type === 'file_download') {
      // File download cards are standalone (not grouped into timeline)
      if (currentTimelineGroup.length > 0) {
        groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
        currentTimelineGroup = []
      }
      groupedChatItems.push({ type: 'file_download', content: item })
    } else if ('type' in item && (item.type === 'thinking' || item.type === 'tool_execution' || item.type === 'plan_wave' || item.type === 'deep_think')) {
      // It's a timeline item - add to current group
      currentTimelineGroup.push(item)
    }
  })

  // Push any remaining timeline items
  if (currentTimelineGroup.length > 0) {
    groupedChatItems.push({ type: 'timeline', content: currentTimelineGroup })
  }

  const handleCopyMessage = useCallback((messageId: string, content: string) => {
    navigator.clipboard.writeText(content).then(() => {
      setCopiedMessageId(messageId)
      setTimeout(() => setCopiedMessageId(null), 2000)
    })
  }, [])

  const handleCopyField = useCallback((key: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedFieldKey(key)
      setTimeout(() => setCopiedFieldKey(null), 2000)
    })
  }, [])

  const renderMessage = (item: Message) => {
    return (
      <div
        key={item.id}
        className={`${styles.message} ${
          item.role === 'user' ? styles.messageUser : styles.messageAssistant
        } ${item.isGuidance ? styles.messageGuidance : ''}`}
      >
        <div className={styles.messageIcon}>
          {item.role === 'user' ? <User size={14} /> : <Bot size={14} />}
        </div>
        <div className={styles.messageContent}>
          {item.isGuidance && (
            <span className={styles.guidanceBadge}>Guidance</span>
          )}
          {item.responseTier === 'full_report' && (
            <div className={styles.reportHeader}>
              <span className={styles.reportBadge}>Report</span>
            </div>
          )}
          {item.responseTier === 'summary' && (
            <div className={styles.reportHeader}>
              <span className={styles.summaryBadge}>Summary</span>
            </div>
          )}
          <div
            className={styles.messageText}
            {...(item.responseTier === 'full_report' || item.responseTier === 'summary' ? { 'data-report-content': true } : {})}
          >
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ className, children, ...props }: any) {
                  const match = /language-(\w+)/.exec(className || '')
                  const language = match ? match[1] : ''
                  const isInline = !className
                  const codeText = String(children).replace(/\n$/, '')

                  if (!isInline) {
                    const codeKey = `code-${item.id}-${codeText.slice(0, 20)}`
                    return (
                      <div className={styles.codeBlockWrapper}>
                        <button
                          className={`${styles.codeBlockCopyButton} ${copiedFieldKey === codeKey ? styles.codeBlockCopyButtonCopied : ''}`}
                          onClick={() => handleCopyField(codeKey, codeText)}
                          title="Copy code"
                        >
                          {copiedFieldKey === codeKey ? <Check size={11} /> : <Copy size={11} />}
                        </button>
                        {language ? (
                          <SyntaxHighlighter
                            style={vscDarkPlus as any}
                            language={language}
                            PreTag="div"
                          >
                            {codeText}
                          </SyntaxHighlighter>
                        ) : (
                          <pre><code className={className} {...props}>{children}</code></pre>
                        )}
                      </div>
                    )
                  }

                  return (
                    <code className={className} {...props}>
                      {children}
                    </code>
                  )
                },
                td({ children, ...props }: any) {
                  const text = extractTextFromChildren(children)
                  if (!text || text.length < 3) {
                    return <td {...props}>{children}</td>
                  }
                  const cellKey = `td-${item.id}-${text.slice(0, 30)}`
                  return (
                    <td {...props}>
                      <span className={styles.tableCellContent}>
                        {children}
                        <button
                          className={`${styles.tableCellCopyButton} ${copiedFieldKey === cellKey ? styles.tableCellCopyButtonCopied : ''}`}
                          onClick={() => handleCopyField(cellKey, text)}
                          title="Copy value"
                        >
                          {copiedFieldKey === cellKey ? <Check size={10} /> : <Copy size={10} />}
                        </button>
                      </span>
                    </td>
                  )
                },
              }}
            >
              {item.content}
            </ReactMarkdown>
          </div>

          {item.role === 'assistant' && !item.isGuidance && (
            <button
              className={`${styles.copyButton} ${copiedMessageId === item.id ? styles.copyButtonCopied : ''}`}
              onClick={() => handleCopyMessage(item.id, item.content)}
              title="Copy to clipboard"
            >
              {copiedMessageId === item.id ? <><Check size={12} /> Copied</> : <><Copy size={12} /> Copy</>}
            </button>
          )}

          {item.error && (
            <div className={styles.errorBadge}>
              <AlertCircle size={12} />
              <span>{item.error}</span>
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div
      className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}
      aria-hidden={!isOpen}
    >
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <div className={styles.headerIcon}>
            <Bot size={16} />
          </div>
          <div className={styles.headerText}>
            <h2 className={styles.title}>AI Agent</h2>
            <div className={styles.connectionStatus}>
              {getConnectionStatusIcon()}
              <span className={styles.subtitle} style={{ color: getConnectionStatusColor() }}>
                {getConnectionStatusText()}
              </span>
              <span className={styles.sessionCode} title={sessionId}>
                Session: {sessionId.slice(-8)}
              </span>
              {!requireToolConfirmation && (
                <Tooltip content="Tool confirmation is disabled. Dangerous tools will execute without manual approval.">
                  <div className={styles.dangerBadge}>
                    <AlertTriangle size={12} />
                    <span>Auto-exec</span>
                  </div>
                </Tooltip>
              )}
            </div>
          </div>
        </div>
        <div className={styles.headerActions}>
          {hasOtherChains && onToggleOtherChains && (
            <button
              className={`${styles.iconButton} ${isOtherChainsHidden ? styles.iconButtonActive : ''}`}
              onClick={onToggleOtherChains}
              title={isOtherChainsHidden ? 'Show all sessions in graph' : 'Show only this session in graph'}
              aria-label={isOtherChainsHidden ? 'Show all sessions in graph' : 'Show only this session in graph'}
            >
              {isOtherChainsHidden ? <Eye size={14} /> : <EyeOff size={14} />}
            </button>
          )}
          <button
            className={styles.iconButton}
            onClick={() => setShowHistory(!showHistory)}
            title="Session history"
            aria-label="Session history"
          >
            <History size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleNewChat}
            title="New session"
            aria-label="Start new session"
          >
            <Plus size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleDownloadMarkdown}
            title="Download chat as Markdown"
            aria-label="Download chat as Markdown"
            disabled={chatItems.length === 0}
          >
            <Download size={14} />
          </button>
          <button
            className={styles.closeButton}
            onClick={onClose}
            aria-label="Close assistant"
          >
            &times;
          </button>
        </div>
      </div>

      {/* Session History Panel */}
      {showHistory && (
        <ConversationHistory
          conversations={conversations}
          currentSessionId={sessionId}
          onBack={() => setShowHistory(false)}
          onSelect={handleSelectConversation}
          onDelete={handleDeleteConversation}
          onNewChat={handleHistoryNewChat}
        />
      )}

      {/* Phase Indicator */}
      <div className={styles.phaseIndicator}>
        <div
          className={styles.phaseBadge}
          style={{
            backgroundColor: PHASE_CONFIG[currentPhase].bgColor,
            borderColor: PHASE_CONFIG[currentPhase].color,
          }}
        >
          <PhaseIcon size={14} style={{ color: PHASE_CONFIG[currentPhase].color }} />
          <span style={{ color: PHASE_CONFIG[currentPhase].color }}>
            {PHASE_CONFIG[currentPhase].label}
          </span>
        </div>

        {/* Phase Tools Icon */}
        {toolPhaseMap && (() => {
          const phaseTools = Object.entries(toolPhaseMap)
            .filter(([, phases]) => phases.includes(currentPhase))
            .map(([name]) => name)
          return phaseTools.length > 0 ? (
            <Tooltip
              position="bottom"
              content={
                <div className={styles.phaseToolsTooltip}>
                  <div className={styles.phaseToolsHeader}>Phase Tools</div>
                  {phaseTools.map(t => (
                    <div key={t} className={styles.phaseToolsItem}>{t}</div>
                  ))}
                </div>
              }
            >
              <Wrench
                size={13}
                className={styles.phaseToolsIcon}
              />
            </Tooltip>
          ) : null
        })()}

        {/* Attack Skill Badge - Show in all phases once classified */}
        {attackPathType && (currentPhase === 'informational' || currentPhase === 'exploitation' || currentPhase === 'post_exploitation') && (
          <Tooltip
            position="bottom"
            content={
              <div className={styles.skillTooltip}>
                <div className={styles.skillTooltipHeader}>
                  <Swords size={11} />
                  Agent Skills
                </div>
                {skillData && (
                  <>
                    <div className={styles.skillTooltipGroup}>
                      <div className={styles.skillTooltipGroupLabel}>Built-in</div>
                      {skillData.builtIn.map(s => {
                        const enabled = skillData.config.builtIn[s.id] !== false
                        const isActive = attackPathType === s.id
                        return (
                          <div key={s.id} className={`${styles.skillTooltipItem} ${!enabled ? styles.skillTooltipItemDisabled : ''} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                            <span className={styles.skillTooltipName}>{s.name}</span>
                            {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                            {!enabled && <span className={styles.skillTooltipOff}>OFF</span>}
                          </div>
                        )
                      })}
                    </div>
                    {skillData.user.length > 0 && (
                      <div className={styles.skillTooltipGroup}>
                        <div className={styles.skillTooltipGroupLabel}>User Skills</div>
                        {skillData.user.map(s => {
                          const enabled = skillData.config.user[s.id] !== false
                          const isActive = attackPathType === `user_skill:${s.id}`
                          return (
                            <div key={s.id} className={`${styles.skillTooltipItem} ${!enabled ? styles.skillTooltipItemDisabled : ''} ${isActive ? styles.skillTooltipItemActive : ''}`}>
                              <span className={styles.skillTooltipName}>{s.name}</span>
                              {isActive && <Check size={11} className={styles.skillTooltipCheck} />}
                              {!enabled && <span className={styles.skillTooltipOff}>OFF</span>}
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </>
                )}
              </div>
            }
          >
            <div
              className={styles.phaseBadge}
              style={{
                backgroundColor: getAttackPathConfig(attackPathType).bgColor,
                borderColor: getAttackPathConfig(attackPathType).color,
              }}
            >
              <span style={{ color: getAttackPathConfig(attackPathType).color }}>
                {getAttackPathConfig(attackPathType).shortLabel}
              </span>
            </div>
          </Tooltip>
        )}

        {iterationCount > 0 && (
          <span className={styles.iterationCount}>Step {iterationCount}</span>
        )}

        {onToggleStealth ? (
          <button
            className={`${styles.stealthToggle} ${stealthMode ? styles.stealthToggleActive : ''}`}
            onClick={() => onToggleStealth(!stealthMode)}
            title={stealthMode
              ? 'Stealth Mode ON — click to disable'
              : 'Stealth Mode OFF — click to enable passive-only techniques'
            }
          >
            <StealthIcon size={11} />
          </button>
        ) : stealthMode ? (
          <span className={styles.stealthBadge} title="Stealth Mode — passive/low-noise techniques only">
            <StealthIcon size={11} />
          </span>
        ) : null}

        {onToggleDeepThink ? (
          <button
            className={`${styles.deepThinkToggle} ${deepThinkEnabled ? styles.deepThinkToggleActive : ''}`}
            onClick={() => onToggleDeepThink(!deepThinkEnabled)}
            title={deepThinkEnabled
              ? 'Deep Think ON — the agent performs strategic reasoning at key decision points (start, phase transitions, failure loops) before acting. Click to disable.'
              : 'Deep Think OFF — click to enable strategic reasoning at key decision points. Adds ~1 extra LLM call at start, phase transitions, and failure loops to plan multi-step strategies.'
            }
          >
            <Lightbulb size={11} />
          </button>
        ) : deepThinkEnabled ? (
          <span className={styles.deepThinkBadge} title="Deep Think — strategic reasoning at key decision points">
            <Lightbulb size={11} />
          </span>
        ) : null}

        {/* Settings dropdown */}
        <div className={styles.settingsWrapper} ref={settingsDropdownRef}>
          <button
            className={styles.settingsButton}
            onClick={() => setShowSettingsDropdown(prev => !prev)}
            title="Agent settings"
          >
            <Settings size={12} />
          </button>
          {showSettingsDropdown && (
            <div className={styles.settingsDropdown}>
              <button
                className={styles.settingsDropdownItem}
                onClick={() => { setSettingsModal('agent'); setShowSettingsDropdown(false) }}
              >
                Agent Behaviour
              </button>
              <button
                className={styles.settingsDropdownItem}
                onClick={() => { setSettingsModal('toolmatrix'); setShowSettingsDropdown(false) }}
              >
                Tool Matrix
              </button>
              <button
                className={styles.settingsDropdownItem}
                onClick={() => { setSettingsModal('attack'); setShowSettingsDropdown(false) }}
              >
                Agent Skills
              </button>
            </div>
          )}
        </div>

        {modelName && (
          <button className={styles.modelBadge} onClick={() => setShowModelModal(true)}>
            {formatModelDisplay(modelName)}
          </button>
        )}
      </div>

      {/* Settings Modal */}
      {settingsModal && (
        <div className={styles.settingsModalOverlay} onClick={() => setSettingsModal(null)}>
          <div className={styles.settingsModal} onClick={e => e.stopPropagation()}>
            <div className={styles.settingsModalHeader}>
              <h2 className={styles.settingsModalTitle}>
                {settingsModal === 'agent' ? 'Agent Behaviour' : settingsModal === 'toolmatrix' ? 'Tool Matrix' : 'Agent Skills'}
              </h2>
              <button className={styles.settingsModalClose} onClick={() => setSettingsModal(null)}>
                <X size={16} />
              </button>
            </div>
            <div className={styles.settingsModalBody}>
              {projectFormData ? (
                settingsModal === 'agent' ? (
                  <AgentBehaviourSection data={projectFormData} updateField={updateProjectField} />
                ) : settingsModal === 'toolmatrix' ? (
                  <ToolMatrixSection data={projectFormData} updateField={updateProjectField} />
                ) : (
                  <AttackSkillsSection data={projectFormData} updateField={updateProjectField} />
                )
              ) : (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
                  <Loader2 size={24} className={styles.spinner} />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Model Picker Modal */}
      {showModelModal && (
        <div className={styles.settingsModalOverlay} onClick={() => setShowModelModal(false)}>
          <div className={`${styles.settingsModal} ${styles.modelModal}`} onClick={e => e.stopPropagation()}>
            <div className={styles.settingsModalHeader}>
              <h2 className={styles.settingsModalTitle}>Change Model</h2>
              <button className={styles.settingsModalClose} onClick={() => setShowModelModal(false)}>
                <X size={16} />
              </button>
            </div>
            <div className={styles.modelModalBody}>
              <input
                ref={modelSearchRef}
                className={styles.modelModalSearch}
                type="text"
                value={modelSearch}
                onChange={(e) => setModelSearch(e.target.value)}
                placeholder="Search models..."
                onKeyDown={(e) => {
                  if (e.key === 'Escape') setShowModelModal(false)
                }}
              />
              <div className={styles.modelList}>
                {modelsLoading ? (
                  <div className={styles.modelListEmpty}>
                    <Loader2 size={16} className={styles.spinner} />
                    <span>Loading models...</span>
                  </div>
                ) : modelsError ? (
                  <div className={styles.modelListEmpty}>
                    <span>Failed to load models. Type a model ID manually:</span>
                    <input
                      className={styles.modelModalManualInput}
                      type="text"
                      value={modelName || ''}
                      onChange={(e) => onModelChange?.(e.target.value)}
                      placeholder="e.g. claude-opus-4-6, gpt-5.2, openrouter/meta-llama/llama-4-maverick"
                    />
                  </div>
                ) : Object.keys(filteredModels).length === 0 ? (
                  <div className={styles.modelListEmpty}>
                    {modelSearch ? `No models matching "${modelSearch}"` : 'No providers configured'}
                  </div>
                ) : (
                  Object.entries(filteredModels).map(([provider, models]) => (
                    <div key={provider} className={styles.modelListGroup}>
                      <div className={styles.modelListGroupHeader}>{provider}</div>
                      {models.map(model => (
                        <div
                          key={model.id}
                          className={`${styles.modelListOption} ${model.id === modelName ? styles.modelListOptionSelected : ''}`}
                          onClick={() => handleSelectModel(model.id)}
                        >
                          <div className={styles.modelListOptionMain}>
                            <span className={styles.modelListOptionName}>{model.name}</span>
                            {model.context_length && (
                              <span className={styles.modelListOptionCtx}>{formatContextLength(model.context_length)}</span>
                            )}
                          </div>
                          {model.description && (
                            <span className={styles.modelListOptionDesc}>{model.description}</span>
                          )}
                        </div>
                      ))}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Todo List Widget */}
      {todoList.length > 0 && (
        <div className={styles.todoWidgetContainer}>
          <TodoListWidget items={todoList} />
        </div>
      )}

      {/* Unified Chat (Messages + Timeline Items) */}
      <div className={styles.messages} ref={messagesContainerRef} onScroll={checkIfAtBottom}>
        {chatItems.length === 0 && (
          <div className={styles.emptyState}>
            <div className={styles.emptyIcon}>
              <img src="/logo.png" alt="RedAmon" width={72} height={72} style={{ objectFit: 'contain' }} />
            </div>
            <h3 className={styles.emptyTitle}>How can I help you?</h3>
            <p className={styles.emptyDescription}>
              Ask me about recon data, vulnerabilities, exploitation, or post-exploitation activities.
            </p>
            <div className={styles.templateGroups}>
              {/* Informational */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'informational' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'informational' ? null : 'informational')}
                  style={{ '--tg-color': 'var(--text-tertiary)' } as React.CSSProperties}
                >
                  <Shield size={14} />
                  <span>Informational</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'informational' && (
                  <div className={styles.templateGroupItems}>
                    {INFORMATIONAL_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openInfoSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenInfoSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openInfoSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>

              {/* Exploitation */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'exploitation' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'exploitation' ? null : 'exploitation')}
                  style={{ '--tg-color': 'var(--status-warning)' } as React.CSSProperties}
                >
                  <Target size={14} />
                  <span>Exploitation</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'exploitation' && (
                  <div className={styles.templateGroupItems}>
                    {EXPLOITATION_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openExploitSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenExploitSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openExploitSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>

              {/* Post-Exploitation */}
              <div className={styles.templateGroup}>
                <button
                  className={`${styles.templateGroupHeader} ${openTemplateGroup === 'post_exploitation' ? styles.templateGroupHeaderOpen : ''}`}
                  onClick={() => setOpenTemplateGroup((prev: string | null) => prev === 'post_exploitation' ? null : 'post_exploitation')}
                  style={{ '--tg-color': 'var(--status-error)' } as React.CSSProperties}
                >
                  <Zap size={14} />
                  <span>Post-Exploitation</span>
                  <ChevronDown size={14} className={styles.templateGroupChevron} />
                </button>
                {openTemplateGroup === 'post_exploitation' && (
                  <div className={styles.templateGroupItems}>
                    {POST_EXPLOITATION_GROUPS.map(group => (
                      <React.Fragment key={group.id}>
                        <button
                          className={`${styles.templateSubGroupHeader} ${openPostSubGroup === group.id ? styles.templateSubGroupHeaderOpen : ''}`}
                          onClick={() => setOpenPostSubGroup(prev => prev === group.id ? null : group.id)}
                        >
                          <span>{group.title}</span>
                          <ChevronDown size={12} className={styles.templateSubGroupChevron} />
                        </button>
                        {openPostSubGroup === group.id && (
                          <div className={styles.templateSubGroupItems}>
                            {group.items.map((section, i) => (
                              <React.Fragment key={i}>
                                {section.osLabel && <span className={styles.templateOsLabel}>{section.osLabel}</span>}
                                {section.suggestions.map((s, j) => (
                                  <button key={j} className={styles.suggestion} onClick={() => setInputValue(s.prompt)} disabled={!isConnected}>
                                    {s.label}
                                  </button>
                                ))}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Render messages and timeline items in chronological order */}
        {groupedChatItems.map((groupItem, index) => {
          if (groupItem.type === 'message') {
            return renderMessage(groupItem.content as Message)
          } else if (groupItem.type === 'file_download') {
            const file = groupItem.content as FileDownloadItem
            return (
              <FileDownloadCard
                key={file.id}
                filepath={file.filepath}
                filename={file.filename}
                description={file.description}
                source={file.source}
              />
            )
          } else {
            // Render timeline group
            const items = groupItem.content as Array<ThinkingItem | ToolExecutionItem | PlanWaveItem | DeepThinkItem>
            return (
              <AgentTimeline
                key={`timeline-${index}`}
                items={items}
                isStreaming={isLoading && index === groupedChatItems.length - 1}
                missingApiKeys={missingApiKeys}
                onAddApiKey={openApiKeyModal}
                onToolConfirmation={handleTimelineToolConfirmation}
                toolConfirmationDisabled={isLoading}
              />
            )
          }
        })}

        {isLoading && (
          <div className={`${styles.message} ${styles.messageAssistant}`}>
            <div className={`${styles.messageIcon} ${styles.loadingEyeIcon}`}>
              <div className={styles.eyeContainer}>
                <img src="/logo.png" alt="RedAmon" width={34} height={21} className={styles.loadingEye} ref={eyeRef} />
                <div className={styles.eyePupil} />
              </div>
            </div>
            <div className={styles.messageContent}>
              <div className={styles.loadingIndicator}>
                <span key={statusWord} className={styles.loadingWord}>{statusWord}</span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Approval Dialog */}
      {awaitingApproval && approvalRequest && (
        <div className={styles.approvalDialog}>
          <div className={styles.approvalHeader}>
            <AlertCircle size={16} />
            <span>Phase Transition Request</span>
          </div>
          <div className={styles.approvalContent}>
            <p className={styles.approvalTransition}>
              <span className={styles.approvalFrom}>{approvalRequest.from_phase}</span>
              <span className={styles.approvalArrow}>→</span>
              <span className={styles.approvalTo}>{approvalRequest.to_phase}</span>
            </p>

            <div className={styles.approvalDisclaimer}>
              <ShieldAlert size={16} className={styles.approvalDisclaimerIcon} />
              <p className={styles.approvalDisclaimerText}>
                This transition will enable <strong>active operations</strong> against the target.
                By approving, you confirm that you <strong>own the target</strong> or have{' '}
                <strong>explicit written permission</strong> from the owner.
                Unauthorized activity is illegal and may result in criminal penalties.
              </p>
            </div>

            <p className={styles.approvalReason}>{approvalRequest.reason}</p>

            {approvalRequest.planned_actions.length > 0 && (
              <div className={styles.approvalSection}>
                <strong>Planned Actions:</strong>
                <ul>
                  {approvalRequest.planned_actions.map((action, i) => (
                    <li key={i}>{action}</li>
                  ))}
                </ul>
              </div>
            )}

            {approvalRequest.risks.length > 0 && (
              <div className={styles.approvalSection}>
                <strong>Risks:</strong>
                <ul>
                  {approvalRequest.risks.map((risk, i) => (
                    <li key={i}>{risk}</li>
                  ))}
                </ul>
              </div>
            )}

            <textarea
              className={styles.modificationInput}
              placeholder="Optional: provide modification feedback..."
              value={modificationText}
              onChange={(e) => setModificationText(e.target.value)}
            />
          </div>
          <div className={styles.approvalActions}>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonApprove}`}
              onClick={() => handleApproval('approve')}
              disabled={isLoading}
            >
              Approve
            </button>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonModify}`}
              onClick={() => handleApproval('modify')}
              disabled={isLoading || !modificationText.trim()}
            >
              Modify
            </button>
            <button
              className={`${styles.approvalButton} ${styles.approvalButtonAbort}`}
              onClick={() => handleApproval('abort')}
              disabled={isLoading}
            >
              Abort
            </button>
          </div>
        </div>
      )}

      {/* Q&A Dialog */}
      {awaitingQuestion && questionRequest && (
        <div className={styles.questionDialog}>
          <div className={styles.questionHeader}>
            <HelpCircle size={16} />
            <span>Agent Question</span>
          </div>
          <div className={styles.questionContent}>
            <div className={styles.questionText}>
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  code({ className, children, ...props }: any) {
                    const match = /language-(\w+)/.exec(className || '')
                    const language = match ? match[1] : ''
                    const isInline = !className

                    return !isInline && language ? (
                      <SyntaxHighlighter
                        style={vscDarkPlus as any}
                        language={language}
                        PreTag="div"
                      >
                        {String(children).replace(/\n$/, '')}
                      </SyntaxHighlighter>
                    ) : (
                      <code className={className} {...props}>
                        {children}
                      </code>
                    )
                  }
                }}
              >
                {questionRequest.question}
              </ReactMarkdown>
            </div>
            {questionRequest.context && (
              <div className={styles.questionContext}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {questionRequest.context}
                </ReactMarkdown>
              </div>
            )}

            {questionRequest.format === 'text' && (
              <textarea
                className={styles.answerInput}
                placeholder={questionRequest.default_value || 'Type your answer...'}
                value={answerText}
                onChange={(e) => setAnswerText(e.target.value)}
              />
            )}

            {questionRequest.format === 'single_choice' && questionRequest.options.length > 0 && (
              <div className={styles.optionsList}>
                {questionRequest.options.map((option, i) => (
                  <label key={i} className={styles.optionRadio}>
                    <input
                      type="radio"
                      name="question-option"
                      value={option}
                      checked={selectedOptions[0] === option}
                      onChange={() => setSelectedOptions([option])}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            )}

            {questionRequest.format === 'multi_choice' && questionRequest.options.length > 0 && (
              <div className={styles.optionsList}>
                {questionRequest.options.map((option, i) => (
                  <label key={i} className={styles.optionCheckbox}>
                    <input
                      type="checkbox"
                      value={option}
                      checked={selectedOptions.includes(option)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedOptions([...selectedOptions, option])
                        } else {
                          setSelectedOptions(selectedOptions.filter(o => o !== option))
                        }
                      }}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </div>
            )}
          </div>
          <div className={styles.questionActions}>
            <button
              className={`${styles.answerButton} ${styles.answerButtonSubmit}`}
              onClick={handleAnswer}
              disabled={isLoading || (questionRequest.format === 'text' ? !answerText.trim() : selectedOptions.length === 0)}
            >
              Submit Answer
            </button>
          </div>
        </div>
      )}

      {/* Input */}
      <div className={styles.inputContainer}>
        <div className={styles.inputWrapper}>
          <textarea
            ref={inputRef}
            className={styles.input}
            value={inputValue}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder={
              !isConnected
                ? 'Connecting to agent...'
                : awaitingApproval
                ? 'Respond to the approval request above...'
                : awaitingQuestion
                ? 'Answer the question above...'
                : isStopped
                ? 'Agent stopped. Click resume to continue...'
                : isLoading
                ? 'Send guidance to the agent...'
                : 'Ask a question...'
            }
            rows={2}
            disabled={awaitingApproval || awaitingQuestion || awaitingToolConfirmation || !isConnected || isStopped}
          />
          <div className={styles.inputActions}>
            {(isLoading || isStopped || isStopping) && (
              <button
                className={`${styles.stopResumeButton} ${isStopped ? styles.resumeButton : styles.stopButton}`}
                onClick={isStopped ? handleResume : handleStop}
                disabled={isStopping}
                aria-label={isStopping ? 'Stopping...' : isStopped ? 'Resume agent' : 'Stop agent'}
                title={isStopping ? 'Stopping...' : isStopped ? 'Resume execution' : 'Stop execution'}
              >
                {isStopping ? <Loader2 size={13} className={styles.spinner} /> : isStopped ? <Play size={13} /> : <Square size={13} />}
              </button>
            )}
            <button
              className={styles.sendButton}
              onClick={handleSend}
              disabled={!inputValue.trim() || awaitingApproval || awaitingQuestion || awaitingToolConfirmation || !isConnected || isStopped}
              aria-label="Send message"
            >
              <Send size={13} />
            </button>
          </div>
        </div>
        <span className={styles.inputHint}>
          {isConnected
            ? isLoading
              ? 'Send guidance or stop the agent'
              : 'Press Enter to send, Shift+Enter for new line'
            : 'Waiting for connection...'}
        </span>
      </div>

      {/* API Key quick-add modal */}
      {apiKeyModal && API_KEY_INFO[apiKeyModal] && (
        <div className={styles.apiKeyOverlay} onClick={closeApiKeyModal}>
          <div className={styles.apiKeyModal} onClick={e => e.stopPropagation()}>
            <h3 className={styles.apiKeyModalTitle}>{API_KEY_INFO[apiKeyModal].label} API Key</h3>
            <div className="formGroup">
              <label className="formLabel">{API_KEY_INFO[apiKeyModal].label} API Key</label>
              <div className={styles.apiKeyInputWrapper}>
                <input
                  className="textInput"
                  type={apiKeyVisible ? 'text' : 'password'}
                  value={apiKeyValue}
                  onChange={e => setApiKeyValue(e.target.value)}
                  placeholder={`Enter ${API_KEY_INFO[apiKeyModal].label.toLowerCase()} API key`}
                  autoFocus
                />
                <button
                  className={styles.apiKeyToggle}
                  onClick={() => setApiKeyVisible(v => !v)}
                  type="button"
                >
                  {apiKeyVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <span className="formHint">
                {API_KEY_INFO[apiKeyModal].hint}
                {' — '}
                <a href={API_KEY_INFO[apiKeyModal].url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
                  Get API key
                </a>
              </span>
            </div>
            <div className={styles.apiKeyModalActions}>
              <button className="secondaryButton" onClick={closeApiKeyModal}>Cancel</button>
              <button
                className="primaryButton"
                disabled={!apiKeyValue.trim() || apiKeySaving}
                onClick={saveApiKey}
              >
                {apiKeySaving ? <Loader2 size={14} className={styles.spinner} /> : null}
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
