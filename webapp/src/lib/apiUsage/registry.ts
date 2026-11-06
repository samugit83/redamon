/**
 * Every credential the report knows, in the order the settings page shows it.
 * registry.drift.test.ts fails when a key field, a Secret Multiscanner
 * credential, an LLM provider type or a rotation tool is added without a probe
 * here, a companion slot, or a NOT_PROBED reason: a new key must never be
 * silently left out of the report.
 */
import type { ProbeDef } from './types'
import { githubEnterpriseProbe, githubHuntProbe, githubMultiscannerProbe, githubSupplyChainProbe } from './providers/github'
import { tavilyProbe } from './providers/tavily'
import { shodanProbe } from './providers/shodan'
import { serpapiProbe } from './providers/serpapi'
import { wpscanProbe } from './providers/wpscan'
import { pdcpProbe } from './providers/pdcp'
import { nvdProbe } from './providers/nvd'
import { vulnersProbe } from './providers/vulners'
import { urlscanProbe } from './providers/urlscan'
import { censysProbe } from './providers/censys'
import { fofaProbe } from './providers/fofa'
import { otxProbe } from './providers/otx'
import { netlasProbe } from './providers/netlas'
import { virustotalProbe } from './providers/virustotal'
import { zoomeyeProbe } from './providers/zoomeye'
import { criminalipProbe } from './providers/criminalip'
import { securitytrailsProbe } from './providers/securitytrails'
import { viewdnsProbe } from './providers/viewdns'
import { quakeProbe } from './providers/quake'
import { qianxinHunterProbe } from './providers/qianxinHunter'
import { publicwwwProbe } from './providers/publicwww'
import { onypheProbe } from './providers/onyphe'
import { driftnetProbe } from './providers/driftnet'
import {
  chiselProbe, dockerHubProbe, elasticsearchProbe, gitProbe, googleCseProbe, hunterHowProbe, jenkinsProbe, ngrokProbe,
} from './providers/notChecked'
import { gitlabProbe } from './providers/sources/gitlab'
import { postmanProbe } from './providers/sources/postman'
import { circleciProbe } from './providers/sources/circleci'
import { travisciProbe } from './providers/sources/travis'
import { awsProbe } from './providers/sources/awsSts'
import { gcpProbe } from './providers/sources/gcpServiceAccount'
import { huggingfaceProbe } from './providers/sources/huggingface'
import { openrouterProbe, jevOpenrouterProbe } from './providers/llm/openrouter'
import { deepseekProbe } from './providers/llm/deepseek'
import { kimiProbe } from './providers/llm/moonshot'
import { xaiProbe } from './providers/llm/xai'
import { anthropicProbe, geminiProbe, glmProbe, mistralProbe, openaiProbe, qwenProbe } from './providers/llm/validity'
import { openaiCompatibleProbe } from './providers/llm/openaiCompatible'
import { jevProbe } from './providers/llm/jev'
import { bedrockProbe } from './providers/llm/bedrock'

export const PROBES: readonly ProbeDef[] = [
  // GitHub & Supply Chain drawer
  githubHuntProbe,
  githubSupplyChainProbe,
  githubEnterpriseProbe,
  // Secret Multiscanner drawer, in TRUFFLEHOG_KEY_FIELDS order
  githubMultiscannerProbe,
  gitlabProbe,
  postmanProbe,
  circleciProbe,
  travisciProbe,
  dockerHubProbe,
  awsProbe,
  gcpProbe,
  huggingfaceProbe,
  jenkinsProbe,
  elasticsearchProbe,
  gitProbe,
  // API keys
  tavilyProbe,
  shodanProbe,
  serpapiProbe,
  wpscanProbe,
  pdcpProbe,
  nvdProbe,
  vulnersProbe,
  urlscanProbe,
  censysProbe,
  fofaProbe,
  otxProbe,
  netlasProbe,
  virustotalProbe,
  zoomeyeProbe,
  criminalipProbe,
  securitytrailsProbe,
  viewdnsProbe,
  // Uncover
  quakeProbe,
  qianxinHunterProbe,
  publicwwwProbe,
  hunterHowProbe,
  googleCseProbe,
  onypheProbe,
  driftnetProbe,
  // Tunneling
  ngrokProbe,
  chiselProbe,
]

/** One probe per UserLlmProvider.providerType. */
export const LLM_PROBES: Readonly<Record<string, ProbeDef>> = {
  openai: openaiProbe,
  anthropic: anthropicProbe,
  openrouter: openrouterProbe,
  deepseek: deepseekProbe,
  gemini: geminiProbe,
  glm: glmProbe,
  kimi: kimiProbe,
  qwen: qwenProbe,
  xai: xaiProbe,
  mistral: mistralProbe,
  bedrock: bedrockProbe,
  openai_compatible: openaiCompatibleProbe,
  jev: jevProbe,
  jev_openrouter: jevOpenrouterProbe,
}

/**
 * Settings fields that are deliberately nobody's key, and why. Companion fields
 * (censysOrgId, googleApiCx, githubEnterpriseHost, ...) are claimed by their
 * probe instead. Empty today: every stored credential has a probe.
 */
export const NOT_PROBED: Readonly<Record<string, string>> = {
  jsmonApiKey: 'subdomains.jsmon.sh has no usage/account endpoint; validity is tested on the first scan query',
}
