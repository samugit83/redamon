/**
 * The catalogue of scanner credentials that live in Global Settings.
 *
 * These fields are rendered in two very different places: the canonical API Keys
 * tab, and the inline "shortcut" input each scan section shows when its key is
 * missing. Both read from here, so a key cannot acquire one label in Settings
 * and a different one on the scan card, and a key added to a source registry
 * without a description here fails a parity test rather than rendering blank.
 *
 * Every `name` is a UserSettings column and MUST also appear in the writable
 * `fields` list in api/users/[id]/settings/route.ts. A name missing there is
 * accepted by the form and silently never persisted.
 */

import {
  TRUFFLEHOG_SOURCES,
  trufflehogCredentialRequirement,
  type CredentialRequirement,
} from './trufflehogSources'

export interface CredentialField {
  /** The UserSettings column, camelCase. */
  name: string
  label: string
  hint: string
  signupUrl?: string
  /**
   * Masked on read and rendered behind a reveal toggle. False for plain
   * configuration values (a hostname) that are not credentials.
   */
  secret?: boolean
  /** The group this key is rendered under in Global Settings. */
  source?: string
  /** Overrides the generic "Enter <label>" placeholder where a sample value
   *  says more than the label repeated (a hostname, an id format). */
  placeholder?: string
}

/** TruffleHog's per-source keys. `source` is the source id it belongs to. */
export const TRUFFLEHOG_KEY_FIELDS: (CredentialField & { source: string })[] = [
  {
    name: 'trufflehogGithubToken', label: 'Secret Multiscanner GitHub Token', source: 'github',
    signupUrl: 'https://github.com/settings/tokens',
    hint: 'Mandatory for the GitHub and GitHub-deleted-commits sources — even for public repos, because unauthenticated GitHub allows only 60 requests/hour, which this scan exhausts immediately. Use repo scope for private repositories.',
  },
  {
    name: 'trufflehogGitlabToken', label: 'Secret Multiscanner GitLab Token', source: 'gitlab',
    signupUrl: 'https://gitlab.com/-/user_settings/personal_access_tokens',
    hint: 'Mandatory for the GitLab source. With no repository or group set, it scans every project the token can reach.',
  },
  {
    name: 'trufflehogPostmanToken', label: 'Secret Multiscanner Postman Token', source: 'postman',
    hint: 'Mandatory for the Postman source.',
  },
  {
    name: 'trufflehogCircleciToken', label: 'Secret Multiscanner CircleCI Token', source: 'circleci',
    hint: 'Mandatory for the CircleCI source; the token defines the scan scope.',
  },
  {
    name: 'trufflehogTravisciToken', label: 'Secret Multiscanner Travis CI Token', source: 'travisci',
    hint: 'Mandatory for the Travis CI source; the token defines the scan scope.',
  },
  {
    name: 'trufflehogDockerToken', label: 'Secret Multiscanner Docker Token', source: 'docker',
    signupUrl: 'https://app.docker.com/settings/personal-access-tokens',
    hint: 'Optional for a single public image. Mandatory for a namespace scan: Docker Hub allows only 10 anonymous pulls/hour per IP, which a namespace scan exhausts at once. Used as both the bearer and the registry token.',
  },
  {
    name: 'trufflehogAwsAccessKeyId', label: 'Secret Multiscanner AWS Access Key ID', source: 's3',
    hint: "Mandatory for the S3 source unless 'Use cloud environment IAM' is enabled on the scan.",
  },
  {
    name: 'trufflehogAwsSecretKey', label: 'Secret Multiscanner AWS Secret Key', source: 's3',
    hint: "Mandatory for the S3 source unless 'Use cloud environment IAM' is enabled on the scan.",
  },
  {
    name: 'trufflehogAwsSessionToken', label: 'Secret Multiscanner AWS Session Token', source: 's3',
    hint: 'Optional. Only for temporary (STS) credentials.',
  },
  {
    name: 'trufflehogGcpServiceAccount', label: 'Secret Multiscanner GCP Service Account (JSON)', source: 'gcs',
    hint: "Mandatory for the GCS source unless 'Without auth' (public buckets) is enabled. Paste the service-account JSON.",
  },
  {
    name: 'trufflehogHuggingfaceToken', label: 'Secret Multiscanner Hugging Face Token', source: 'huggingface',
    signupUrl: 'https://huggingface.co/settings/tokens',
    hint: 'Optional. Public models, spaces and datasets scan without it; set it for private or gated assets, or for higher rate limits.',
  },
  {
    name: 'trufflehogJenkinsUsername', label: 'Secret Multiscanner Jenkins Username', source: 'jenkins',
    hint: 'Optional. An exposed, unauthenticated Jenkins scans without it (and is itself a finding). Set both username and password for an instance behind a login.',
  },
  {
    name: 'trufflehogJenkinsPassword', label: 'Secret Multiscanner Jenkins Password', source: 'jenkins',
    hint: 'Optional. Pairs with the Jenkins username above.',
  },
  {
    name: 'trufflehogElasticUsername', label: 'Secret Multiscanner Elasticsearch Username', source: 'elasticsearch',
    hint: 'Optional. An exposed cluster scans without it. If secured, provide exactly ONE of: username+password, API key, or service token.',
  },
  {
    name: 'trufflehogElasticPassword', label: 'Secret Multiscanner Elasticsearch Password', source: 'elasticsearch',
    hint: 'Optional. Pairs with the Elasticsearch username above.',
  },
  {
    name: 'trufflehogElasticApiKey', label: 'Secret Multiscanner Elasticsearch API Key', source: 'elasticsearch',
    hint: 'Optional. Use INSTEAD of username+password or a service token, not alongside them.',
  },
  {
    name: 'trufflehogElasticServiceToken', label: 'Secret Multiscanner Elasticsearch Service Token', source: 'elasticsearch',
    hint: 'Optional. Use INSTEAD of username+password or an API key, not alongside them.',
  },
  {
    name: 'trufflehogGitUsername', label: 'Secret Multiscanner Git Username', source: 'git',
    hint: 'Optional. Public Git URLs clone anonymously. Set both username and token only to reach a private repository over HTTPS.',
  },
  {
    name: 'trufflehogGitToken', label: 'Secret Multiscanner Git Token', source: 'git',
    hint: 'Optional. Pairs with the Git username above.',
  },
]

/**
 * The github.com and GitHub Enterprise credentials, one per consumer.
 *
 * Secret Hunt and Supply Chain each hold their own github.com PAT: they scan a
 * different set of repositories, and an operator has to be able to scope them
 * differently or revoke one without stopping the other. The Enterprise PAT is
 * deliberately NOT split the same way - it is one credential for one server,
 * and its whole point is that it never leaves that server.
 */
export const SHARED_SCANNER_KEY_FIELDS: CredentialField[] = [
  {
    name: 'githubAccessToken', label: 'GitHub Secret Hunt Token', source: 'github-secret-hunt',
    signupUrl: 'https://github.com/settings/tokens',
    hint: 'Required for GitHub Secret Hunt, which searches public GitHub for secrets mentioning your target. Also used by Tradecraft Lookup to fetch a resource from GitHub. A read-only token is enough; unauthenticated GitHub search is rate-limited to the point of being unusable. Also used by Workspace URL import, to import private GitHub repositories and to lift GitHub\'s limit of 60 requests an hour for unauthenticated use.',
  },
  {
    name: 'supplyChainGithubToken', label: 'Supply Chain GitHub Token', source: 'supply-chain',
    signupUrl: 'https://github.com/settings/tokens',
    hint: 'Only for Supply Chain scans of a PRIVATE repository - public repos clone anonymously. Use repo scope, or a fine-grained token limited to the repositories you are allowed to scan. For a repo on your own GitHub Enterprise server, the Enterprise token below is used instead.',
  },
  {
    name: 'githubEnterpriseHost', label: 'GitHub Enterprise Host', secret: false,
    source: 'github-enterprise', placeholder: 'ghe.example.com',
    hint: 'Optional. A self-hosted or custom-domain GitHub Enterprise server, hostname only (no https://, port or path). This is also the allowlist: a Supply Chain target may name this host and github.com, nothing else.',
  },
  {
    name: 'githubEnterpriseToken', label: 'GitHub Enterprise Token',
    source: 'github-enterprise',
    hint: 'The PAT for the host above. Kept separate from both github.com tokens on purpose: an Enterprise credential is never sent to github.com, and a github.com credential is never sent to an internal server.',
  },
]

const ALL_FIELDS: CredentialField[] = [...TRUFFLEHOG_KEY_FIELDS, ...SHARED_SCANNER_KEY_FIELDS]

const BY_NAME: Record<string, CredentialField> = Object.fromEntries(
  ALL_FIELDS.map(f => [f.name, f]),
)

/** Every credential this app can prompt for inline. */
export const CREDENTIAL_FIELD_NAMES = ALL_FIELDS.map(f => f.name)

/**
 * Look a credential up by its UserSettings column. Returns undefined for an
 * unknown key so a caller can decide between rendering nothing and throwing;
 * the parity test is what makes an unknown key a build-time problem instead.
 */
export function credentialField(name: string): CredentialField | undefined {
  return BY_NAME[name]
}

/** A field is a masked secret unless it explicitly opts out. */
export function isSecretField(name: string): boolean {
  return credentialField(name)?.secret !== false
}

/**
 * The label with the scanner name taken off the front.
 *
 * The stored label has to name its scanner, because the inline shortcut renders
 * it inside a project form where nothing else says which scanner wants the key.
 * Under a header that already says "Secret Multiscanner", repeating it 19 times
 * is the noise the grouping exists to remove.
 */
export function shortCredentialLabel(label: string): string {
  return label.replace(/^Secret Multiscanner /, '')
}

export interface KeyGroupSpec {
  /** Group id, also the anchor: `<drawer id>-<source>`. */
  source: string
  label: string
  /** Other sources reading the same keys - the GitHub token feeds two. */
  alsoUsedBy: string[]
  /** The strongest requirement in the group, which is what the header shows. */
  requirement: CredentialRequirement
  fields: (CredentialField & { requirement: CredentialRequirement })[]
}

const REQUIREMENT_RANK: Record<CredentialRequirement, number> = {
  required: 2, conditional: 1, optional: 0,
}

/**
 * The Secret Multiscanner keys grouped by the source they authenticate.
 *
 * Order follows TRUFFLEHOG_KEY_FIELDS, which is deliberate: the keys that block
 * a scan outright are declared first and so stay at the top of the drawer.
 */
export function trufflehogKeyGroups(): KeyGroupSpec[] {
  const groups = new Map<string, KeyGroupSpec>()

  for (const field of TRUFFLEHOG_KEY_FIELDS) {
    const requirement = trufflehogCredentialRequirement(field.name)
    let group = groups.get(field.source)
    if (!group) {
      group = {
        source: field.source,
        label: TRUFFLEHOG_SOURCES[field.source]?.label ?? field.source,
        alsoUsedBy: [],
        requirement: 'optional',
        fields: [],
      }
      groups.set(field.source, group)
    }
    group.fields.push({ ...field, requirement })
    if (REQUIREMENT_RANK[requirement] > REQUIREMENT_RANK[group.requirement]) {
      group.requirement = requirement
    }
  }

  for (const group of groups.values()) {
    const keys = new Set(group.fields.map(f => f.name))
    group.alsoUsedBy = Object.values(TRUFFLEHOG_SOURCES)
      .filter(s => s.id !== group.source && s.credentials.some(c => keys.has(c.settingsKey)))
      .map(s => s.label)
  }

  return [...groups.values()]
}

/**
 * The github.com / GitHub Enterprise keys, grouped by what consumes them.
 *
 * Static rather than derived: unlike a Secret Multiscanner source, no registry
 * declares these, and the requirement of each is a property of the scanner that
 * reads it. Secret Hunt cannot run at all without its token; Supply Chain only
 * needs one for a private repository.
 */
const GITHUB_GROUPS: { source: string; label: string; requirement: CredentialRequirement }[] = [
  { source: 'github-secret-hunt', label: 'GitHub Secret Hunt', requirement: 'required' },
  { source: 'supply-chain', label: 'Supply Chain', requirement: 'conditional' },
  { source: 'github-enterprise', label: 'GitHub Enterprise', requirement: 'optional' },
]

export function githubKeyGroups(): KeyGroupSpec[] {
  return GITHUB_GROUPS.map(spec => ({
    ...spec,
    alsoUsedBy: [],
    fields: SHARED_SCANNER_KEY_FIELDS
      .filter(f => f.source === spec.source)
      .map(f => ({ ...f, requirement: spec.requirement })),
  }))
}
