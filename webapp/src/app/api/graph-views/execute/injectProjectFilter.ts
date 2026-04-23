/**
 * Inject project_id filter into all node patterns in a Cypher query.
 *
 * Extracted as a standalone function for testability.
 */

// Global node types that exist across all projects (no project_id property).
// These are enrichment/reference data from public databases (NVD, MITRE, CAPEC).
const GLOBAL_LABELS = new Set([
  'CVE',
  'MitreData',
  'Capec',
  'ExploitGvm',
])

/**
 * Inject project_id filter into all node patterns.
 * Converts (v:Label) -> (v:Label {project_id: $projectId})
 * and (v:Label {key: val}) -> (v:Label {project_id: $projectId, key: val})
 *
 * Skips global labels (CVE, MitreData, Capec, ExploitGvm) that don't have project_id.
 */
export function injectProjectFilter(cypher: string): string {
  const filterProp = 'project_id: $projectId'

  return cypher.replace(
    /\((\w+):(\w+)(?:\s*\{([^}]*)\})?\)/g,
    (_match, varName, label, existingProps) => {
      if (GLOBAL_LABELS.has(label)) {
        return existingProps != null
          ? `(${varName}:${label} {${existingProps.trim()}})`
          : `(${varName}:${label})`
      }

      if (existingProps != null && existingProps.trim()) {
        return `(${varName}:${label} {${filterProp}, ${existingProps.trim()}})`
      }
      return `(${varName}:${label} {${filterProp}})`
    }
  )
}
