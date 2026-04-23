/**
 * Fields excluded from user project presets.
 * Target-identity fields, binary data, and file references are stripped.
 */
export const PRESET_EXCLUDED_FIELDS = new Set([
  // Target-specific (user-requested exclusions)
  'targetDomain',
  'subdomainList',
  'ipMode',
  'targetIps',
  // Project identity
  'name',
  'description',
  // Binary / file-tied
  'roeDocumentData',
  'roeDocumentName',
  'roeDocumentMimeType',
  'jsReconUploadedFiles',
])

/**
 * Extract preset-safe settings from form data by stripping excluded fields.
 */
export function extractPresetSettings(
  formData: Record<string, unknown>
): Record<string, unknown> {
  const settings: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(formData)) {
    if (!PRESET_EXCLUDED_FIELDS.has(key)) {
      settings[key] = value
    }
  }
  return settings
}
