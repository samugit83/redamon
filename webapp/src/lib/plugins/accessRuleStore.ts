/**
 * Where the per-plugin allowlist rules live (GV-16): one `{pluginId, setId}` per permission set a
 * plugin is limited to. `pluginId` is the catalog id and `setId` a permission set row id or a
 * built-in id (`builtin:<slug>`), neither a foreign key: a plugin uninstalled keeps its rules for a
 * reinstall, and built-in sets are code.
 *
 * The `PluginAccessRule` table is not in the schema yet. Until it is, no plugin has a rule, so
 * every plugin stays available to everyone holding plugins:use, as before the allowlists.
 */
export interface PluginAccessRule {
  pluginId: string
  setId: string
}

/** The rules of one plugin, or of every plugin when `pluginId` is left out. A failed read throws. */
export async function readAccessRules(pluginId?: string): Promise<PluginAccessRule[]> {
  void pluginId
  return []
}
