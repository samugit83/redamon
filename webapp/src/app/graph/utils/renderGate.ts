/**
 * The "Render" switch on the /graph toolbar.
 *
 * Turning it off is not a cosmetic hide: on a project big enough to bog the tab
 * down, the /api/graph read is itself the expensive half, so the off state has
 * to stop the fetch, not just skip the canvas. These two helpers are the whole
 * decision, kept pure so the rule is testable without mounting the page.
 */

export interface GraphRenderGateInput {
  /** Still fetching the saved per-project preference. */
  prefsLoading: boolean
  /** The persisted switch value (defaults to on when never set). */
  renderEnabled: boolean
  /** Which tab is on screen: only the graph map renders a force layout. */
  activeView: string
}

/** True when the map area should show the "rendering is off" panel. */
export function isGraphRenderOff({ prefsLoading, renderEnabled }: GraphRenderGateInput): boolean {
  return !prefsLoading && !renderEnabled
}

/**
 * True when the graph payload may be fetched.
 *
 * Two rules that are easy to get backwards:
 * - while prefs are loading, nothing is fetched. Treating "not loaded yet" as on
 *   would fire the exact query the user switched off, every single page load.
 * - the suppression is scoped to the graph map. Node Inspector, All Nodes and
 *   the analytics panels read the same payload, and the off-state message sends
 *   the user to them, so any other view still fetches normally.
 */
export function shouldFetchGraph({ prefsLoading, renderEnabled, activeView }: GraphRenderGateInput): boolean {
  if (prefsLoading) return false
  return renderEnabled || activeView !== 'graph'
}
