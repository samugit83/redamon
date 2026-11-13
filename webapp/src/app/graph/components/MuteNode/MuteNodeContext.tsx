'use client'

/**
 * What every Mute button on the graph page shares, provided once by the page
 * so the node drawer and ~20 tables need no extra props.
 *
 * `epoch` is how a table learns a mute happened: muted nodes are filtered out
 * server-side by every table route (`notMuted`), so refetching on a new epoch
 * is what removes the row.
 *
 * The provider also owns the one Multi mute modal on the page: every Multi
 * mute button opens it through `openMultiMute`, and opening it again replaces
 * (and so supersedes) the one before.
 */
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { muteableLabel, muteKey } from '@/lib/muteTarget'
import { useOptionalProject } from '@/providers/ProjectProvider'
import type { GraphNode } from '../../types'
import type { MutedNodesFocus } from '../MutedNodes/mutedNodes'
import { formatNodeId } from '../RedZoneTables/nodeId'
import { MuteButton } from './MuteButton'
import { MultiMuteButton } from './MultiMuteButton'
import { MultiMuteModal } from './MultiMuteModal'
import type { MultiMuteOptions, MultiMuteSeed } from './multiMuteModel'
import { useMuteNode } from './useMuteNode'
import styles from './MuteButton.module.css'

interface MuteNodeContextValue {
  projectId: string | null
  /** Whose models Multi mute reads and saves. */
  userId: string | null
  /** A saved version is a read-only snapshot, so nothing on it may be muted. */
  readOnly: boolean
  /** Why, when it is not the saved version (a read share: "Read access, shared by <owner>"). */
  readOnlyReason?: string
  /** Open Muted Nodes, optionally filtered (one Multi mute batch). */
  onViewMuted?: (focus?: MutedNodesFocus) => void
  /** Bumped after every mute and every stale-node reload. */
  epoch: number
  /** Refresh the graph and every table after a mute. */
  notifyMuted: () => void
  openMultiMute: (seed: MultiMuteSeed, options?: MultiMuteOptions) => void
}

const MuteNodeContext = createContext<MuteNodeContextValue>({
  projectId: null,
  userId: null,
  readOnly: true,
  epoch: 0,
  notifyMuted: () => {},
  openMultiMute: () => {},
})

interface MuteNodeProviderProps {
  projectId: string | null
  readOnly: boolean
  /** The disabled buttons' tooltip when it is not the saved version's (step 4.11). */
  readOnlyReason?: string
  onViewMuted?: (focus?: MutedNodesFocus) => void
  /** Refetch the graph; the drawer, Node Inspector and All Nodes read from it. */
  onGraphChanged?: () => void
  /** Open Mute Rules at a catalog kind, from a Multi mute exact group. */
  onOpenMuteRules?: (kind: string) => void
  children: ReactNode
}

interface MultiMuteRequest {
  id: number
  seed: MultiMuteSeed
  options: MultiMuteOptions
}

export function MuteNodeProvider({
  projectId, readOnly, readOnlyReason, onViewMuted, onGraphChanged, onOpenMuteRules, children,
}: MuteNodeProviderProps) {
  // Optional, not useProject(): tests and embeds render this provider alone,
  // and Multi mute's gate degrades to "could not load your models" without one.
  const userId = useOptionalProject()?.userId ?? null
  const [epoch, setEpoch] = useState(0)
  const [multi, setMulti] = useState<MultiMuteRequest | null>(null)
  const multiSeq = useRef(0)

  const notifyMuted = useCallback(() => {
    setEpoch(e => e + 1)
    onGraphChanged?.()
  }, [onGraphChanged])
  const openMultiMute = useCallback((seed: MultiMuteSeed, options: MultiMuteOptions = {}) => {
    setMulti({ id: ++multiSeq.current, seed, options })
  }, [])
  const closeMultiMute = useCallback(() => setMulti(null), [])

  const value = useMemo(
    () => ({ projectId, userId, readOnly, readOnlyReason, onViewMuted, epoch, notifyMuted, openMultiMute }),
    [projectId, userId, readOnly, readOnlyReason, onViewMuted, epoch, notifyMuted, openMultiMute],
  )
  return (
    <MuteNodeContext.Provider value={value}>
      {children}
      {multi && projectId && (
        <MultiMuteModal
          key={multi.id}
          projectId={projectId}
          userId={userId}
          seed={multi.seed}
          options={multi.options}
          onDone={closeMultiMute}
          notifyMuted={notifyMuted}
          onViewMuted={onViewMuted}
          onOpenMuteRules={onOpenMuteRules}
        />
      )}
    </MuteNodeContext.Provider>
  )
}

export function useMuteNodeContext(): MuteNodeContextValue {
  return useContext(MuteNodeContext)
}

/** Why a node cannot be muted, as the disabled button's tooltip. */
export function unmuteableReason(label: string): string {
  return `${label} nodes cannot be muted. Only findings can: an asset is context, ` +
    'and muting it would orphan the findings attached to it.'
}

export const READ_ONLY_REASON =
  'You are viewing a saved version, which is read-only. Switch back to the ' +
  'active version to mute nodes.'

interface MuteNodeButtonProps {
  /** Names the node in the confirm. */
  name: string
  /** The node's graph id (a table's Node ID column, `GraphNode.id`). */
  graphId?: unknown
  /** The finding's stored key, when known; preferred over graphId because it
   *  survives an import or version activation. */
  nodeId?: string | null
  /** The node's label when known. An asset label disables the button up front
   *  instead of letting the server refuse after the confirm. */
  label?: string
  /** JsReconFinding's `finding_type`: a `js_file` container is no Multi mute seed. */
  findingType?: string | null
  /** After the page has been told; the drawer closes itself here. */
  onMuted?: () => void
  /** Multi mute's short "Multi" label, for table rows. */
  compact?: boolean
}

/**
 * The Mute button for one graph node, wired to the page's project and refresh,
 * with Multi mute beside it.
 *
 * Renders nothing outside a `MuteNodeProvider` (a table embedded elsewhere) or
 * for a row that is not one node (an aggregate with no id).
 */
export function MuteNodeButton(props: MuteNodeButtonProps) {
  const { projectId } = useMuteNodeContext()
  if (!projectId || !(props.nodeId || formatNodeId(props.graphId))) return null
  const { name, graphId, nodeId, label, findingType, onMuted, compact = true } = props
  return (
    <span className={styles.pair}>
      <MultiMuteButton
        seed={{ name, nodeId, graphId: formatNodeId(graphId), label, findingType }}
        compact={compact}
        onSeedMuted={onMuted}
      />
      <ProvidedMuteButton {...props} />
    </span>
  )
}

/** Split out so the alert and toast hooks only run inside the page's providers. */
function ProvidedMuteButton({ name, graphId, nodeId, label, onMuted }: MuteNodeButtonProps) {
  const { projectId, readOnly, readOnlyReason, onViewMuted, notifyMuted } = useMuteNodeContext()
  const { mute, mutingKey } = useMuteNode(projectId, onViewMuted)
  const gid = formatNodeId(graphId)

  const reason = readOnly
    ? readOnlyReason ?? READ_ONLY_REASON
    : label && !muteableLabel([label]) ? unmuteableReason(label) : undefined

  return (
    <MuteButton
      busy={mutingKey !== null && mutingKey === (nodeId || gid)}
      disabled={!!reason}
      title={reason}
      onClick={() => void mute(
        nodeId ? { name, nodeId } : { name, graphId: gid ?? undefined },
        {
          onMuted: () => {
            notifyMuted()
            onMuted?.()
          },
          onStale: notifyMuted,
        },
      )}
    />
  )
}

/** `MuteNodeButton` for a graph node: the drawer, All Nodes, Node Inspector. */
export function GraphNodeMuteButton({ node, onMuted, compact }: {
  node: GraphNode
  onMuted?: () => void
  compact?: boolean
}) {
  const label = muteableLabel([node.type])
  const findingType = node.properties?.finding_type
  return (
    <MuteNodeButton
      name={node.name}
      graphId={node.id}
      nodeId={label ? muteKey(label, node.properties ?? {}) : null}
      label={node.type}
      findingType={typeof findingType === 'string' ? findingType : null}
      onMuted={onMuted}
      compact={compact}
    />
  )
}
