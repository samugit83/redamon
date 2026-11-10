'use client'

import { useMemo, useState } from 'react'
import { AlertTriangle, ArrowLeft, Bot, Check, Copy, Trash2 } from 'lucide-react'
import { Drawer, ExternalLink, useToast } from '@/components/ui'
import { trufflehogDisplayFields } from '@/lib/trufflehogDisplay'
import { confirmedInGraph, endpointExposureFields, isRouteExposureFinding, routeExposureDisplayFields } from '@/lib/routeExposureDisplay'
import { COVERAGE_STAMP_PROPERTIES, coverageLines, recordedCoverageModules } from '@/lib/coverageStamps'
import { copyText } from '@/lib/copyText'
import { muteableLabel } from '@/lib/muteTarget'
import { dispositionText, readDisposition } from '@/lib/triage/disposition'
import { OWNERSHIP_PROPERTIES, ownershipLine } from '@/lib/ipOwnership'
import { GraphData, GraphNode } from '../../types'
import { badgeColors, buildNodeContext, getNodeColor, getNodeUrl, nodeLabel } from '../../utils'
import { domainScopeRoots, scanRootBadge } from '../../utils/scopeRootsForNode'
import type { ScopeGroup } from '@/lib/scopeGroups'
import { renderPropertyValue } from '../../utils/renderPropertyValue'
import { ClusterNodeList } from './ClusterNodeList'
import { NodeAgentModal } from './NodeAgentModal'
import { GraphNodeMuteButton, useMuteNodeContext } from '../MuteNode'
import styles from './NodeDrawer.module.css'
import clusterStyles from './ClusterNodeList.module.css'

// The shared Drawer's <h2> is the box that clips the title with an ellipsis.
// Show the full name as a tooltip only when it is actually clipped, checked at
// hover time so it stays right after a resize. A native title is used because
// the shared Tooltip wraps its trigger in a block that would defeat the ellipsis.
function DrawerTitle({ text }: { text: string }) {
  return (
    <span
      className={styles.drawerTitleText}
      onMouseEnter={(e) => {
        const box = e.currentTarget.parentElement
        e.currentTarget.title = box && box.scrollWidth > box.clientWidth ? text : ''
      }}
    >
      {text}
    </span>
  )
}

interface NodeDrawerProps {
  node: GraphNode | null
  isOpen: boolean
  onClose: () => void
  onDeleteNode?: (nodeId: string) => Promise<void>
  expandedChild?: GraphNode | null
  onExpandChild?: (child: GraphNode) => void
  onCollapseChild?: () => void
  // Full (unfiltered) graph, used to describe the node's relationships when
  // building the LLM context. Omitted when unavailable (relationships elided).
  graphData?: GraphData | null
  projectName?: string
  targetDomain?: string
  /** The project's current scope groups; undefined on a saved version, whose
   *  stored scan roots are then shown without the current/removed split. */
  scopeGroups?: ScopeGroup[]
  // Start a fresh agent session seeded with the node context + the request.
  onStartAgentSession?: (request: string, context: string, nodeLabel: string) => void
}

export function NodeDrawer({
  node,
  isOpen,
  onClose,
  onDeleteNode,
  expandedChild,
  onExpandChild,
  onCollapseChild,
  graphData,
  projectName,
  targetDomain,
  scopeGroups,
  onStartAgentSession,
}: NodeDrawerProps) {
  const toast = useToast()
  const [isDeleting, setIsDeleting] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [copied, setCopied] = useState(false)
  const [showAgentModal, setShowAgentModal] = useState(false)
  const { readOnly: muteReadOnly } = useMuteNodeContext()

  const handleDeleteClick = () => {
    setShowDeleteConfirm(true)
  }

  // Determine what to display:
  // - Root is a cluster with nothing expanded → show its child list
  // - Root is a cluster with expanded node that is ALSO a cluster → show that cluster's list (nested)
  // - Root is a cluster with expanded leaf node → show that leaf's properties
  // - Root is a regular node → show its properties
  const isCluster = !!node?.isCluster
  const topOfStack = expandedChild ?? null
  const showList = (isCluster && !topOfStack) || !!topOfStack?.isCluster
  const listCluster: GraphNode | null = topOfStack?.isCluster ? topOfStack : (isCluster ? node : null)
  const displayNode: GraphNode | null = showList ? null : (topOfStack ?? node)

  const handleDeleteConfirm = async () => {
    if (!displayNode || !onDeleteNode) return
    setIsDeleting(true)
    try {
      await onDeleteNode(displayNode.id)
      setShowDeleteConfirm(false)
      onClose()
    } finally {
      setIsDeleting(false)
    }
  }

  const handleDeleteCancel = () => {
    setShowDeleteConfirm(false)
  }

  // Whether a missing stamp reads "not scanned" or "coverage not recorded" is a
  // project-wide question: did the module stamp ANY host.
  const recordedModules = useMemo(() => recordedCoverageModules(graphData?.nodes), [graphData])
  const coverage = displayNode?.type === 'BaseURL'
    ? coverageLines(displayNode.properties ?? {}, recordedModules)
    : []

  const isIp = displayNode?.type === 'IP'
  const hiddenKeys: string[] = [
    'project_id', 'user_id',
    ...(coverage.length ? COVERAGE_STAMP_PROPERTIES : []),
    ...(isIp ? OWNERSHIP_PROPERTIES : []),
  ]
  const sortedProperties = displayNode
    ? Object.entries(displayNode.properties || {})
        .filter(([key]) => !hiddenKeys.includes(key))
        .sort(([a], [b]) => {
          const bottomKeys = ['created_at', 'updated_at']
          const aIsBottom = bottomKeys.includes(a)
          const bIsBottom = bottomKeys.includes(b)
          if (aIsBottom && !bIsBottom) return 1
          if (!aIsBottom && bIsBottom) return -1
          if (aIsBottom && bIsBottom) return bottomKeys.indexOf(a) - bottomKeys.indexOf(b)
          return 0
        })
    : []

  // Findings only: an asset or a reference node is never "reportable".
  const disposition = displayNode && muteableLabel([displayNode.type])
    ? readDisposition(displayNode.properties)
    : null

  const trufflehogFields = displayNode?.type === 'MultiscannerFinding'
    ? trufflehogDisplayFields((displayNode.properties ?? {}) as Record<string, unknown>)
    : []

  const routeExposure = !displayNode
    ? []
    : isRouteExposureFinding(displayNode.type, displayNode.properties)
      ? routeExposureDisplayFields(displayNode.properties ?? {}, confirmedInGraph(displayNode.id, graphData?.links))
      : displayNode.type === 'Endpoint'
        ? endpointExposureFields(displayNode.properties ?? {})
        : []

  const drawerTitle = node
    ? showList && listCluster
      ? `Cluster: ${listCluster.clusterChildType ?? ''}`
      : displayNode
        ? `${displayNode.type}: ${displayNode.name}`
        : undefined
    : undefined

  const handleCopyContext = async () => {
    if (!displayNode) return
    const context = buildNodeContext(displayNode, graphData, { projectName, targetDomain, scopeGroups })
    try {
      await copyText(context)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
      toast.success('Node context copied for an external agent')
    } catch {
      toast.error('Could not access the clipboard')
    }
  }

  const handleAgentSubmit = (request: string) => {
    if (!displayNode) return
    const context = buildNodeContext(displayNode, graphData, { projectName, targetDomain, scopeGroups })
    setShowAgentModal(false)
    onStartAgentSession?.(request, context, nodeLabel(displayNode))
  }

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      position="left"
      mode="overlay"
      title={drawerTitle ? <DrawerTitle text={drawerTitle} /> : undefined}
    >
      {showList && listCluster && (
        <>
          {topOfStack && onCollapseChild && (
            <button
              className={clusterStyles.backBtn}
              onClick={onCollapseChild}
            >
              <ArrowLeft size={14} />
              Back
            </button>
          )}
          <ClusterNodeList
            cluster={listCluster}
            onSelectChild={(child) => onExpandChild?.(child)}
          />
        </>
      )}

      {displayNode && !showList && (
        <>
          {isCluster && onCollapseChild && (
            <button
              className={clusterStyles.backBtn}
              onClick={onCollapseChild}
            >
              <ArrowLeft size={14} />
              Back to list
            </button>
          )}

          <div className={styles.section}>
            <div className={styles.sectionHeader}>
              <div className={styles.basicInfoActions}>
                <button
                  className={styles.iconBtn}
                  onClick={handleCopyContext}
                  title="Copy LLM-ready context (node + relationships) for an external agent"
                  aria-label="Copy node context"
                >
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                </button>
                {onStartAgentSession && (
                  <button
                    className={`${styles.iconBtn} ${styles.iconBtnPrimary}`}
                    onClick={() => setShowAgentModal(true)}
                    title="Start a new agent session from this node"
                    aria-label="Ask agent about this node"
                  >
                    <Bot size={14} />
                  </button>
                )}
                {/* Hidden on a saved version, like delete: a snapshot is read-only. */}
                {!muteReadOnly && <GraphNodeMuteButton node={displayNode} onMuted={onClose} compact={false} />}
                {displayNode.type !== 'Domain' && displayNode.type !== 'Subdomain' && onDeleteNode && (
                  <button
                    className={`${styles.iconBtn} ${styles.iconBtnDanger}`}
                    onClick={handleDeleteClick}
                    disabled={isDeleting}
                    title="Delete node"
                    aria-label="Delete node"
                  >
                    <Trash2 size={14} />
                  </button>
                )}
              </div>
              <h3 className={styles.sectionTitleBasicInfo}>Basic Info</h3>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Type</span>
              <span
                className={styles.propertyBadge}
                style={badgeColors(getNodeColor(displayNode))}
              >
                {displayNode.type === 'Domain' && !displayNode.properties?.ip_mode
                  ? 'Domain (organisation)' : displayNode.type}
              </span>
              {(() => {
                const badge = scanRootBadge(displayNode, scopeGroups)
                return badge && (
                  <span className={styles.propertyBadge} data-testid="scan-root-badge">{badge}</span>
                )
              })()}
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>ID</span>
              <span className={styles.propertyValue}>{displayNode.id}</span>
            </div>
            <div className={styles.propertyRow}>
              <span className={styles.propertyKey}>Name</span>
              <span className={styles.propertyValue}>
                {(() => {
                  const url = getNodeUrl(displayNode)
                  return url
                    ? <ExternalLink href={url}>{displayNode.name}</ExternalLink>
                    : displayNode.name
                })()}
              </span>
            </div>
            {isIp && (
              <div className={styles.propertyRow} data-testid="drawer-ownership">
                <span className={styles.propertyKey}>Ownership</span>
                <span className={`${styles.propertyValue} ${styles.proseValue}`}>
                  {ownershipLine(displayNode.properties)}
                </span>
              </div>
            )}
            {disposition && (
              <div className={styles.propertyRow} data-testid="drawer-disposition">
                <span className={styles.propertyKey}>Disposition</span>
                <span className={styles.propertyValue}>{dispositionText(disposition)}</span>
              </div>
            )}
            {(() => {
              const roots = domainScopeRoots(displayNode, scopeGroups)
              return roots && (
                <div className={styles.propertyRow} data-testid="domain-scan-roots">
                  <span className={styles.propertyKey}>Scan roots under this domain</span>
                  <span className={styles.propertyValue}>
                    {roots.current.map(label => <div key={label}>{label}</div>)}
                    {roots.removed.length > 0 && (
                      <div style={{ color: 'var(--text-muted)' }}>
                        {roots.removed.join(', ')}: removed from scope, cleared by the next full recon
                      </div>
                    )}
                  </span>
                </div>
              )
            })()}
          </div>

          {/* A Secret Multiscanner finding's asset/location/extra_data are generic on the
              node — they must hold a repo AND an image AND a bucket. The
              per-source display registry says what they MEAN, so the drawer
              shows "Image / Layer / Tag" for a docker finding rather than three
              unlabelled strings and a JSON blob. */}
          {trufflehogFields.length > 0 && (
            <div className={styles.section}>
              <h3 className={styles.sectionTitleProperties}>Finding</h3>
              {trufflehogFields.map(({ label, value }) => (
                <div key={label} className={styles.propertyRow}>
                  <span className={styles.propertyKey}>{label}</span>
                  <span className={styles.propertyValue}>{value}</span>
                </div>
              ))}
            </div>
          )}

          {routeExposure.length > 0 && (
            <div className={styles.section} data-testid="route-exposure-section">
              <h3 className={styles.sectionTitleProperties}>Route exposure</h3>
              {routeExposure.map(({ label, value }) => (
                <div key={label} className={styles.propertyRow}>
                  <span className={styles.propertyKey}>{label}</span>
                  <span className={`${styles.propertyValue} ${styles.proseValue}`}>{value}</span>
                </div>
              ))}
            </div>
          )}

          {coverage.length > 0 && (
            <div className={styles.section} data-testid="coverage-section">
              <h3 className={styles.sectionTitleProperties}>Coverage</h3>
              {coverage.map(line => (
                <div key={line.module} className={styles.propertyRow} data-state={line.state}>
                  <span className={styles.propertyKey}>{line.label}</span>
                  <span className={`${styles.coverageValue} ${styles[`coverage_${line.state}`] ?? ''}`}>
                    {line.text}
                    {line.at && <span className={styles.coverageAt}> · run started {line.at}</span>}
                  </span>
                </div>
              ))}
            </div>
          )}

          <div className={styles.section}>
            <h3 className={styles.sectionTitleProperties}>Properties</h3>
            {sortedProperties.map(([key, value]) => {
              const nodeUrl = key === 'name' ? getNodeUrl(displayNode) : null
              return (
                <div key={key} className={styles.propertyRow}>
                  <span className={styles.propertyKey}>{key}</span>
                  <span className={styles.propertyValue}>
                    {nodeUrl
                      ? <ExternalLink href={nodeUrl}>{String(value)}</ExternalLink>
                      : renderPropertyValue(value, key, displayNode?.type)}
                  </span>
                </div>
              )
            })}
            {sortedProperties.length === 0 && (
              <p className={styles.emptyProperties}>No additional properties</p>
            )}
          </div>

          {/* Delete confirmation modal */}
          {showDeleteConfirm && (
            <div className={styles.confirmOverlay} onClick={handleDeleteCancel}>
              <div className={styles.confirmModal} onClick={(e) => e.stopPropagation()}>
                <div className={styles.confirmIcon}>
                  <AlertTriangle size={28} />
                </div>
                <h4 className={styles.confirmTitle}>Delete Node</h4>
                <p className={styles.confirmText}>
                  Deleting <strong>{displayNode.type}: {displayNode.name}</strong> will permanently remove
                  this node and all its relationships from the graph.
                </p>
                <p className={styles.confirmWarning}>
                  This may break the connectivity of the graph and affect
                  the agent&apos;s ability to interpret the attack chain context.
                </p>
                <div className={styles.confirmActions}>
                  <button
                    className={styles.confirmCancelBtn}
                    onClick={handleDeleteCancel}
                  >
                    Cancel
                  </button>
                  <button
                    className={styles.confirmDeleteBtn}
                    onClick={handleDeleteConfirm}
                    disabled={isDeleting}
                  >
                    {isDeleting ? 'Deleting...' : 'Delete'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {displayNode && (
        <NodeAgentModal
          isOpen={showAgentModal}
          nodeLabel={nodeLabel(displayNode)}
          onClose={() => setShowAgentModal(false)}
          onSubmit={handleAgentSubmit}
        />
      )}
    </Drawer>
  )
}
