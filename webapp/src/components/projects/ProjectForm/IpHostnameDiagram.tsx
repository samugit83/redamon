'use client'

/**
 * The "How it works" diagram of one hostname mode (04_ui_spec.md §4): three
 * lanes (discover, decide, scan), a graph strip and a traffic strip. One
 * component, four configurations, all read from ipHostnameModes.ts.
 *
 * The lanes are HTML boxes rather than one SVG drawing so they can stack under
 * each other in a narrow modal (the arrows, inline SVG, turn to point down);
 * the graph strip is inline SVG in the graph's own node colours, so IP,
 * ExternalDomain, Subdomain and Domain look as they do on the graph page.
 *
 * The figure is `role="img"` with the mode's summary as its label; the modal
 * renders the same steps as a visible list under it, which is what a screen
 * reader reads in full.
 */
import { NODE_COLORS } from '@/app/graph/config/colors'
import { type IpHostnameMode, ipHostnameModeInfo } from './ipHostnameModes'
import styles from './IpHostnameDiagram.module.css'

const DISCOVER_SOURCES = ['Reverse DNS', 'TLS certificates', 'Passive DNS', 'Redirects']

function Arrow() {
  return (
    <svg className={styles.arrow} viewBox="0 0 28 14" aria-hidden="true" focusable="false">
      <path className={styles.arrowLine} d="M1 7h22" />
      <path className={styles.arrowHead} d="M18 2l7 5-7 5z" />
    </svg>
  )
}

interface GraphNode { id: string; label: string; x: number; y: number; type: keyof typeof NODE_COLORS }
interface GraphEdge { from: string; to: string; label?: string; dashed?: boolean }

const NODES: Record<string, GraphNode> = {
  cert: { id: 'cert', label: 'Certificate', x: 46, y: 46, type: 'Certificate' },
  ip: { id: 'ip', label: 'IP', x: 150, y: 46, type: 'IP' },
  ext: { id: 'ext', label: 'ExternalDomain (recorded)', x: 262, y: 20, type: 'ExternalDomain' },
  sub: { id: 'sub', label: 'Subdomain (scanned)', x: 262, y: 74, type: 'Subdomain' },
  dom: { id: 'dom', label: 'Domain', x: 360, y: 74, type: 'Domain' },
}

const GRAPH: Record<'ip' | 'recorded' | 'scanned', { nodes: string[]; edges: GraphEdge[] }> = {
  ip: { nodes: ['cert', 'ip'], edges: [{ from: 'ip', to: 'cert' }] },
  recorded: {
    nodes: ['cert', 'ip', 'ext'],
    edges: [{ from: 'ip', to: 'cert' }, { from: 'ext', to: 'ip', label: 'SEEN_ON', dashed: true }],
  },
  scanned: {
    nodes: ['cert', 'ip', 'ext', 'sub', 'dom'],
    edges: [
      { from: 'ip', to: 'cert' },
      { from: 'ext', to: 'ip', label: 'SEEN_ON', dashed: true },
      { from: 'sub', to: 'ip', label: 'RESOLVES_TO' },
      { from: 'dom', to: 'sub' },
    ],
  },
}

function GraphStrip({ kind }: { kind: 'ip' | 'recorded' | 'scanned' }) {
  const { nodes, edges } = GRAPH[kind]
  return (
    <svg className={styles.graphSvg} viewBox="0 0 420 100" aria-hidden="true" focusable="false">
      {edges.map(e => {
        const a = NODES[e.from]
        const b = NODES[e.to]
        return (
          <g key={`${e.from}-${e.to}`} data-edge={e.label ?? 'link'}>
            <line
              className={`${styles.edge} ${e.dashed ? styles.edgeDashed : ''}`}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
            />
            {e.label && (
              <text className={styles.edgeLabel} x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 4} textAnchor="middle">
                {e.label}
              </text>
            )}
          </g>
        )
      })}
      {nodes.map(id => {
        const n = NODES[id]
        return (
          <g key={id} data-node={n.type}>
            <circle cx={n.x} cy={n.y} r={9} style={{ fill: NODE_COLORS[n.type] }} className={styles.node} />
            <text className={styles.nodeLabel} x={n.x} y={n.y + 22} textAnchor="middle">{n.label}</text>
          </g>
        )
      })}
    </svg>
  )
}

export function IpHostnameDiagram({ mode }: { mode: IpHostnameMode }) {
  const info = ipHostnameModeInfo(mode)
  const d = info.diagram
  const off = d.discover === 'off'
  return (
    <figure className={styles.diagram} role="img" aria-label={d.ariaLabel} data-mode={info.mode}>
      <div className={styles.lanes}>
        <div
          className={`${styles.lane} ${off ? styles.laneOff : ''}`}
          data-element="discover"
          data-state={d.discover}
        >
          <span className={styles.laneTitle}>Discover</span>
          <ul className={styles.sources}>
            {DISCOVER_SOURCES.map(s => <li key={s}>{s}</li>)}
          </ul>
          {off && <span className={styles.offTag}>off</span>}
          {d.passiveChip && (
            <span className={styles.chip} data-element="passive-chip">Passive search of *.filters</span>
          )}
        </div>
        <Arrow />
        <div
          className={`${styles.lane} ${d.decide.dimmed ? styles.laneOff : ''}`}
          data-element="decide"
          data-state={d.decide.dimmed ? 'off' : 'active'}
        >
          <span className={styles.laneTitle}>Decide</span>
          <p className={styles.decideText}>{d.decide.text}</p>
          {d.decide.confirmedChip && (
            <span className={`${styles.chip} ${styles.chipDanger}`} data-element="confirmed-chip">confirmed</span>
          )}
        </div>
        <Arrow />
        <div className={`${styles.lane} ${styles.laneScan}`} data-element="scan" data-state="active">
          <span className={styles.laneTitle}>Scan (packets → your IPs only)</span>
          <div className={styles.scanBox}>
            <strong>Your IPs</strong>
            <span>ports · TLS · HTTP · vulns</span>
          </div>
          {d.scanNames && (
            <div className={`${styles.scanBox} ${styles.namesBox}`} data-element="scan-names">{d.scanNames}</div>
          )}
        </div>
      </div>
      <div className={styles.strip} data-element="graph" data-state={d.graph}>
        <span className={styles.stripTitle}>Graph</span>
        <GraphStrip kind={d.graph} />
        <span className={styles.stripCaption}>{d.graphCaption}</span>
      </div>
      <div className={styles.strip} data-element="traffic">
        <span className={styles.stripTitle}>Traffic</span>
        <span className={styles.stripCaption}>{d.traffic}</span>
      </div>
    </figure>
  )
}
