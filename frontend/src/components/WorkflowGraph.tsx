import React from 'react'

export type WorkflowNodeId =
  | 'assessment'
  | 'triage'
  | 'gate'
  | 'slack'
  | 'jira'
  | 'regression'

type NodeDef = {
  id: WorkflowNodeId
  label: string
  sub: string
  x: number
  y: number
  optional?: boolean
}

const NODES: NodeDef[] = [
  { id: 'assessment', label: 'Assessment', sub: 'run suite', x: 36, y: 150 },
  { id: 'triage', label: 'Triage', sub: 'severity buckets', x: 210, y: 150 },
  { id: 'gate', label: 'CI Gate', sub: 'release decision', x: 384, y: 150 },
  { id: 'slack', label: 'Slack Alert', sub: 'SOC channel', x: 580, y: 54, optional: true },
  { id: 'jira', label: 'Jira Ticket', sub: 'remediation', x: 580, y: 246, optional: true },
  { id: 'regression', label: 'Regression', sub: 'vs baseline', x: 780, y: 150 },
]

const EDGES: Array<[WorkflowNodeId, WorkflowNodeId]> = [
  ['assessment', 'triage'],
  ['triage', 'gate'],
  ['gate', 'slack'],
  ['gate', 'jira'],
  ['slack', 'regression'],
  ['jira', 'regression'],
  ['gate', 'regression'],
]

const W = 132
const H = 56

interface Props {
  selectedId?: WorkflowNodeId
  onSelect?: (id: WorkflowNodeId) => void
  gateStatus?: string
  slackLive?: boolean
  jiraLive?: boolean
  slackStatus?: string
  jiraStatus?: string
  hasRegression?: boolean
}

function nodeAnchor(id: WorkflowNodeId, side: 'left' | 'right' | 'center') {
  const n = NODES.find(x => x.id === id)!
  if (side === 'left') return { x: n.x, y: n.y + H / 2 }
  if (side === 'right') return { x: n.x + W, y: n.y + H / 2 }
  return { x: n.x + W / 2, y: n.y + H / 2 }
}

function edgePath(fromId: WorkflowNodeId, toId: WorkflowNodeId) {
  const from = nodeAnchor(fromId, 'right')
  const to = nodeAnchor(toId, 'left')
  const midX = (from.x + to.x) / 2
  return `M ${from.x} ${from.y} C ${midX} ${from.y}, ${midX} ${to.y}, ${to.x} ${to.y}`
}

export default function WorkflowGraph({
  selectedId = 'gate',
  onSelect,
  gateStatus = 'N/A',
  slackLive = false,
  jiraLive = false,
  slackStatus,
  jiraStatus,
  hasRegression = false,
}: Props) {
  const gatePass = gateStatus === 'PASS'
  const gateFail = gateStatus === 'FAIL'

  const statusFor = (id: WorkflowNodeId) => {
    if (id === 'gate') return gateStatus
    if (id === 'slack') return slackStatus || (slackLive ? 'LIVE' : 'MOCK')
    if (id === 'jira') return jiraStatus || (jiraLive ? 'LIVE' : 'MOCK')
    if (id === 'regression') return hasRegression ? 'TRACKED' : 'WAITING'
    if (id === 'assessment' || id === 'triage') return 'DONE'
    return ''
  }

  const colorsFor = (node: NodeDef) => {
    const selected = selectedId === node.id
    if (node.id === 'gate' && gateFail) {
      return {
        fill: selected ? '#fef2f2' : '#fff5f5',
        stroke: '#dc2626',
        text: '#991b1b',
        badge: '#dc2626',
      }
    }
    if (node.id === 'gate' && gatePass) {
      return {
        fill: selected ? '#ecfdf5' : '#f0fdf4',
        stroke: '#16a34a',
        text: '#166534',
        badge: '#16a34a',
      }
    }
    if ((node.id === 'slack' && slackLive) || (node.id === 'jira' && jiraLive)) {
      return {
        fill: selected ? '#ecfdf5' : '#ffffff',
        stroke: selected ? '#16a34a' : '#86efac',
        text: '#166534',
        badge: '#16a34a',
      }
    }
    if (selected) {
      return {
        fill: '#e8f1fb',
        stroke: '#005bb5',
        text: '#004488',
        badge: '#005bb5',
      }
    }
    return {
      fill: '#ffffff',
      stroke: node.optional ? '#c4b5fd' : '#cbd5e1',
      text: '#334155',
      badge: '#64748b',
    }
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 bg-slate-50">
      <svg viewBox="0 0 960 360" className="w-full min-w-[720px]" style={{ maxHeight: 380 }}>
        <defs>
          <pattern id="wf-dots" x="0" y="0" width="18" height="18" patternUnits="userSpaceOnUse">
            <circle cx="1.2" cy="1.2" r="1.1" fill="#94a3b8" opacity="0.45" />
          </pattern>
          <marker id="wf-arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#64748b" />
          </marker>
          <marker id="wf-arrow-hot" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 Z" fill="#005bb5" />
          </marker>
        </defs>

        <rect x="0" y="0" width="960" height="360" fill="#f8fafc" />
        <rect x="0" y="0" width="960" height="360" fill="url(#wf-dots)" />

        <text x="20" y="28" fontSize="11" fill="#64748b" fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace">
          release workflow graph  ·  nodes = real post-assessment steps
        </text>

        {EDGES.map(([from, to]) => {
          const hot =
            selectedId === from ||
            selectedId === to ||
            (from === 'gate' && (to === 'slack' || to === 'jira' || to === 'regression'))
          // Keep direct gate→regression quieter when integrations are on-path
          const muted = from === 'gate' && to === 'regression'
          return (
            <path
              key={`${from}-${to}`}
              d={edgePath(from, to)}
              fill="none"
              stroke={hot && !muted ? '#005bb5' : '#94a3b8'}
              strokeWidth={hot && !muted ? 2.2 : 1.4}
              strokeDasharray={muted ? '5 5' : hot ? 'none' : '4 4'}
              opacity={muted ? 0.45 : 1}
              markerEnd={hot && !muted ? 'url(#wf-arrow-hot)' : 'url(#wf-arrow)'}
            />
          )
        })}

        {NODES.map(node => {
          const c = colorsFor(node)
          const status = statusFor(node.id)
          return (
            <g
              key={node.id}
              style={{ cursor: 'pointer' }}
              onClick={() => onSelect?.(node.id)}
            >
              <rect
                x={node.x}
                y={node.y}
                width={W}
                height={H}
                rx={8}
                fill={c.fill}
                stroke={c.stroke}
                strokeWidth={selectedId === node.id ? 2.4 : 1.5}
              />
              <text
                x={node.x + 12}
                y={node.y + 20}
                fontSize="11"
                fontWeight="700"
                fill={c.text}
                fontFamily="system-ui, sans-serif"
              >
                {node.label}
              </text>
              <text
                x={node.x + 12}
                y={node.y + 36}
                fontSize="9"
                fill="#64748b"
                fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              >
                {node.sub}
              </text>
              {status && (
                <text
                  x={node.x + W - 10}
                  y={node.y + 18}
                  textAnchor="end"
                  fontSize="8"
                  fontWeight="700"
                  fill={c.badge}
                  fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                >
                  {status}
                </text>
              )}
              {node.optional && (
                <text
                  x={node.x + 12}
                  y={node.y + H - 8}
                  fontSize="8"
                  fill="#7c3aed"
                  fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                >
                  optional integration
                </text>
              )}
            </g>
          )
        })}

        <g transform="translate(20, 330)">
          {[
            { color: '#005bb5', label: 'selected / active edge' },
            { color: '#16a34a', label: 'pass / live' },
            { color: '#dc2626', label: 'gate fail' },
            { color: '#94a3b8', label: 'idle path' },
          ].map((item, i) => (
            <g key={item.label} transform={`translate(${i * 200}, 0)`}>
              <rect width="10" height="10" rx="2" fill={item.color} />
              <text x="16" y="9" fontSize="9" fill="#64748b" fontFamily="system-ui, sans-serif">
                {item.label}
              </text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  )
}
