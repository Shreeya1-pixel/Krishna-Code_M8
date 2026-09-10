import React from 'react'

const NODES = [
  { id: 'user_input', label: 'User Input', x: 50, y: 40, defense: false },
  { id: 'injection_classifier', label: 'Injection Classifier', x: 200, y: 40, defense: true },
  { id: 'planner', label: 'Planner (LLM)', x: 380, y: 40, defense: false },
  { id: 'tool_request', label: 'Tool Request', x: 530, y: 40, defense: false },
  { id: 'policy_broker', label: 'Policy Broker', x: 380, y: 140, defense: true },
  { id: 'tool_exec', label: 'Tool Exec', x: 530, y: 140, defense: false },
  { id: 'output_guard', label: 'Output Guard', x: 380, y: 240, defense: true },
  { id: 'responder', label: 'Responder', x: 200, y: 240, defense: false },
]

const EDGES = [
  ['user_input', 'injection_classifier'],
  ['injection_classifier', 'planner'],
  ['planner', 'tool_request'],
  ['tool_request', 'policy_broker'],
  ['policy_broker', 'tool_exec'],
  ['tool_exec', 'output_guard'],
  ['output_guard', 'responder'],
]

interface Props {
  activeNode?: string
  blockedNode?: string
  completedNodes?: string[]
  mode?: string
}

export default function AgentGraph({ activeNode, blockedNode, completedNodes = [], mode = 'defended' }: Props) {
  const getNodePos = (id: string) => NODES.find(n => n.id === id) ?? null

  const getNodeColor = (node: typeof NODES[0]) => {
    if (node.id === blockedNode) return { fill: '#fef2f2', stroke: '#dc2626', text: '#991b1b' }
    if (node.id === activeNode) return { fill: '#e6f0fa', stroke: '#005bb5', text: '#004488' }
    if (completedNodes.includes(node.id)) return { fill: '#dcfce7', stroke: '#16a34a', text: '#15803d' }
    if (mode === 'vulnerable' && node.defense) return { fill: '#f9fafb', stroke: '#d1d5db', text: '#9ca3af' }
    return { fill: '#ffffff', stroke: '#d1d5db', text: '#4b5563' }
  }

  return (
    <svg viewBox="0 -20 640 320" className="w-full bg-gray-50 rounded-lg border border-gray-200" style={{ maxHeight: 280 }}>
      {EDGES.map(([fromId, toId]) => {
        const from = getNodePos(fromId)
        const to = getNodePos(toId)
        if (!from || !to) return null
        const x1 = from.x + 60
        const y1 = from.y + 18
        const x2 = to.x
        const y2 = to.y + 18
        const active = completedNodes.includes(fromId) || fromId === activeNode
        return (
          <line
            key={`${fromId}-${toId}`}
            x1={x1} y1={y1} x2={x2} y2={y2}
            stroke={active ? '#005bb5' : '#e5e7eb'}
            strokeWidth={active ? 2 : 1}
            strokeDasharray={active ? 'none' : '4 4'}
          />
        )
      })}

      {NODES.map(node => {
        const colors = getNodeColor(node)
        const isDefense = node.defense
        const isDisabled = mode === 'vulnerable' && isDefense

        return (
          <g key={node.id}>
            <rect
              x={node.x}
              y={node.y}
              width={120}
              height={36}
              rx={6}
              fill={colors.fill}
              stroke={colors.stroke}
              strokeWidth={node.id === blockedNode ? 2 : 1}
              opacity={isDisabled ? 0.55 : 1}
            />
            {isDefense && (
              <text x={node.x + 4} y={node.y + 10} fontSize={8} fill={isDisabled ? '#9ca3af' : '#005bb5'}>🛡</text>
            )}
            <text
              x={node.x + 60}
              y={node.y + 22}
              textAnchor="middle"
              fontSize={9}
              fill={isDisabled ? '#9ca3af' : colors.text}
              fontFamily="system-ui, sans-serif"
              fontWeight={500}
            >
              {node.label}
            </text>
            {isDisabled && (
              <text x={node.x + 60} y={node.y + 32} textAnchor="middle" fontSize={7} fill="#9ca3af" fontFamily="system-ui, sans-serif">
                BYPASSED
              </text>
            )}
            {node.id === blockedNode && (
              <text x={node.x + 60} y={node.y + 32} textAnchor="middle" fontSize={7} fill="#dc2626" fontFamily="system-ui, sans-serif">
                ✗ BLOCKED
              </text>
            )}
          </g>
        )
      })}

      <g transform="translate(0, 285)">
        {[
          { color: '#005bb5', label: 'Active' },
          { color: '#dc2626', label: 'Blocked' },
          { color: '#16a34a', label: 'Done' },
          { color: '#d1d5db', label: 'Idle' },
        ].map(({ color, label }, i) => (
          <g key={label} transform={`translate(${i * 90}, 0)`}>
            <rect width={10} height={10} rx={2} fill={color} />
            <text x={14} y={9} fontSize={8} fill="#6b7280" fontFamily="system-ui, sans-serif">{label}</text>
          </g>
        ))}
      </g>
    </svg>
  )
}
