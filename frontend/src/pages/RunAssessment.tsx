import React, { useState, useCallback, useRef } from 'react'
import { Play, Square, Shield, Zap } from 'lucide-react'
import { startAssessment, SSEEvent } from '../lib/api'
import AgentGraph from '../components/AgentGraph'
import TerminalLog from '../components/TerminalLog'

type LogLine = { text: string; type: 'info' | 'success' | 'error' | 'warn' | 'blocked' | 'system'; timestamp?: string }

function getTimestamp() {
  return new Date().toTimeString().slice(0, 8)
}

export default function RunAssessment() {
  const [mode, setMode] = useState<'vulnerable' | 'defended'>('defended')
  const [suiteType, setSuiteType] = useState<'suite' | 'adaptive'>('suite')
  const [running, setRunning] = useState(false)
  const [done, setDone] = useState(false)
  const [logs, setLogs] = useState<LogLine[]>([])
  const [progress, setProgress] = useState({ total: 0, current: 0, succeeded: 0, partial: 0, blocked: 0, asr: 0 })
  const [activeNode, setActiveNode] = useState<string>()
  const [blockedNode, setBlockedNode] = useState<string>()
  const [completedNodes, setCompletedNodes] = useState<string[]>([])
  const [results, setResults] = useState<Array<{ attack_id: string; result: string; severity: string; reason: string }>>([])
  const stopFn = useRef<(() => void) | null>(null)

  const addLog = (text: string, type: LogLine['type'] = 'info') => {
    setLogs(prev => [...prev, { text, type, timestamp: getTimestamp() }])
  }

  const handleEvent = useCallback((event: SSEEvent) => {
    const d = event.data

    switch (event.type) {
      case 'phase':
        addLog(`Phase: ${d.phase}${d.total_attacks ? ` (${d.total_attacks} attacks)` : ''}`, 'system')
        if (d.phase === 'initializing') {
          addLog(`Run ID: ${(d.run_id as string)?.slice(0, 8)}...`, 'info')
          addLog(`Mode: ${d.mode?.toString().toUpperCase()} | Suite: ${suiteType}`, 'info')
        }
        break

      case 'attack_start':
        addLog(`[${d.index}/${d.total}] Testing ${d.attack_id} [${d.category}]: ${(d.description as string)?.slice(0, 60)}...`, 'info')
        setActiveNode('planner')
        setBlockedNode(undefined)
        break

      case 'node_trace': {
        const trace = (d.node_trace as Array<{ node: string; decision: string }>) || []
        if (trace.length > 0) {
          const last = trace[trace.length - 1]
          setActiveNode(last.node)
          if (last.decision === 'BLOCK' || last.decision === 'DENY') {
            setBlockedNode(last.node)
          }
          setCompletedNodes(trace.filter(n => n.decision !== 'BLOCK').map(n => n.node))
        }
        break
      }

      case 'attack_result': {
        const result = d.result as string
        const id = d.attack_id as string
        const sev = d.severity as string
        const reason = (d.reason as string)?.slice(0, 80)

        if (result === 'SUCCEEDED') addLog(`✗ ${id} SUCCEEDED [${sev}] — ${reason}`, 'error')
        else if (result === 'PARTIAL') addLog(`~ ${id} PARTIAL [${sev}] — ${reason}`, 'warn')
        else addLog(`✓ ${id} BLOCKED [${d.halted_at_node || 'defense'}]`, 'blocked')

        setResults(prev => [...prev, { attack_id: id, result, severity: sev, reason: reason || '' }])
        break
      }

      case 'score_update':
        setProgress({
          total: d.total as number,
          current: d.total as number,
          succeeded: d.succeeded as number,
          partial: d.partial as number,
          blocked: d.blocked as number,
          asr: (d.asr as number) || 0,
        })
        break

      case 'workflow_result':
        addLog(`Workflow: Gate = ${d.gate_status}`, d.gate_status === 'FAIL' ? 'error' : 'success')
        break

      case 'done':
        if (d.succeeded != null || d.blocked != null) {
          setProgress({
            total: (d.total as number) || 0,
            current: (d.total as number) || 0,
            succeeded: (d.succeeded as number) || 0,
            partial: (d.partial as number) || 0,
            blocked: (d.blocked as number) || 0,
            asr: (d.asr as number) || 0,
          })
        }
        addLog(
          `Assessment complete. ASR: ${(((d.asr as number) || 0) * 100).toFixed(1)}% | Gate: ${d.gate_status || 'N/A'}`,
          'system',
        )
        setActiveNode(undefined)
        setDone(true)
        break

      case 'error':
        addLog(`Error: ${d.error}`, 'error')
        break

      default:
        if (event.type === 'adaptive_event') {
          const ev = d as any
          if (ev.type === 'confirmed') addLog(`★ Adaptive exploit CONFIRMED: ${ev.attack_id} (${ev.escalation_path?.length} attempts)`, 'error')
          else if (ev.type === 'attempt') addLog(`  Try ${ev.attempt} [${ev.strategy}]: ${ev.result}`, 'info')
        }
    }
  }, [suiteType])

  const handleRun = () => {
    setLogs([])
    setResults([])
    setProgress({ total: 0, current: 0, succeeded: 0, partial: 0, blocked: 0, asr: 0 })
    setActiveNode(undefined)
    setBlockedNode(undefined)
    setCompletedNodes([])
    setDone(false)
    setRunning(true)

    addLog('🛡 M8 Assessment Starting...', 'system')
    addLog(`Mode: ${mode.toUpperCase()} | Suite: ${suiteType.toUpperCase()}`, 'system')

    const stop = startAssessment(
      mode,
      suiteType,
      handleEvent,
      () => { setRunning(false) },
      (e) => { addLog(`Error: ${e.message}`, 'error'); setRunning(false) },
    )
    stopFn.current = stop
  }

  const handleStop = () => {
    stopFn.current?.()
    setRunning(false)
    addLog('Assessment stopped by user.', 'system')
  }

  const pct = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <Play size={24} className="text-[#005bb5]" />
        <h1 className="text-xl font-bold text-gray-800">Run Assessment</h1>
      </div>

      {/* Controls */}
      <div className="soft-panel p-5 space-y-4">
        <div className="flex gap-6">
          {/* Mode toggle */}
          <div>
            <div className="text-xs text-gray-500 mb-2">Mode</div>
            <div className="flex overflow-hidden rounded border border-blue-100 bg-white shadow-sm">
              {(['vulnerable', 'defended'] as const).map(m => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  disabled={running}
                  className={`px-4 py-2 text-sm font-semibold transition-all ${
                    mode === m
                      ? m === 'vulnerable' ? 'bg-red-600 text-white' : 'bg-[#005bb5] text-white'
                      : 'bg-white text-gray-500 hover:bg-blue-50 hover:text-[#005bb5]'
                  }`}
                >
                  {m === 'vulnerable' ? '⚠ Vulnerable' : '🛡 Defended'}
                </button>
              ))}
            </div>
          </div>

          {/* Suite type toggle */}
          <div>
            <div className="text-xs text-gray-500 mb-2">Suite Type</div>
            <div className="flex overflow-hidden rounded border border-blue-100 bg-white shadow-sm">
              {(['suite', 'adaptive'] as const).map(s => (
                <button
                  key={s}
                  onClick={() => setSuiteType(s)}
                  disabled={running}
                  className={`px-4 py-2 text-sm font-semibold transition-all ${
                    suiteType === s
                      ? 'bg-[#005bb5] text-white'
                      : 'bg-white text-gray-500 hover:bg-blue-50 hover:text-[#005bb5]'
                  }`}
                >
                  {s === 'suite' ? '📋 Static Suite' : '🔄 Adaptive'}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Description */}
        <div className="rounded border border-blue-100 bg-blue-50/60 p-3 text-xs text-gray-600">
          {mode === 'vulnerable'
            ? '⚠️ Vulnerable mode: Defense nodes bypassed. Attacks will succeed against the unprotected agent. Use to establish baseline.'
            : '🛡 Defended mode: All defense nodes active (classifier → policy broker → output guard). Same payloads as vulnerable run.'
          }
          {suiteType === 'adaptive' && ' Adaptive: MAP→BREAK→FALSIFY loop will escalate attacks through Arabic translation, base64 encoding, and other mutations.'}
        </div>

        {/* Run button */}
        <div className="flex gap-3">
          {!running ? (
            <button
              onClick={handleRun}
              className="flex items-center gap-2 px-6 py-3 bg-[#005bb5] hover:bg-[#0066cc] text-white font-semibold rounded text-sm shadow-soft"
            >
              <Play size={16} />
              RUN SECURITY ASSESSMENT
            </button>
          ) : (
            <button
              onClick={handleStop}
              className="flex items-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 text-white font-semibold rounded text-sm"
            >
              <Square size={16} />
              STOP
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      {(running || done) && (
        <div className="soft-panel p-4 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-gray-500">{running ? 'Running...' : 'Complete'}</span>
            <div className="flex gap-4 text-xs">
              <span className="text-red-600">✗ {progress.succeeded} Succeeded</span>
              <span className="text-amber-600">~ {progress.partial} Partial</span>
              <span className="text-green-600">✓ {progress.blocked} Blocked</span>
              <span className="text-[#005bb5]">ASR: {(progress.asr * 100).toFixed(1)}%</span>
            </div>
          </div>
          <div className="w-full bg-blue-50 rounded-full h-2">
            <div
              className={`h-2 rounded-full transition-all duration-300 ${done ? 'bg-green-500' : 'bg-[#005bb5]'}`}
              style={{ width: `${done ? 100 : pct}%` }}
            />
          </div>
        </div>
      )}

      {/* Grid: AgentGraph + Terminal */}
      <div className="grid grid-cols-2 gap-5">
        <div className="soft-panel p-4">
          <h2 className="text-sm font-medium text-gray-500 mb-3">Agent Turn Graph</h2>
          <AgentGraph
            activeNode={activeNode}
            blockedNode={blockedNode}
            completedNodes={completedNodes}
            mode={mode}
          />
        </div>

        <div className="soft-panel p-4">
          <h2 className="text-sm font-medium text-gray-500 mb-3">Assessment Console</h2>
          <TerminalLog lines={logs} maxHeight={320} />
        </div>
      </div>

      {/* Results table */}
      {results.length > 0 && (
        <div className="soft-panel p-5">
          <h2 className="text-sm font-medium text-gray-500 mb-3">Results Summary</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-gray-200 text-gray-500">
                  <th className="text-left pb-2">Attack ID</th>
                  <th className="text-left pb-2">Result</th>
                  <th className="text-left pb-2">Severity</th>
                  <th className="text-left pb-2">Reason</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i} className="border-b border-gray-200/50 hover:bg-gray-100/30">
                    <td className="py-1.5 font-mono">{r.attack_id}</td>
                    <td className="py-1.5">
                      <span className={`px-2 py-0.5 rounded text-xs badge-${r.result.toLowerCase()}`}>
                        {r.result}
                      </span>
                    </td>
                    <td className="py-1.5">
                      <span className={`px-2 py-0.5 rounded text-xs badge-${r.severity.toLowerCase()}`}>
                        {r.severity}
                      </span>
                    </td>
                    <td className="py-1.5 text-gray-500 max-w-xs truncate">{r.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
