import React, { useEffect, useState } from 'react'
import { FileText, Search as SearchIcon } from 'lucide-react'
import { api, AttackResult } from '../lib/api'

function resultRowClass(result: string) {
  if (result === 'SUCCEEDED') return 'result-row-succeeded'
  if (result === 'PARTIAL') return 'result-row-partial'
  return 'result-row-blocked'
}

function resultLabel(result: string) {
  return result
}

export default function Evidence() {
  const [allAttacks, setAllAttacks] = useState<(AttackResult & { run_mode: string })[]>([])
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<(AttackResult & { run_mode: string }) | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      const { runs } = await api.runs(5)
      const combined: (AttackResult & { run_mode: string })[] = []
      for (const run of runs.filter(r => r.status === 'completed').slice(0, 3)) {
        const detail = await api.runDetail(run.id)
        combined.push(...(detail.attacks as AttackResult[]).map(a => ({ ...a, run_mode: run.mode })))
      }
      setAllAttacks(combined)
      setLoading(false)
    }
    load()
  }, [])

  const filtered = allAttacks.filter(a =>
    !search ||
    a.attack_id.toLowerCase().includes(search.toLowerCase()) ||
    a.category.toLowerCase().includes(search.toLowerCase()) ||
    a.reason?.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <FileText size={24} className="text-[#005bb5]" />
        <h1 className="text-xl font-bold text-gray-800">Evidence</h1>
        <span className="text-sm text-gray-500">— {allAttacks.length} attack transcripts</span>
      </div>

      {/* Search */}
      <div className="relative">
        <SearchIcon size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search attacks, categories, results..."
          className="w-full bg-white border border-blue-100 rounded pl-9 pr-4 py-2 text-sm text-gray-700 placeholder-gray-400 focus:outline-none focus:border-[#005bb5] focus:ring-2 focus:ring-blue-50"
        />
      </div>

      {loading ? (
        <div className="text-gray-500 text-sm">Loading evidence...</div>
      ) : (
        <div className="grid grid-cols-2 gap-5">
          {/* List */}
          <div className="space-y-1 overflow-y-auto max-h-screen">
            {filtered.map((a, i) => (
              <div
                key={i}
                onClick={() => setSelected(a)}
                className={`p-3 rounded-lg cursor-pointer transition border ${resultRowClass(a.result)} ${
                  selected?.id === a.id
                    ? 'result-row-selected'
                    : 'hover:shadow-sm'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[#005bb5] w-14">{a.attack_id}</span>
                  <span className={`decision-badge ${a.result === 'SUCCEEDED' ? 'block' : a.result === 'PARTIAL' ? 'warn' : 'allow'}`}>{resultLabel(a.result)}</span>
                  <span className={`px-1.5 py-0.5 text-xs rounded badge-${a.severity.toLowerCase()}`}>{a.severity}</span>
                  <span className="text-xs text-gray-500 ml-auto">{a.run_mode}</span>
                </div>
                <div className="text-xs text-gray-500 mt-1 truncate">{a.reason}</div>
              </div>
            ))}
          </div>

          {/* Detail */}
          <div className="soft-panel p-5 sticky top-6">
            {!selected ? (
              <div className="text-gray-400 text-sm text-center mt-8">Select an attack to view evidence</div>
            ) : (
              <div className="space-y-4 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[#005bb5] font-bold">{selected.attack_id}</span>
                  <span className={`decision-badge ${selected.result === 'SUCCEEDED' ? 'block' : selected.result === 'PARTIAL' ? 'warn' : 'allow'}`}>{resultLabel(selected.result)}</span>
                  <span className={`px-2 py-0.5 rounded badge-${selected.severity.toLowerCase()}`}>{selected.severity}</span>
                </div>

                <div>
                  <div className="text-gray-500 mb-1">Category</div>
                  <div className="text-gray-700">{selected.category}</div>
                </div>

                <div>
                  <div className="text-gray-500 mb-1">Oracle Result</div>
                  <div className="text-gray-700">{selected.reason}</div>
                </div>

                {/* Node trace */}
                {selected.node_trace_json && (
                  <div>
                    <div className="text-gray-500 mb-2">Node Trace ({(selected.node_trace_json as any[]).length} nodes)</div>
                    <div className="space-y-1">
                      {(selected.node_trace_json as any[]).map((node: any, ni: number) => (
                        <div key={ni} className={`flex items-start gap-2 p-2 rounded border ${node.decision === 'BLOCK' || node.decision === 'DENY' ? 'bg-red-50 border-red-200' : node.decision === 'ALLOW' || node.decision === 'PASS' ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'}`}>
                          <span className="font-mono text-gray-500 w-32 flex-shrink-0">{node.node}</span>
                          <span className={`px-1.5 py-0.5 rounded text-xs flex-shrink-0 ${node.decision === 'BLOCK' || node.decision === 'DENY' ? 'bg-red-50 text-red-600' : 'bg-white text-gray-500'}`}>{node.decision}</span>
                          <span className="text-gray-500 truncate">{node.output_summary}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Tool calls */}
                {selected.tool_calls_json && (selected.tool_calls_json as any[]).length > 0 && (
                  <div>
                    <div className="text-gray-500 mb-2">Tool Calls</div>
                    {(selected.tool_calls_json as any[]).map((tc: any, ti: number) => (
                      <div key={ti} className="bg-gray-50 rounded p-2 font-mono">
                        <div className="text-[#005bb5]">{tc.name}</div>
                        <div className="text-gray-500 ml-2">{JSON.stringify(tc.arguments)}</div>
                        {tc.source && <div className="text-orange-600 text-xs">source: {tc.source}</div>}
                      </div>
                    ))}
                  </div>
                )}

                {/* Hash chain */}
                {selected.node_trace_json && (selected.node_trace_json as any[]).length > 0 && (
                  <div>
                    <div className="text-gray-500 mb-1">Tamper-evident checkpoint</div>
                    <div className="font-mono text-gray-400 text-xs truncate">
                      sha256:{(selected.node_trace_json as any[])[((selected.node_trace_json as any[]).length - 1)]?.checkpoint_hash?.slice(0, 32)}...
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
