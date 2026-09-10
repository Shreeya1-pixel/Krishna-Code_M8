import React, { useEffect, useState } from 'react'
import { Search, AlertTriangle } from 'lucide-react'
import { api, Run, AttackResult } from '../lib/api'

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const OWASP_MAP: Record<string, string> = {
  direct_injection: 'LLM01: Prompt Injection',
  indirect_injection: 'LLM01: Prompt Injection + LLM07',
  tool_misuse: 'LLM08: Excessive Agency',
  exfiltration: 'LLM06: Sensitive Information Disclosure',
  multilingual: 'LLM01: Prompt Injection (Multilingual)',
  obfuscated: 'LLM01: Prompt Injection (Obfuscated)',
}

export default function Findings() {
  const [findings, setFindings] = useState<AttackResult[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      const { runs } = await api.runs(5)
      const allFindings: AttackResult[] = []
      for (const run of runs.filter(r => r.status === 'completed').slice(0, 2)) {
        const detail = await api.runDetail(run.id)
        allFindings.push(...(detail.attacks as AttackResult[]).filter(a => a.result !== 'BLOCKED'))
      }
      allFindings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
      setFindings(allFindings)
      setLoading(false)
    }
    load()
  }, [])

  if (loading) return <div className="p-6 text-gray-500 text-sm">Loading findings...</div>

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <Search size={24} className="text-orange-600" />
        <h1 className="text-xl font-bold text-gray-800">Findings</h1>
        <span className="text-sm text-gray-500">— {findings.length} findings (SUCCEEDED + PARTIAL)</span>
      </div>

      {findings.length === 0 ? (
        <div className="glass rounded-lg p-8 text-center text-gray-500">
          No findings yet. Run an assessment first.
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((f, i) => (
            <div
              key={i}
              className={`glass rounded-lg p-5 border-l-4 ${
                f.severity === 'CRITICAL' ? 'border-red-600' :
                f.severity === 'HIGH' ? 'border-orange-500' :
                f.severity === 'MEDIUM' ? 'border-yellow-500' : 'border-green-500'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className="flex-1 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 text-xs rounded border badge-${f.severity.toLowerCase()}`}>
                      {f.severity}
                    </span>
                    <span className={`px-2 py-0.5 text-xs rounded border badge-${f.result.toLowerCase()}`}>
                      {f.result}
                    </span>
                    <span className="font-mono text-xs text-[#005bb5]">{f.attack_id}</span>
                    <span className="text-xs text-gray-500">{f.category.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="text-sm text-gray-800 font-medium">
                    {OWASP_MAP[f.category] || 'Security Finding'}
                  </div>
                  <div className="text-xs text-gray-500">{f.reason}</div>
                  <div className="flex gap-4 text-xs text-gray-500 pt-1">
                    <span>OWASP: <span className="text-gray-500">{OWASP_MAP[f.category] || 'N/A'}</span></span>
                    <span>Oracle: <span className="font-mono text-gray-500">{(f as any).oracle_ref || 'N/A'}</span></span>
                    <span>{f.elapsed_ms}ms</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
