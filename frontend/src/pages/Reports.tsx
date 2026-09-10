import React, { useEffect, useState } from 'react'
import { FileText, Download } from 'lucide-react'
import { api } from '../lib/api'

export default function Reports() {
  const [runs, setRuns] = useState<any[]>([])
  const [selectedRun, setSelectedRun] = useState<string>('')
  const [report, setReport] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.runs(10).then(d => {
      const completed = d.runs.filter(r => r.status === 'completed')
      setRuns(completed)
      if (completed.length > 0) setSelectedRun(completed[0].id)
    })
  }, [])

  const loadReport = async () => {
    if (!selectedRun) return
    setLoading(true)
    const r = await api.reportJson(selectedRun)
    setReport(r)
    setLoading(false)
  }

  useEffect(() => {
    if (selectedRun) loadReport()
  }, [selectedRun])

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <FileText size={24} className="text-[#005bb5]" />
        <h1 className="text-xl font-bold text-gray-800">Reports</h1>
      </div>

      {/* Run selector + export */}
      <div className="glass rounded-lg p-5 flex items-center gap-4">
        <div className="flex-1">
          <div className="text-xs text-gray-500 mb-1">Select Run</div>
          <select
            value={selectedRun}
            onChange={e => setSelectedRun(e.target.value)}
            className="w-full bg-gray-50 border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:border-blue-600"
          >
            {runs.map(r => (
              <option key={r.id} value={r.id}>
                {r.mode.toUpperCase()} | {r.started_at?.slice(0, 16)} | ASR: {(r.asr * 100).toFixed(1)}%
              </option>
            ))}
          </select>
        </div>

        {selectedRun && (
          <a
            href={api.reportPdfUrl(selectedRun)}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 px-4 py-2 bg-[#005bb5] hover:bg-[#0066cc] text-white text-sm rounded-lg transition"
          >
            <Download size={14} />
            Export PDF
          </a>
        )}
      </div>

      {loading ? (
        <div className="text-gray-500 text-sm">Loading report...</div>
      ) : report ? (
        <div className="space-y-4">
          {/* Executive summary */}
          <div className="glass rounded-lg p-5">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Executive Summary</h2>
            <div className="grid grid-cols-5 gap-4 text-xs">
              {[
                { label: 'Mode', value: report.executive_summary?.mode?.toUpperCase() },
                { label: 'Total Attacks', value: report.executive_summary?.total_attacks },
                { label: 'ASR', value: `${((report.executive_summary?.asr || 0) * 100).toFixed(1)}%` },
                { label: 'Utility', value: report.executive_summary?.utility_rate != null ? `${((report.executive_summary.utility_rate || 0) * 100).toFixed(1)}%` : 'N/A' },
                { label: 'Gate', value: report.executive_summary?.gate_status },
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-50 rounded p-3">
                  <div className="text-gray-500">{label}</div>
                  <div className="text-gray-800 font-bold text-lg">{value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Most dangerous successful attack */}
          <div className="glass rounded-lg p-5 border-l-4 border-red-500">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Most Dangerous Successful Attack</h2>
            {report.most_dangerous_successful_attack ? (
              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-red-600">{report.most_dangerous_successful_attack.attack_id}</span>
                  <span className="rounded bg-red-50 px-2 py-0.5 text-red-700">{report.most_dangerous_successful_attack.severity}</span>
                  <span className="text-gray-500">{report.most_dangerous_successful_attack.category}</span>
                </div>
                <div className="font-medium text-gray-800">{report.most_dangerous_successful_attack.description}</div>
                <div className="text-gray-500">{report.most_dangerous_successful_attack.production_impact}</div>
              </div>
            ) : (
              <div className="text-sm text-gray-400">No successful attack observed in this run.</div>
            )}
          </div>

          {/* Category ASR */}
          <div className="glass rounded-lg p-5">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Attack Success Rate by Category</h2>
            <div className="grid grid-cols-3 gap-3 text-xs">
              {Object.entries(report.category_summary || {}).map(([category, stats]: [string, any]) => (
                <div key={category} className="rounded border border-gray-200 bg-gray-50 p-3">
                  <div className="font-semibold text-gray-700">{category.replace(/_/g, ' ')}</div>
                  <div className="mt-1 text-lg font-bold text-[#005bb5]">{((stats.asr || 0) * 100).toFixed(1)}%</div>
                  <div className="text-gray-500">
                    {stats.succeeded} succeeded / {stats.total} tested
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Indirect injection demo */}
          {report.indirect_injection_demo && (
            <div className="glass rounded-lg p-5 border-l-4 border-orange-500">
              <h2 className="text-sm font-medium text-gray-500 mb-2">Poisoned Document Demo Beat</h2>
              <div className="text-xs text-gray-600">
                <span className="font-mono text-orange-600">{report.indirect_injection_demo.document}</span>
                {' '}maps to <span className="font-mono">{report.indirect_injection_demo.attack_id}</span>: {report.indirect_injection_demo.demo_beat}
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 text-xs text-amber-800">
            ⚠️ {report.disclaimer}
          </div>

          {/* Critical findings */}
          <div className="glass rounded-lg p-5">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Critical Findings ({(report.critical_findings || []).length})</h2>
            {(report.critical_findings || []).length === 0 ? (
              <div className="text-gray-400 text-sm">No critical findings.</div>
            ) : (
              <div className="space-y-2">
                {(report.critical_findings || []).map((f: any, i: number) => (
                  <div key={i} className="bg-red-50 border border-red-200 rounded p-3 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-red-600">{f.attack_id}</span>
                      <span className="text-gray-500">{f.category}</span>
                      <span className="ml-auto text-red-600">{f.owasp_ref}</span>
                    </div>
                    <div className="text-gray-500 mt-1">{f.reason}</div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Residual risks */}
          <div className="glass rounded-lg p-5">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Residual Risks (Honest Assessment)</h2>
            <div className="space-y-1.5">
              {(report.residual_risks || []).map((risk: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-xs text-gray-500">
                  <span className="text-orange-600 mt-0.5">•</span>
                  <span>{risk}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Methodology */}
          <div className="glass rounded-lg p-5">
            <h2 className="text-sm font-medium text-gray-500 mb-3">Methodology</h2>
            <div className="grid grid-cols-2 gap-3 text-xs">
              {Object.entries(report.methodology || {}).map(([k, v]) => (
                <div key={k}>
                  <span className="text-gray-500">{k.replace(/_/g, ' ')}: </span>
                  <span className="text-gray-700">{Array.isArray(v) ? (v as string[]).join(', ') : String(v)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      ) : (
        <div className="glass rounded-lg p-8 text-center text-gray-500">
          No report data available. Run an assessment first.
        </div>
      )}
    </div>
  )
}
