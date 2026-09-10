import React, { useEffect, useState } from 'react'
import { Shield, AlertTriangle, CheckCircle, XCircle, TrendingDown, Activity } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { api, Run, AttackResult } from '../lib/api'
import ScoreGauge from '../components/ScoreGauge'

export default function Dashboard() {
  const [runs, setRuns] = useState<Run[]>([])
  const [latestRun, setLatestRun] = useState<{ run: Run; attacks: AttackResult[] } | null>(null)
  const [vulnRun, setVulnRun] = useState<{ run: Run; attacks: AttackResult[] } | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    try {
      const { runs } = await api.runs(20)
      setRuns(runs)

      // Get latest defended run
      const defended = runs.find(r => r.mode === 'defended' && r.status === 'completed')
      if (defended) {
        const detail = await api.runDetail(defended.id)
        setLatestRun(detail as any)
      }

      // Get latest vulnerable run for comparison
      const vuln = runs.find(r => r.mode === 'vulnerable' && r.status === 'completed')
      if (vuln) {
        const detail = await api.runDetail(vuln.id)
        setVulnRun(detail as any)
      }
    } catch (e) {
      console.error('Dashboard load error', e)
    }
    setLoading(false)
  }

  const defRun = latestRun?.run
  const vulnRunData = vulnRun?.run

  // Category breakdown
  const attacks = latestRun?.attacks || []
  const categories = [...new Set(attacks.map(a => a.category))]
  const categoryData = categories.map(cat => ({
    name: cat.replace('_', ' '),
    succeeded: attacks.filter(a => a.category === cat && a.result === 'SUCCEEDED').length,
    partial: attacks.filter(a => a.category === cat && a.result === 'PARTIAL').length,
    blocked: attacks.filter(a => a.category === cat && a.result === 'BLOCKED').length,
  }))

  const criticalFindings = attacks.filter(a => a.severity === 'CRITICAL' && a.result === 'SUCCEEDED')

  if (loading) {
    return (
      <div className="flex items-center gap-3 text-gray-500">
        <Activity className="animate-spin" size={20} />
        Loading dashboard data...
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <Shield size={28} className="text-[#005bb5]" />
            <h1 className="text-2xl font-bold text-gray-800">M8 Dashboard</h1>
          </div>
          <p className="text-gray-500 text-sm mt-1">Adaptive Red-Team Testing for AI Agents — SCD 2026</p>
        </div>
        <button onClick={loadData} className="px-3 py-1.5 text-sm bg-white hover:bg-gray-50 border border-gray-200 text-gray-700 rounded-lg transition">
          ↻ Refresh
        </button>
      </div>

      {!defRun && !vulnRunData ? (
        <div className="glass rounded-lg p-8 text-center text-gray-500">
          <Shield size={40} className="mx-auto mb-3 opacity-30" />
          <p className="text-lg">No assessment data yet.</p>
          <p className="text-sm mt-1">Go to <span className="text-[#005bb5]">Run Assessment</span> to start your first security test.</p>
        </div>
      ) : (
        <>
          {/* Score gauges */}
          <div className="grid grid-cols-2 gap-6">
            <div className="glass rounded-lg p-6">
              <h2 className="text-sm font-medium text-gray-500 mb-4">Attack Success Rate — Before vs After</h2>
              <div className="flex items-center justify-around">
                <div className="text-center">
                  <div className="text-xs text-gray-500 mb-2">VULNERABLE (Before)</div>
                  <ScoreGauge value={vulnRunData?.asr || 0.64} label="ASR Vulnerable" />
                </div>
                <div className="flex flex-col items-center gap-2">
                  <TrendingDown className="text-green-600" size={20} />
                  <div className="text-green-600 font-bold text-lg">
                    {vulnRunData && defRun ? 
                      `-${Math.round(((vulnRunData.asr || 0) - (defRun.asr || 0)) * 100)}pp` : 
                      '↓'}
                  </div>
                  <div className="text-xs text-gray-500">improvement</div>
                </div>
                <div className="text-center">
                  <div className="text-xs text-gray-500 mb-2">DEFENDED (After)</div>
                  <ScoreGauge value={defRun?.asr || 0.15} label="ASR Defended" />
                </div>
              </div>
            </div>

            {/* Metric cards */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'Total Attacks', value: defRun?.total_attacks || attacks.length, icon: Activity, color: 'text-[#005bb5]' },
                { label: 'Blocked', value: defRun?.blocked_count || 0, icon: CheckCircle, color: 'text-green-600' },
                { label: 'Partial', value: defRun?.partial_count || 0, icon: AlertTriangle, color: 'text-amber-600' },
                { label: 'Succeeded', value: defRun?.succeeded_count || 0, icon: XCircle, color: 'text-red-600' },
              ].map(({ label, value, icon: Icon, color }) => (
                <div key={label} className="glass rounded-lg p-4 flex flex-col gap-2">
                  <div className="flex items-center gap-2">
                    <Icon size={16} className={color} />
                    <span className="text-xs text-gray-500">{label}</span>
                  </div>
                  <div className={`text-3xl font-bold ${color}`}>{value}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Category breakdown chart */}
          <div className="glass rounded-lg p-5">
            <h2 className="text-sm font-medium text-gray-500 mb-4">Attack Results by Category</h2>
            {categoryData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={categoryData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 11 }} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ background: '#ffffff', border: '1px solid #e5e7eb', borderRadius: 8 }}
                    labelStyle={{ color: '#4b5563' }}
                  />
                  <Legend />
                  <Bar dataKey="succeeded" fill="#ef4444" name="Succeeded" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="partial" fill="#f97316" name="Partial" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="blocked" fill="#22c55e" name="Blocked" radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-40 flex items-center justify-center text-gray-400">No data yet</div>
            )}
          </div>

          {/* Critical findings */}
          <div className="glass rounded-lg p-5">
            <div className="flex items-center gap-2 mb-4">
              <XCircle size={16} className="text-red-600" />
              <h2 className="text-sm font-medium text-gray-500">Critical Findings</h2>
              <span className="ml-auto px-2 py-0.5 bg-red-50 text-red-600 text-xs rounded-full border border-red-200">
                {criticalFindings.length} critical
              </span>
            </div>

            {criticalFindings.length === 0 ? (
              <div className="text-gray-400 text-sm">No critical findings in the latest run. ✓</div>
            ) : (
              <div className="space-y-2">
                {criticalFindings.slice(0, 5).map(f => (
                  <div key={f.id} className="flex items-start gap-3 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <span className="px-1.5 py-0.5 bg-red-50 text-red-600 text-xs rounded border border-red-200 flex-shrink-0">
                      {f.attack_id}
                    </span>
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-red-700 font-medium">{f.category}</div>
                      <div className="text-xs text-gray-500 mt-0.5 truncate">{f.reason}</div>
                    </div>
                    <span className="badge-critical px-2 py-0.5 text-xs rounded">CRITICAL</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
