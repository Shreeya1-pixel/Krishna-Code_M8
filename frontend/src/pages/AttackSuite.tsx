import React, { useEffect, useState } from 'react'
import { Zap, Filter } from 'lucide-react'
import { api, Attack } from '../lib/api'

const CATEGORY_COLORS: Record<string, string> = {
  direct_injection: 'category-direct',
  indirect_injection: 'category-indirect',
  tool_misuse: 'category-tool',
  exfiltration: 'category-exfil',
  multilingual: 'category-multilingual',
  obfuscated: 'category-obfuscated',
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-600 border-red-200 bg-red-50',
  HIGH: 'text-orange-700 border-orange-200 bg-orange-50',
  MEDIUM: 'text-amber-800 border-amber-200 bg-amber-50',
  LOW: 'text-green-700 border-green-200 bg-green-50',
}

export default function AttackSuite() {
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [filter, setFilter] = useState<string>('all')
  const [selected, setSelected] = useState<Attack | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.attackSuite().then(d => {
      setAttacks(d.attacks)
      setCategories(d.categories)
      setLoading(false)
    })
  }, [])

  const filtered = filter === 'all' ? attacks : attacks.filter(a => a.category === filter)

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <Zap size={24} className="text-amber-600" />
        <h1 className="text-xl font-bold text-gray-800">Attack Suite</h1>
        <span className="text-sm text-gray-500">— {attacks.length} attacks across {categories.length} categories</span>
      </div>

      {/* Category filter */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter size={14} className="text-gray-500" />
        <button
          onClick={() => setFilter('all')}
          className={`px-3 py-1 text-xs rounded-full border transition ${filter === 'all' ? 'bg-[#005bb5] text-white border-[#005bb5]' : 'border-gray-200 text-gray-500 hover:bg-blue-50 hover:text-[#005bb5]'}`}
        >
          All ({attacks.length})
        </button>
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className={`px-3 py-1 text-xs rounded-full border transition ${
              filter === cat
                ? 'bg-[#005bb5] text-white border-[#005bb5]'
                : `border-gray-200 text-gray-500 hover:bg-blue-50 hover:text-[#005bb5]`
            }`}
          >
            {cat.replace(/_/g, ' ')} ({attacks.filter(a => a.category === cat).length})
          </button>
        ))}
      </div>

      {loading ? (
        <div className="text-gray-500 text-sm">Loading attacks...</div>
      ) : (
        <div className="grid gap-2">
          {filtered.map(attack => (
            <div
              key={attack.id}
              onClick={() => setSelected(attack === selected ? null : attack)}
              className={`glass rounded-lg p-4 cursor-pointer transition-all hover:shadow-md ${
                selected?.id === attack.id ? 'result-row-selected' : ''
              }`}
            >
              <div className="flex items-start gap-3">
                <span className="font-mono text-xs text-gray-500 mt-0.5 w-12 flex-shrink-0">{attack.id}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`px-2 py-0.5 text-xs rounded-full border font-semibold ${CATEGORY_COLORS[attack.category] || 'text-gray-500 border-gray-200 bg-white'}`}>
                      {attack.category.replace(/_/g, ' ')}
                    </span>
                    <span className={`px-2 py-0.5 text-xs rounded-full border font-semibold ${SEV_COLORS[attack.severity_if_success] || ''}`}>
                      {attack.severity_if_success}
                    </span>
                    <span className="text-xs text-gray-500 font-mono">{attack.oracle_ref}</span>
                  </div>
                  <p className="text-sm text-gray-700 mt-1">{attack.description}</p>

                  {/* Expanded detail */}
                  {selected?.id === attack.id && (
                    <div className="mt-3 space-y-2">
                      <div>
                        <div className="text-xs text-gray-500 mb-1">Payload / User Query</div>
                        <pre className="text-xs bg-gray-50 text-gray-800 border border-gray-200 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap">
                          {attack.payload.slice(0, 500)}
                        </pre>
                      </div>
                      <div>
                        <div className="text-xs text-gray-500 mb-1">Expected behavior (secure agent)</div>
                        <div className="text-xs text-gray-700 bg-gray-50 rounded p-2">{attack.expected_behavior}</div>
                      </div>
                      {attack.mitre.length > 0 && (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-gray-500">MITRE ATLAS:</span>
                          {attack.mitre.map(m => (
                            <span key={m} className="px-2 py-0.5 text-xs bg-blue-50 text-[#005bb5] border border-blue-200 rounded font-mono">{m}</span>
                          ))}
                        </div>
                      )}
                      {attack.doc_name && (
                        <div className="text-xs text-orange-600">
                          📄 Indirect injection via: <span className="font-mono">{attack.doc_name}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <div className="text-gray-400 text-xs">{selected?.id === attack.id ? '▲' : '▼'}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
