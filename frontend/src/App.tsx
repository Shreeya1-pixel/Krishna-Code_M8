import React from 'react'
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom'
import { Shield, Activity, Target, Play, Search, Lock, Workflow, FileText, Zap } from 'lucide-react'
import Dashboard from './pages/Dashboard'
import TargetAgent from './pages/TargetAgent'
import AttackSuite from './pages/AttackSuite'
import RunAssessment from './pages/RunAssessment'
import Findings from './pages/Findings'
import Evidence from './pages/Evidence'
import Defences from './pages/Defences'
import WorkflowPage from './pages/WorkflowPage'
import Reports from './pages/Reports'

const NAV_ITEMS = [
  { path: '/', label: 'Dashboard', icon: Activity },
  { path: '/agent', label: 'Target Agent', icon: Target },
  { path: '/attacks', label: 'Attack Suite', icon: Zap },
  { path: '/run', label: 'Run Assessment', icon: Play },
  { path: '/findings', label: 'Findings', icon: Search },
  { path: '/evidence', label: 'Evidence', icon: FileText },
  { path: '/defences', label: 'Defences', icon: Lock },
  { path: '/workflow', label: 'Workflow', icon: Workflow },
  { path: '/reports', label: 'Reports', icon: FileText },
]

const PAGE_TITLES: Record<string, string> = {
  '/': 'Dashboard',
  '/agent': 'Target Agent',
  '/attacks': 'Attack Suite',
  '/run': 'Run Assessment',
  '/findings': 'Findings',
  '/evidence': 'Evidence',
  '/defences': 'Defences',
  '/workflow': 'Workflow',
  '/reports': 'Reports',
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function NavItem({ path, label, Icon }: { path: string; label: string; Icon: React.ComponentType<any> }) {
  const location = useLocation()
  const active = location.pathname === path

  return (
    <Link
      to={path}
      className={`mx-3 mb-1 flex items-center rounded-md px-3 py-2.5 text-sm font-medium transition-all ${
        active
          ? 'bg-[#005bb5] text-white shadow-sm'
          : 'text-gray-700 hover:bg-white hover:text-[#005bb5] hover:shadow-sm'
      }`}
    >
      <Icon size={16} className={`mr-3 ${active ? 'text-white' : 'text-gray-500'}`} />
      {label}
    </Link>
  )
}

function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const title = PAGE_TITLES[location.pathname] || 'M8'

  return (
    <div className="portal-shell-bg flex h-screen flex-col overflow-hidden">
      {/* Top header — SC portal style */}
      <header className="z-20 h-14 flex-shrink-0 border-b border-blue-100 bg-white/95 backdrop-blur">
        <div className="flex h-full items-center justify-between px-5">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded bg-[#005bb5] shadow-sm">
                <Shield size={16} className="text-white" />
              </div>
              <div>
                <span className="text-sm font-bold text-gray-800">M8</span>
                <div className="-mt-0.5 text-[10px] font-medium uppercase tracking-wide text-[#005bb5]">Adaptive Red Team</div>
              </div>
            </div>
            <div className="hidden items-center rounded-full border border-blue-100 bg-blue-50 px-3 py-1.5 text-sm font-medium text-gray-600 sm:flex">
              Adaptive Red-Team Testing
            </div>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-medium text-amber-800 bg-amber-50 border border-amber-200 rounded-full px-2.5 py-1">
              DEMO DATA ONLY
            </span>
            <div className="w-8 h-8 rounded-full bg-pink-50 text-pink-700 text-xs font-semibold flex items-center justify-center">
              SG
            </div>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <aside className="flex w-60 flex-shrink-0 flex-col overflow-y-auto border-r border-[var(--sidebar-border)] bg-[var(--sidebar-bg)]">
          <div className="px-4 py-3">
            <input
              type="text"
              placeholder="Filter pages..."
              className="w-full rounded border border-blue-100 bg-white px-3 py-2 text-sm shadow-sm focus:border-[#005bb5] focus:outline-none"
              readOnly
            />
          </div>
          <nav className="flex-1 py-1">
            {NAV_ITEMS.map(({ path, label, icon: Icon }) => (
              <NavItem key={path} path={path} label={label} Icon={Icon} />
            ))}
          </nav>
          <div className="border-t border-blue-100 bg-white/45 p-4 text-xs text-gray-500">
            <div className="font-semibold text-gray-700">SCD 2026 · v1.0.0</div>
            <div className="mt-1">Offline demo ready</div>
            <div className="mt-2 h-1 overflow-hidden rounded bg-blue-100">
              <div className="h-full bg-[#005bb5]" style={{ width: '18%' }} />
            </div>
          </div>
        </aside>

        {/* Main */}
        <main className="flex flex-1 flex-col overflow-hidden bg-transparent">
          <div className="flex flex-shrink-0 items-center justify-between border-b border-blue-100 bg-white/80 px-6 py-4 backdrop-blur">
            <div className="flex items-center text-lg font-semibold text-gray-800">
              <span className="mr-2 text-gray-500">📁</span>
              <span>M8</span>
              <span className="mx-2 text-gray-400 text-sm font-normal">›</span>
              <span>{title}</span>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-6">
            <div className="max-w-6xl mx-auto">{children}</div>
          </div>
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agent" element={<TargetAgent />} />
          <Route path="/attacks" element={<AttackSuite />} />
          <Route path="/run" element={<RunAssessment />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/defences" element={<Defences />} />
          <Route path="/workflow" element={<WorkflowPage />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </Layout>
    </Router>
  )
}
