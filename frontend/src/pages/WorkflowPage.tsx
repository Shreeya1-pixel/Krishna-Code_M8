import React, { useEffect, useState } from 'react'
import { Workflow, CheckCircle, XCircle, Bell, Bug, ExternalLink } from 'lucide-react'
import { api } from '../lib/api'
import WorkflowGraph, { WorkflowNodeId } from '../components/WorkflowGraph'

const NODE_COPY: Record<WorkflowNodeId, { title: string; body: string }> = {
  assessment: {
    title: 'Assessment',
    body: 'Runs the attack suite against SecureAssist and stores transcripts + oracle scores.',
  },
  triage: {
    title: 'Triage',
    body: 'Groups succeeded attacks by severity so CRITICAL / HIGH findings drive alerts and tickets.',
  },
  gate: {
    title: 'CI Gate',
    body: 'Release decision from ASR threshold and CRITICAL findings. FAIL blocks the release path.',
  },
  slack: {
    title: 'Slack Alert',
    body: 'Posts a vulnerability alert for CRITICAL / HIGH findings. LIVE when SLACK_WEBHOOK_URL is set.',
  },
  jira: {
    title: 'Jira Ticket',
    body: 'Creates a remediation ticket with ATLAS / OWASP context. LIVE when Jira env vars are set.',
  },
  regression: {
    title: 'Regression',
    body: 'Compares this run to the previous baseline: new exploits, fixed exploits, ASR delta.',
  },
}

function descriptionPreview(description: unknown): string {
  if (!description) return ''
  if (typeof description === 'string') return description.slice(0, 400)
  if (typeof description === 'object' && description !== null && 'content' in description) {
    const parts: string[] = []
    const content = (description as { content?: Array<{ content?: Array<{ text?: string }> }> }).content || []
    for (const block of content) {
      for (const node of block.content || []) {
        if (node.text) parts.push(node.text)
      }
    }
    return parts.join('\n').slice(0, 400)
  }
  return JSON.stringify(description).slice(0, 400)
}

export default function WorkflowPage() {
  const [wf, setWf] = useState<any>(null)
  const [loading, setLoading] = useState(true)
  const [selected, setSelected] = useState<WorkflowNodeId>('gate')

  useEffect(() => {
    api.workflowGate().then(setWf).finally(() => setLoading(false))
  }, [])

  const gate = wf?.status
  const gatePass = gate === 'PASS'
  const slackLive = wf?.integrations?.slack?.configured === true
  const jiraLive = wf?.integrations?.jira?.configured === true
  const jiraProject = wf?.integrations?.jira?.project_key || 'KAN'
  const slackOpenUrl = wf?.integrations?.slack?.open_url || 'https://app.slack.com/'
  const jiraIssueKey = wf?.jira_payload?._issue_key as string | undefined
  const jiraOpenUrl = jiraIssueKey && wf?.integrations?.jira?.browse_base
    ? `${wf.integrations.jira.browse_base}/${jiraIssueKey}`
    : (wf?.integrations?.jira?.open_url || `https://dubai-team-mki6033f.atlassian.net/jira/software/projects/${jiraProject}`)
  const slackStatus = wf?.slack_payload
    ? (wf.slack_payload._mock ? 'MOCK' : 'SENT')
    : undefined
  const jiraStatus = wf?.jira_payload
    ? (wf.jira_payload._issue_key || (wf.jira_payload._mock ? 'MOCK' : 'QUEUED'))
    : undefined

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-3">
        <Workflow size={24} className="text-[#005bb5]" />
        <div>
          <h1 className="text-xl font-bold text-gray-800">Workflow Pipeline</h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Post-assessment release graph. Click a node for details — this is not a toy toggle strip.
          </p>
        </div>
      </div>

      {loading ? (
        <div className="text-gray-500 text-sm">Loading workflow data...</div>
      ) : (
        <>
          {wf?.integrations && (
            <div className="grid grid-cols-2 gap-4">
              <div className={`glass rounded-lg p-5 border-l-4 ${slackLive ? 'border-green-500' : 'border-purple-500'}`}>
                <div className="flex items-center gap-2">
                  <Bell size={15} className={slackLive ? 'text-green-600' : 'text-purple-600'} />
                  <h2 className="text-sm font-medium text-gray-600">Slack Integration</h2>
                  <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                    slackLive ? 'bg-green-50 text-green-700' : 'bg-white text-gray-500'
                  }`}>
                    {slackLive ? 'LIVE' : 'MOCK'}
                  </span>
                  <a
                    href={slackOpenUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-auto inline-flex items-center gap-1 rounded bg-[#4A154B] px-2.5 py-1 text-xs font-semibold text-white hover:bg-[#611f69]"
                  >
                    Open Slack <ExternalLink size={12} />
                  </a>
                </div>
                <p className="mt-2 text-xs text-gray-500">
                  {slackLive
                    ? 'Webhook configured. CRITICAL / HIGH findings post real alerts to your Slack channel.'
                    : <>Mock preview by default. Set <span className="font-mono text-gray-700">SLACK_WEBHOOK_URL</span> to send real alerts.</>}
                </p>
              </div>
              <div className={`glass rounded-lg p-5 border-l-4 ${jiraLive ? 'border-green-500' : 'border-cyan-500'}`}>
                <div className="flex items-center gap-2">
                  <Bug size={15} className={jiraLive ? 'text-green-600' : 'text-cyan-600'} />
                  <h2 className="text-sm font-medium text-gray-600">Jira Integration</h2>
                  <span className={`rounded-full px-2 py-0.5 text-xs font-semibold ${
                    jiraLive ? 'bg-green-50 text-green-700' : 'bg-white text-gray-500'
                  }`}>
                    {jiraLive ? 'LIVE' : 'MOCK'}
                  </span>
                  <a
                    href={jiraOpenUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="ml-auto inline-flex items-center gap-1 rounded bg-[#0052CC] px-2.5 py-1 text-xs font-semibold text-white hover:bg-[#0747A6]"
                  >
                    {jiraIssueKey ? `Open ${jiraIssueKey}` : 'Open Jira'} <ExternalLink size={12} />
                  </a>
                </div>
                <p className="mt-2 text-xs text-gray-500">
                  {jiraLive
                    ? <>Credentials configured. CRITICAL / HIGH findings create real tickets in project <span className="font-mono text-gray-700">{jiraProject}</span>.</>
                    : <>Mock ticket by default. Set <span className="font-mono text-gray-700">JIRA_BASE_URL</span>, email, token, and project key for real tickets.</>}
                </p>
              </div>
            </div>
          )}

          {!wf || wf.status === 'no_runs' ? (
            <div className="glass rounded-lg p-8 text-center text-gray-500">No workflow data. Run an assessment first.</div>
          ) : (
            <>
              <div className="glass rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <h2 className="text-sm font-medium text-gray-700">Release workflow graph</h2>
                    <p className="text-xs text-gray-400 mt-0.5">
                      Assessment → Triage → CI Gate, then branch to Slack / Jira, then Regression.
                    </p>
                  </div>
                  <div className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                    gatePass
                      ? 'bg-green-50 border-green-200 text-green-700'
                      : 'bg-red-50 border-red-200 text-red-700'
                  }`}>
                    Gate {gate}
                  </div>
                </div>

                <WorkflowGraph
                  selectedId={selected}
                  onSelect={setSelected}
                  gateStatus={gate}
                  slackLive={slackLive}
                  jiraLive={jiraLive}
                  slackStatus={slackStatus}
                  jiraStatus={jiraStatus}
                  hasRegression={Boolean(wf.regression?.has_baseline)}
                />

                <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="text-xs font-semibold text-[#005bb5]">{NODE_COPY[selected].title}</div>
                  <div className="text-xs text-gray-600 mt-1">{NODE_COPY[selected].body}</div>
                </div>
              </div>

              <div className={`glass rounded-lg p-5 border-l-4 ${gatePass ? 'border-green-500' : 'border-red-500'}`}>
                <div className="flex items-center gap-3">
                  {gatePass ? <CheckCircle size={20} className="text-green-600" /> : <XCircle size={20} className="text-red-600" />}
                  <div>
                    <div className={`font-bold text-lg ${gatePass ? 'text-green-600' : 'text-red-600'}`}>
                      CI Gate: {gate}
                    </div>
                    {(wf.reasons || []).map((r: string, i: number) => (
                      <div key={i} className="text-xs text-gray-500 mt-1">→ {r}</div>
                    ))}
                  </div>
                </div>
              </div>

              {wf.slack_payload && (
                <div className="glass rounded-lg p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <Bell size={14} className="text-green-600" />
                    <h2 className="text-sm font-medium text-gray-500">Slack Alert Preview</h2>
                    <span className={`px-2 py-0.5 text-xs rounded ${
                      wf.slack_payload._mock ? 'bg-white text-gray-500' : 'bg-green-50 text-green-700'
                    }`}>
                      {wf.slack_payload._mock ? 'MOCK' : 'SENT'}
                    </span>
                    <a
                      href={slackOpenUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-auto inline-flex items-center gap-1 text-xs font-semibold text-[#4A154B] hover:underline"
                    >
                      Open Slack <ExternalLink size={12} />
                    </a>
                  </div>
                  <pre className="text-xs bg-gray-50 rounded p-3 text-gray-700 overflow-x-auto max-h-48">
                    {JSON.stringify(wf.slack_payload, null, 2).slice(0, 1000)}
                  </pre>
                </div>
              )}

              {wf.jira_payload && (
                <div className="glass rounded-lg p-5">
                  <div className="flex items-center gap-2 mb-3">
                    <Bug size={14} className="text-[#005bb5]" />
                    <h2 className="text-sm font-medium text-gray-500">Jira Issue Preview</h2>
                    <span className={`px-2 py-0.5 text-xs rounded ${
                      wf.jira_payload._mock ? 'bg-white text-gray-500' : 'bg-green-50 text-green-700'
                    }`}>
                      {wf.jira_payload._issue_key
                        ? wf.jira_payload._issue_key
                        : (wf.jira_payload._mock ? 'MOCK' : 'QUEUED')}
                    </span>
                    <a
                      href={jiraOpenUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="ml-auto inline-flex items-center gap-1 text-xs font-semibold text-[#0052CC] hover:underline"
                    >
                      {jiraIssueKey ? `Open ${jiraIssueKey}` : 'Open Jira'} <ExternalLink size={12} />
                    </a>
                  </div>
                  <div className="bg-gray-50 rounded p-3 space-y-2 text-xs">
                    <div><span className="text-gray-500">Summary: </span><span className="text-gray-800">{wf.jira_payload?.fields?.summary}</span></div>
                    <div><span className="text-gray-500">Priority: </span><span className="text-red-600">{wf.jira_payload?.fields?.priority?.name || '—'}</span></div>
                    <div><span className="text-gray-500">Labels: </span><span className="text-gray-700">{(wf.jira_payload?.fields?.labels || []).join(', ')}</span></div>
                    <div className="mt-2">
                      <div className="text-gray-500 mb-1">Description preview:</div>
                      <pre className="text-gray-500 whitespace-pre-wrap text-xs max-h-32 overflow-y-auto">{descriptionPreview(wf.jira_payload?.fields?.description)}</pre>
                    </div>
                  </div>
                </div>
              )}

              {wf.regression && wf.regression.has_baseline && (
                <div className="glass rounded-lg p-5">
                  <h2 className="text-sm font-medium text-gray-500 mb-3">Regression Tracking</h2>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div className="bg-red-50 border border-red-200 rounded p-3">
                      <div className="text-red-600 font-bold text-lg">{wf.regression.new_exploits?.length || 0}</div>
                      <div className="text-gray-500">New Exploits</div>
                    </div>
                    <div className="bg-green-50 border border-green-200 rounded p-3">
                      <div className="text-green-600 font-bold text-lg">{wf.regression.fixed_exploits?.length || 0}</div>
                      <div className="text-gray-500">Fixed</div>
                    </div>
                    <div className="bg-blue-50 border border-blue-200 rounded p-3">
                      <div className="text-[#005bb5] font-bold text-lg">{((wf.regression.asr_delta || 0) * 100).toFixed(1)}%</div>
                      <div className="text-gray-500">ASR Delta</div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  )
}
