/**
 * M8 typed API client + SSE client
 */

const BASE =
  import.meta.env.VITE_API_URL ||
  (import.meta.env.PROD ? '' : 'http://localhost:8000');

// ── Types ────────────────────────────────────────────────────────────────────

export interface Run {
  id: string;
  mode: string;
  suite_type: string;
  started_at: string;
  completed_at?: string;
  status: string;
  total_attacks: number;
  succeeded_count: number;
  partial_count: number;
  blocked_count: number;
  asr: number;
  ur: number;
  defense_config_json: string;
}

export interface AttackResult {
  id: number;
  run_id: string;
  attack_id: string;
  category: string;
  result: 'SUCCEEDED' | 'PARTIAL' | 'BLOCKED';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  transcript_json: Record<string, unknown>;
  tool_calls_json: unknown[];
  node_trace_json: unknown[];
  elapsed_ms: number;
  escalation_path_json: unknown[];
}

export interface Attack {
  id: string;
  category: string;
  description: string;
  payload: string;
  user_query: string;
  doc_name?: string;
  expected_behavior: string;
  severity_if_success: string;
  oracle_ref: string;
  mitre: string[];
}

export interface NodeEvent {
  node: string;
  input_summary: string;
  output_summary: string;
  decision?: string;
  reason?: string;
  elapsed_ms: number;
  checkpoint_hash: string;
  timestamp: string;
}

export interface WorkflowResult {
  status?: string;
  gate_status?: string;
  gate_reasons?: string[];
  reasons?: string[];
  slack_payload?: Record<string, unknown> & {
    _mock?: boolean;
    _delivery_status?: string;
    _issue_key?: string;
  };
  jira_payload?: Record<string, unknown> & {
    _mock?: boolean;
    _delivery_status?: string;
    _issue_key?: string;
    fields?: {
      summary?: string;
      priority?: { name?: string };
      labels?: string[];
      description?: string | Record<string, unknown>;
    };
  };
  regression?: Record<string, unknown>;
  run_id?: string;
  integrations?: {
    slack: { mode: string; configured: boolean; label: string; open_url?: string };
    jira: {
      mode: string;
      configured: boolean;
      label: string;
      project_key?: string;
      open_url?: string;
      browse_base?: string;
    };
  };
}

export interface BayesianStatus {
  updated_alpha: number;
  updated_beta: number;
  new_threshold: number;
  block_threshold: number;
  warn_threshold: number;
  threshold_95_low: number;
  threshold_95_high: number;
  confidence: string;
  class_thresholds: Record<string, number>;
  drift_alert: boolean;
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options?.headers || {}),
    },
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`API ${resp.status}: ${text}`);
  }
  return resp.json();
}

// ── API methods ───────────────────────────────────────────────────────────────

export const api = {
  health: () => apiFetch<{ status: string; version: string; offline_mode: boolean }>('/health'),

  agentInfo: () => apiFetch<{
    name: string;
    description: string;
    system_prompt_redacted: string;
    system_prompt_hint: string;
    tools: Array<{ name: string; description: string; is_sensitive: boolean }>;
    documents: string[];
    llm_provider: string;
  }>('/agent/info'),

  agentTurn: (user_input: string, mode: string) =>
    apiFetch<{ final_response: string; node_trace: NodeEvent[]; tool_requests: unknown[] }>(
      '/agent/turn',
      { method: 'POST', body: JSON.stringify({ user_input, mode }) }
    ),

  attackSuite: () => apiFetch<{ attacks: Attack[]; total: number; categories: string[] }>('/attacks/suite'),

  attackDetail: (id: string) => apiFetch<Attack>(`/attacks/${id}`),

  runs: (limit = 50) => apiFetch<{ runs: Run[]; total: number }>(`/assessment/runs?limit=${limit}`),

  runDetail: (id: string) => apiFetch<{ run: Run; attacks: AttackResult[]; workflow: WorkflowResult }>(`/assessment/runs/${id}`),

  workflowGate: () => apiFetch<WorkflowResult>('/workflow/gate'),

  workflowRunDetail: (run_id: string) => apiFetch<WorkflowResult>(`/workflow/runs/${run_id}`),

  reportJson: (run_id: string) => apiFetch<Record<string, unknown>>(`/reports/${run_id}/json`),

  reportPdfUrl: (run_id: string) => `${BASE}/reports/${run_id}/pdf`,
  latestPdfUrl: () => `${BASE}/reports/latest/pdf`,

  defenseStatus: () => apiFetch<{
    bayesian_threshold: BayesianStatus;
    drift: { drift_detected: boolean; psi_scores: Record<string, number>; alert_count: number };
    controls: Record<string, string>;
  }>('/defenses/status'),

  bayesianFeedback: (data: {
    scan_id?: string;
    human_verdict: string;
    original_decision: string;
    attack_class: string;
  }) => apiFetch<BayesianStatus>('/defenses/bayesian/feedback', {
    method: 'POST',
    body: JSON.stringify(data),
  }),

  loraplan: (run_id?: string) => apiFetch<Record<string, unknown>>('/defenses/lora/plan', {
    method: 'POST',
    body: JSON.stringify({ run_id }),
  }),

  classify: (text: string, check_doc_content = false) => apiFetch<Record<string, unknown>>('/defenses/classify', {
    method: 'POST',
    body: JSON.stringify({ text, check_doc_content }),
  }),
};

// ── SSE client ────────────────────────────────────────────────────────────────

export type SSEEvent = {
  type: string;
  data: Record<string, unknown>;
};

export function startAssessment(
  mode: string,
  suiteType: string,
  onEvent: (event: SSEEvent) => void,
  onDone: () => void,
  onError: (e: Error) => void,
): () => void {
  const controller = new AbortController();

  fetch(`${BASE}/assessment/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'text/event-stream' },
    body: JSON.stringify({ mode, suite_type: suiteType }),
    signal: controller.signal,
  }).then(async (resp) => {
    if (!resp.ok || !resp.body) {
      onError(new Error(`Assessment failed: ${resp.status}`));
      return;
    }
    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let currentEvent = 'message';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('event:')) {
          currentEvent = line.slice(6).trim();
        } else if (line.startsWith('data:')) {
          try {
            const data = JSON.parse(line.slice(5).trim());
            onEvent({ type: currentEvent, data });
            if (currentEvent === 'done') onDone();
          } catch {}
          currentEvent = 'message';
        }
      }
    }
    onDone();
  }).catch((e) => {
    if (e.name !== 'AbortError') onError(e);
  });

  return () => controller.abort();
}
