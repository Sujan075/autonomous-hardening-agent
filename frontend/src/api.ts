export type Target = {
  id: string
  name: string
  platform: string
  address?: string | null
  status?: string
  created_at?: string
}

const base = (import.meta.env.VITE_CONTROLLER_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const token = import.meta.env.VITE_API_TOKEN

export async function get<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  let response: Response
  try {
    response = await fetch(`${base}${path}`, { method: 'GET', headers, credentials: 'omit' })
  } catch {
    throw new Error(`Cannot reach Controller at ${base}. Check that it is running and that browser CORS allows this origin.`)
  }
  if (response.status === 401 || response.status === 403) throw Object.assign(new Error('Controller authorization is required for this view.'), { auth: true })
  if (!response.ok) {
    let detail = ''
    try { const body = await response.json(); detail = typeof body.detail === 'string' ? `: ${body.detail}` : '' } catch { /* response has no JSON detail */ }
    throw new Error(`Controller returned HTTP ${response.status}${detail}`)
  }
  try {
    return await response.json() as T
  } catch {
    throw new Error(`Controller returned an invalid JSON response for ${path}.`)
  }
}

export async function getHealth() {
  const value = await get<unknown>('/health')
  if (!isRecord(value) || value.status !== 'ok') malformed('/health', 'expected { status: "ok" }')
  return value as { status: string }
}

export async function getTargets(): Promise<Target[]> {
  const value = await get<unknown>('/api/targets')
  if (!Array.isArray(value)) malformed('/api/targets', 'expected an array')
  return value.map((target, index) => {
    if (!isRecord(target) || !isNonemptyString(target.id) || !isNonemptyString(target.name) || !isNonemptyString(target.platform)) {
      malformed('/api/targets', `target at index ${index} is missing id, name, or platform`)
    }
    if (target.address !== undefined && target.address !== null && typeof target.address !== 'string') malformed('/api/targets', `target at index ${index} has invalid address`)
    if (target.status !== undefined && typeof target.status !== 'string') malformed('/api/targets', `target at index ${index} has invalid status`)
    return target as Target
  })
}

export async function getAgentStatus(targetId: string) {
  const path = `/api/targets/${encodeURIComponent(targetId)}/agent-status`
  const value = await get<unknown>(path)
  if (!isRecord(value) || !isRecord(value.agent) || typeof value.agent.reachable !== 'boolean'
    || (value.agent.status !== undefined && value.agent.status !== null && typeof value.agent.status !== 'string')
    || (value.agent.agent_id !== undefined && value.agent.agent_id !== null && typeof value.agent.agent_id !== 'string')
    || (value.agent.error !== undefined && value.agent.error !== null && typeof value.agent.error !== 'string')) {
    malformed(path, 'expected a target response with agent.reachable as a boolean')
  }
  return value as Record<string, unknown>
}

export async function getAssessment(targetId: string) {
  const path = `/api/targets/${encodeURIComponent(targetId)}/assessment`
  const value = await get<unknown>(path)
  if (!isRecord(value) || !isNonemptyString(value.target_id) || !isNonemptyString(value.target_name)
    || !isRecord(value.assessment) || !isNonemptyString(value.assessment.platform) || !Array.isArray(value.assessment.findings)
    || !isNonemptyString(value.assessment_observation_id) || !isNonemptyString(value.assessment_trust_status)
    || !isNonemptyString(value.policy_status) || !isRecord(value.policy)) {
    malformed(path, 'expected assessment.platform and an assessment.findings array')
  }
  value.assessment.findings.forEach((finding, index) => {
    if (!isRecord(finding) || !isNonemptyString(finding.control_id) || !isNonemptyString(finding.title)
      || !isNonemptyString(finding.status) || !isNonemptyString(finding.severity)) {
      malformed(path, `finding at index ${index} is missing a required field`)
    }
    if (finding.evidence !== undefined && !Array.isArray(finding.evidence)) malformed(path, `finding at index ${index} has invalid evidence`)
    if (Array.isArray(finding.evidence) && finding.evidence.some((entry) => !isRecord(entry)
      || typeof entry.name !== 'string' || typeof entry.value !== 'string' || typeof entry.source !== 'string')) {
      malformed(path, `finding at index ${index} has malformed evidence entries`)
    }
  })
  return value as Record<string, unknown>
}

export async function getPlan(targetId: string) {
  const path = `/api/targets/${encodeURIComponent(targetId)}/plan`
  const value = await get<unknown>(path)
  if (!isRecord(value) || !isRecord(value.plan) || !isNonemptyString(value.plan.status) || !Array.isArray(value.plan.actions)) {
    malformed(path, 'expected plan.status and a plan.actions array')
  }
  value.plan.actions.forEach((action, index) => {
    if (!isRecord(action) || !isNonemptyString(action.action_id) || !isNonemptyString(action.title)
      || !isNonemptyString(action.execution_mode)) malformed(path, `action at index ${index} is malformed`)
  })
  return value as Record<string, unknown>
}

export function controllerUrl() { return base }

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isNonemptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}

function malformed(path: string, detail: string): never {
  throw new Error(`Controller returned malformed ${path} response: ${detail}.`)
}
