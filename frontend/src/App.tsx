import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUpRight, ArrowUpRight as External,
  Boxes, Check, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, CircleHelp,
  Cloud, Cpu, Database, FileCheck2, Filter, Globe2, HardDrive, Layers3,
  LockKeyhole, Menu, Monitor, MoreHorizontal, Network, RefreshCw, Search, Server,
  Shield, ShieldAlert, ShieldCheck, ShieldHalf, SlidersHorizontal, Terminal,
} from 'lucide-react'
import { controllerUrl, getAgentStatus, getAssessment, getDiscovery, getHealth, getPlan, getTargets, getRemediationRuns, getDecoyEvents, getAuditEvents, type Target, type DemoRemediationRun, type DemoDecoyEvent, type AuditEvent } from './api'
import { filterByCategory, normalizeFindingStatus, resourcePhase } from './presentation'

type View = 'Overview' | 'Environments' | 'Findings' | 'Remediation plan' | 'Validation sandbox' | 'Decoy monitor' | 'Audit & evidence'
type Finding = { id: string; control: string; title: string; environment: string; severity: string; status: string; message?: string; evidence?: string; observed?: string; expected?: string }
type ResourceState<T> = { loading: boolean; value: T | null; error: string; auth: boolean }
const nav = [
  { label: 'Overview', icon: Layers3 }, { label: 'Environments', icon: Server }, { label: 'Findings', icon: ShieldAlert },
  { label: 'Remediation plan', icon: FileCheck2 }, { label: 'Validation sandbox', icon: Terminal }, { label: 'Decoy monitor', icon: Activity }, { label: 'Audit & evidence', icon: Database },
] as const
const platforms = [
  { name: 'Ubuntu', detail: '24.04 · ARM64', icon: Server, state: 'READ ONLY', tone: 'blue', count: 'Captured assessment evidence · execution disabled' },
  { name: 'CentOS', detail: 'Stream 9 · ARM64', icon: HardDrive, state: 'READ ONLY', tone: 'blue', count: '4-control assessment adapter · remediation blocked' },
  { name: 'Windows', detail: 'Server / Desktop', icon: Monitor, state: 'NOT STARTED', tone: 'muted', count: 'No platform adapter' },
  { name: 'Docker', detail: 'Container runtime', icon: Boxes, state: 'NOT STARTED', tone: 'muted', count: 'No container adapter' },
  { name: 'AWS Cloud', detail: 'Guest + control plane', icon: Cloud, state: 'NOT STARTED', tone: 'muted', count: 'Separate scopes' },
  { name: 'Edge ARM64', detail: 'Linux devices', icon: Cpu, state: 'PARTIAL', tone: 'blue', count: 'Build verified only · assessment BLOCKED' },
]
function useResource<T>() {
  const [state, setState] = useState<ResourceState<T>>({ loading: false, value: null, error: '', auth: false })
  const reset = useCallback(() => setState({ loading: false, value: null, error: '', auth: false }), [])
  const load = useCallback(async (request: () => Promise<T>) => {
    setState({ loading: true, value: null, error: '', auth: false })
    try { setState({ loading: false, value: await request(), error: '', auth: false }) }
    catch (e) { const err = e as Error & { auth?: boolean }; setState((s) => ({ ...s, loading: false, error: err.message || 'Request failed', auth: Boolean(err.auth) })) }
  }, [])
  return [state, load, reset] as const
}

function App() {
  const [view, setView] = useState<View>('Overview')
  const [collapsed, setCollapsed] = useState(false)
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [envFilter, setEnvFilter] = useState('All environments')
  const [severityFilter, setSeverityFilter] = useState('All severities')
  const [statusFilter, setStatusFilter] = useState('All statuses')
  const [targets, loadTargets] = useResource<Target[]>()
  const [health, loadHealth] = useResource<{ status: string }>()
  const [agent, loadAgent] = useResource<Record<string, unknown>>()
  const [discovery, loadDiscovery] = useResource<Record<string, unknown>>()
  const [assessment, loadAssessment, resetAssessment] = useResource<Record<string, unknown>>()
  const [plan, loadPlan] = useResource<Record<string, unknown>>()

  const refreshInventory = useCallback(() => loadTargets(getTargets), [loadTargets])
  useEffect(() => { void refreshInventory(); void loadHealth(getHealth) }, [refreshInventory, loadHealth])
  useEffect(() => {
    if (targets.error) { setSelectedId(''); return }
    if (targets.value?.length && !targets.value.some((t) => t.id === selectedId)) setSelectedId(targets.value[0].id)
    if (targets.value && targets.value.length === 0) setSelectedId('')
  }, [targets.value, targets.error, selectedId])
  useEffect(() => {
    if (!selectedId) return
    void loadAgent(() => getAgentStatus(selectedId))
    void loadDiscovery(() => getDiscovery(selectedId))
    resetAssessment()
    void loadPlan(() => getPlan(selectedId))
  }, [selectedId, loadAgent, loadDiscovery, resetAssessment, loadPlan])

  const target = targets.value?.find((t) => t.id === selectedId)
  const findings = useMemo(() => normalizeFindings(assessment.value, target), [assessment.value, target])
  const visibleFindings = findings.filter((f) => (envFilter === 'All environments' || f.environment === envFilter)
    && (severityFilter === 'All severities' || f.severity.toLowerCase() === severityFilter.toLowerCase())
    && (statusFilter === 'All statuses' || f.status.toLowerCase() === statusFilter.toLowerCase())
    && `${f.control} ${f.title} ${f.environment}`.toLowerCase().includes(query.toLowerCase()))

  const statusLabel = health.value?.status === 'ok' ? 'Controller online' : health.error ? 'Controller unavailable' : 'Connecting to Controller'
  const go = (v: View) => { setView(v); if (v === 'Findings') window.scrollTo({ top: 0, behavior: 'smooth' }) }

  return <div className="app-shell">
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldCheck size={21}/></div>{!collapsed && <div className="brand-copy"><b>sentinel<span>.</span></b><small>SECURITY OPERATIONS</small></div>}<button className="collapse-btn" onClick={() => setCollapsed(!collapsed)} aria-label="Toggle sidebar">{collapsed ? <ChevronRight size={16}/> : <ChevronLeft size={16}/>}</button></div>
      {!collapsed && <div className="workspace"><div className="workspace-icon">A</div><div><b>Autonomous Hardening</b><small>DEVELOPMENT WORKSPACE</small></div><ChevronDown size={14}/></div>}
      <div className="nav-label">WORKSPACE</div>
      <nav>{nav.map(({ label, icon: Icon }) => <button key={label} className={`nav-item ${view === label ? 'active' : ''}`} title={collapsed ? label : undefined} onClick={() => go(label)}><Icon size={18}/>{!collapsed && <span>{label}</span>}{label === 'Findings' && findings.length > 0 && !collapsed && <em>{findings.length}</em>}</button>)}</nav>
      {!collapsed && <><div className="nav-label systems-label">PLATFORM SCOPE</div><div className="system-link"><span className="dot gray-dot"/>Ubuntu <small>READ ONLY</small></div><div className="system-link faded"><span className="dot amber-dot"/>CentOS <small>READ ONLY</small></div><div className="sidebar-bottom"><div className="side-avatar">LC</div><div><b>Local dashboard</b><small>Identity unavailable</small></div><MoreHorizontal size={17}/></div></>}
    </aside>

    <main className="main-area">
      <header className="topbar"><div className="breadcrumbs"><button className="mobile-menu" onClick={() => setCollapsed(!collapsed)}><Menu size={18}/></button><span>Workspace</span><ChevronRight size={14}/><b>{view}</b></div><div className="top-actions"><div className={`controller-pill ${health.value ? 'online' : health.error ? 'offline' : ''}`}><span className="pulse-dot"/>{statusLabel}</div><div className="top-avatar" title="No authenticated user session">LC</div></div></header>
      <div className="content">
        <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line"/>SECURITY POSTURE / 24 OCT 2026</div><h1>{view === 'Overview' ? 'Security overview' : view}</h1><p>{subtitle(view)}</p></div><div className="heading-actions">{selectedId && <button className="button secondary" onClick={() => void loadAssessment(() => getAssessment(selectedId))} title="This Controller GET records an assessment observation and audit event"><ShieldAlert size={15}/> Collect assessment</button>}<button className="button secondary" onClick={() => { void refreshInventory(); void loadHealth(getHealth); if (selectedId) { void loadAgent(() => getAgentStatus(selectedId)); void loadDiscovery(() => getDiscovery(selectedId)); void loadPlan(() => getPlan(selectedId)) } }}><RefreshCw size={15}/> Refresh</button><button className="button primary" onClick={() => go('Environments')}><Network size={15}/> Environments <ChevronRight size={15}/></button></div></div>

        {view === 'Overview' && <Overview targets={targets} findings={findings} agent={agent} assessment={assessment} plan={plan} health={health} onNavigate={go} />}
        {view === 'Environments' && <Environments targets={targets} selectedId={selectedId} onSelect={setSelectedId} agent={agent} discovery={discovery} assessment={assessment} onRefresh={refreshInventory} onViewFindings={() => go('Findings')} />}
        {view === 'Findings' && <FindingsPage findings={visibleFindings} allFindings={findings} query={query} setQuery={setQuery} env={envFilter} setEnv={setEnvFilter} severity={severityFilter} setSeverity={setSeverityFilter} status={statusFilter} setStatus={setStatusFilter} assessment={assessment} />}
        {view === 'Remediation plan' && <PlanPage plan={plan} target={target} />}
        {view === 'Validation sandbox' && <SandboxPage />}
        {view === 'Decoy monitor' && <DecoyPage />}
        {view === 'Audit & evidence' && <AuditPage target={target} assessment={assessment} plan={plan} />}

        <footer><span><Shield size={14}/> Autonomous Hardening Agent <i>·</i> Dashboard preview</span><span>Controller <code>{controllerUrl()}</code><i>·</i> <a href="https://github.com/Sujan075/autonomous-hardening-agent" target="_blank" rel="noreferrer">Project repo <External size={12}/></a></span></footer>
      </div>
    </main>
  </div>
}

function subtitle(view: View) {
  const copy: Record<View, string> = {
    Overview: 'A clear view of your enrolled targets, current findings, and platform coverage.', Environments: 'Inspect registered targets and the evidence currently available from each agent.',
    Findings: 'Review assessment results. Filters apply to live Controller observations only.', 'Remediation plan': 'Review recommendations independently from approvals and execution.',
    'Validation sandbox': 'Inspect persisted evidence from the local fixed-action OpenSSH fixture.', 'Decoy monitor': 'Inspect safely generated synthetic events with no live listener or remediation connection.', 'Audit & evidence': 'Review Controller observations and the integrity result for its local SQLite audit chain.',
  }
  return copy[view]
}

function Overview({ targets, findings, agent, assessment, plan, health, onNavigate }: { targets: ResourceState<Target[]>; findings: Finding[]; agent: ResourceState<Record<string, unknown>>; assessment: ResourceState<Record<string, unknown>>; plan: ResourceState<Record<string, unknown>>; health: ResourceState<{ status: string }>; onNavigate: (v: View) => void }) {
  const passes = findings.filter((f) => f.status.toLowerCase() === 'pass').length
  const fail = findings.filter((f) => ['fail', 'failed'].includes(f.status.toLowerCase())).length
  return <>
    <div className="notice"><div className="notice-icon"><CircleHelp size={17}/></div><div><b>Evidence-first preview</b><span>Only Controller responses are shown as live. The multi-platform roadmap does not imply those adapters are deployed.</span></div><span className={health.value ? 'live-badge' : 'state-tag muted'}>{health.value ? <><i/> CONTROLLER ONLINE</> : health.loading ? 'CHECKING CONNECTION' : health.error ? 'CONNECTION UNAVAILABLE' : 'UNKNOWN'}</span></div>
    <section className="metric-grid">
      <Metric icon={Globe2} label="REGISTERED TARGETS" value={targets.loading ? '—' : targets.value ? String(targets.value.length) : '—'} sub={targets.error ? 'Inventory unavailable' : targets.value?.length ? 'From Controller inventory' : 'No inventory loaded'} tone="blue" onClick={() => onNavigate('Environments')}/>
      <Metric icon={ShieldAlert} label="CURRENT FINDINGS" value={assessment.loading || assessment.error || !assessment.value ? '—' : String(findings.length)} sub={assessment.error ? 'Assessment unavailable' : assessment.value ? `${fail} require attention · ${passes} passing` : 'NOT RUN · assessment not collected'} tone="amber" onClick={() => onNavigate('Findings')}/>
      <Metric icon={CheckCircle2} label="AGENT CONNECTIVITY" value={agent.loading ? '—' : agent.error ? 'Unknown' : agent.value ? (agentReachable(agent.value) ? 'Online' : 'Offline') : 'Unknown'} sub={agent.error ? 'Status request failed' : agent.value ? 'Controller status response' : 'No target selected'} tone="green" onClick={() => onNavigate('Environments')}/>
      <Metric icon={FileCheck2} label="PLAN READINESS" value={plan.loading ? '—' : plan.error ? 'Unknown' : plan.value ? planStatus(plan.value) : 'Unknown'} sub={plan.error ? 'Plan request failed' : 'Planning is not approval'} tone="violet" onClick={() => onNavigate('Remediation plan')}/>
    </section>
    <div className="section-head"><div><div className="eyebrow">PLATFORM COVERAGE</div><h2>Environment landscape</h2></div><button className="text-button" onClick={() => onNavigate('Environments')}>View targets <ChevronRight size={15}/></button></div>
    <section className="platform-grid">{platforms.map((p) => { const Icon = p.icon; const liveTarget = targets.value?.find((t) => normalizePlatform(t.platform) === p.name); return <button className="platform-card" key={p.name} onClick={() => onNavigate('Environments')}><div className="platform-card-top"><div className="platform-icon"><Icon size={19}/></div><span className={`state-tag ${p.tone}`}>{p.state}</span></div><h3>{p.name}</h3><p>{p.detail}</p><div className="platform-foot"><span>{liveTarget ? 'Registered target found' : p.count}</span><span className={`dot ${liveTarget ? 'green-dot' : p.tone === 'amber' ? 'amber-dot' : 'gray-dot'}`}/></div></button> })}</section>
    <div className="two-col overview-bottom">
      <section className="panel"><div className="panel-head"><div><h2>Recent findings</h2><p>Latest Controller assessment results</p></div><button className="icon-button subtle" onClick={() => onNavigate('Findings')}><ArrowUpRight size={17}/></button></div>
        {assessment.loading ? <LoadingState label="Collecting assessment…"/> : assessment.error ? <div className="table-empty"><AlertTriangle size={17}/><span>LIVE assessment unavailable</span></div> : assessment.value ? <FindingTable findings={findings.slice(0, 4)} compact/> : <div className="table-empty"><CircleHelp size={17}/><span>NOT RUN · collect an assessment to view findings</span></div>}<div className="panel-link" onClick={() => onNavigate('Findings')}>View all findings <ChevronRight size={14}/></div>
      </section>
      <section className="panel"><div className="panel-head"><div><h2>Security posture</h2><p>Based on the selected live target</p></div><ShieldHalf className="muted-icon" size={20}/></div>
        {assessment.error ? <InlineState error={assessment.error} auth={assessment.auth} /> : <div className="posture-content"><div className="posture-score"><div className="score-ring" style={{ '--score': findings.length ? `${Math.round(passes / findings.length * 100)}%` : '0%' } as React.CSSProperties}><div><strong>{findings.length && assessment.value ? Math.round(passes / findings.length * 100) : '—'}</strong><small>{findings.length && assessment.value ? 'PASS RATE' : 'NO DATA'}</small></div></div><div className="score-copy"><b>{findings.length ? (fail ? 'Attention required' : 'Assessment received') : 'Awaiting evidence'}</b><span>{findings.length ? `${passes} of ${findings.length} controls passing` : 'No live assessment data loaded'}</span><em className={`source-label ${assessment.value ? '' : 'source-muted'}`}><i/> {assessment.value ? 'LIVE · CONTROLLER' : assessment.loading ? 'COLLECTING' : 'NOT RUN'}</em></div></div><div className="bar-list"><div><span>Passing</span><div className="bar"><i className="bar-green" style={{ width: `${assessment.value && findings.length ? passes / findings.length * 100 : 0}%` }}/></div><b>{assessment.value ? passes : '—'}</b></div><div><span>Failing</span><div className="bar"><i className="bar-red" style={{ width: `${assessment.value && findings.length ? fail / findings.length * 100 : 0}%` }}/></div><b>{assessment.value ? fail : '—'}</b></div></div><div className="posture-foot"><span><LockKeyhole size={13}/> Collection can create a Controller observation</span><span>Read only in UI</span></div></div>}
      </section>
    </div>
    {targets.error && <div className="inline-error"><AlertTriangle size={16}/><div><b>Target inventory unavailable</b><span>{targets.error}</span></div></div>}
  </>
}

function Metric({ icon: Icon, label, value, sub, tone, onClick }: { icon: typeof Activity; label: string; value: string; sub: string; tone: string; onClick: () => void }) { return <button className="metric-card" onClick={onClick}><div className="metric-top"><span>{label}</span><div className={`metric-icon ${tone}`}><Icon size={17}/></div></div><div className="metric-value">{value}</div><div className="metric-sub"><span className="metric-indicator"/>{sub}</div></button> }

function Environments({ targets, selectedId, onSelect, agent, discovery, assessment, onRefresh, onViewFindings }: { targets: ResourceState<Target[]>; selectedId: string; onSelect: (s: string) => void; agent: ResourceState<Record<string, unknown>>; discovery: ResourceState<Record<string, unknown>>; assessment: ResourceState<Record<string, unknown>>; onRefresh: () => void; onViewFindings: () => void }) {
  const selectedTarget = targets.value?.find((t) => t.id === selectedId)
  const inventoryState = targets.error ? 'UNAVAILABLE' : targets.loading ? 'LOADING' : selectedTarget ? 'REGISTERED' : 'UNKNOWN'
  const targetFindings = assessment.value ? normalizeFindings(assessment.value, selectedTarget) : []
  const identity = asRecord(discovery.value?.discovery)
  return <><div className="two-col env-layout"><section className="panel"><div className="panel-head"><div><h2>Registered targets</h2><p>Controller inventory · {targets.value?.length ?? 0} target(s)</p></div><button className="button secondary small" onClick={onRefresh}><RefreshCw size={14}/> Refresh</button></div>{targets.loading ? <LoadingState label="Loading target inventory…"/> : targets.error ? <InlineState error={targets.error} auth={targets.auth}/> : !targets.value?.length ? <EmptyState title="No registered targets" detail="The Controller inventory returned no targets. Environment catalog entries are not target registrations."/> : <div className="target-list">{targets.value.map((t) => <button key={t.id} onClick={() => onSelect(t.id)} className={`target-row ${selectedId === t.id ? 'selected' : ''}`}><div className="target-mark"><Server size={17}/></div><div className="target-info"><b>{t.name}</b><span>{t.platform}{t.address ? ` · ${t.address}` : ''}</span></div><span className={`state-tag ${t.status?.toLowerCase() === 'online' ? 'green' : 'muted'}`}>{t.status || 'REGISTERED'}</span><ChevronRight size={15}/></button>)}</div>}</section>
      <div className="stack"><section className="panel detail-panel"><div className="panel-head"><div><h2>Target details</h2><p>{selectedTarget?.id || selectedId || 'Select a target'}</p></div><span className={selectedTarget ? 'state-tag blue' : 'state-tag muted'}>{inventoryState}</span></div>{!selectedId ? <EmptyState title="No target selected" detail="Select a registered target to view its Controller status and read-only discovery response."/> : <><div className="detail-grid"><Detail label="Name" value={selectedTarget?.name || '—'}/><Detail label="Platform" value={selectedTarget?.platform || '—'}/><Detail label="Target status" value={selectedTarget?.status || 'UNKNOWN'}/><Detail label="Target ID" value={selectedId}/></div><div className="divider"/><div className="subsection-title">Agent connection</div><StateLine loading={agent.loading} error={agent.error} auth={agent.auth} value={agent.value ? `${agentReachable(agent.value) ? 'Reachable' : 'Unreachable'} · ${agentId(agent.value)}` : ''}/><div className="subsection-title">Read-only discovery identity</div>{discovery.error ? <StateLine loading={false} error={discovery.error} auth={discovery.auth} value=""/> : discovery.loading ? <LoadingState label="Reading discovery from agent…"/> : !identity ? <div className="state-line">UNKNOWN · discovery unavailable</div> : <div className="detail-grid"><Detail label="OS" value={String(identity.os || 'UNKNOWN')}/><Detail label="OS version" value={String(identity.os_version || 'UNKNOWN')}/><Detail label="Architecture" value={String(identity.architecture || 'UNKNOWN')}/><Detail label="Kernel" value={String(identity.kernel || 'UNKNOWN')}/><Detail label="Hostname" value={String(identity.hostname || 'UNKNOWN')}/><Detail label="Primary IP" value={String(identity.primary_ip || 'UNKNOWN')}/></div>}<div className="subsection-title assessment-title">Assessment collection</div><StateLine loading={assessment.loading} error={assessment.error} auth={assessment.auth} value={assessment.value ? `${targetFindings.length} findings · observation ${String(assessment.value.assessment_observation_id || 'recorded')}` : 'NOT RUN · collect from the page header'}/><div className="subsection-title">Controls evidenced in latest assessment</div>{assessment.value ? targetFindings.length ? <div className="control-chip-list">{targetFindings.map((f) => <code key={f.control}>{f.control}</code>)}<span>Observed controls only · not a full catalog</span></div> : <div className="state-line">UNKNOWN · no controls returned</div> : assessment.error ? <div className="state-line error"><AlertTriangle size={14}/>{assessment.auth ? 'AUTH REQUIRED' : 'UNAVAILABLE'}</div> : assessment.loading ? <LoadingState label="Loading assessment…"/> : <div className="state-line">NOT RUN · control list unavailable until assessment collection</div>}<button className="panel-link" type="button" onClick={onViewFindings}>Target findings and evidence are in Findings <ChevronRight size={14}/></button></>}</section>
        <section className="panel"><div className="panel-head"><div><h2>Platform support</h2><p>Implemented assessment scope</p></div></div><div className="support-list">{platforms.map((p) => <div className="support-row" key={p.name}><span className={`dot ${p.tone === 'green' ? 'green-dot' : p.tone === 'amber' ? 'amber-dot' : 'gray-dot'}`}/><b>{p.name}</b><span>{p.name === 'CentOS' ? '4-control read-only · plan blocked' : p.name === 'Ubuntu' ? '4-control read-only · execution sandbox-only' : p.state}</span></div>)}</div></section></div></div></>
}

function FindingsPage({ findings, allFindings, query, setQuery, env, setEnv, severity, setSeverity, status, setStatus, assessment }: { findings: Finding[]; allFindings: Finding[]; query: string; setQuery: (s: string) => void; env: string; setEnv: (s: string) => void; severity: string; setSeverity: (s: string) => void; status: string; setStatus: (s: string) => void; assessment: ResourceState<Record<string, unknown>> }) {
  const sourceState = assessment.value ? 'LIVE DATA' : assessment.loading ? 'COLLECTING' : assessment.auth ? 'AUTH REQUIRED' : assessment.error ? 'UNAVAILABLE' : 'NOT RUN'
  const policy = asRecord(assessment.value?.policy_evaluation)
  const reasons = Array.isArray(policy?.reasons) ? policy.reasons.filter((reason): reason is string => typeof reason === 'string') : []
  return <><section className="panel"><div className="panel-head"><div><h2>Assessment findings</h2><p>{assessment.value ? `Controller observation · ${allFindings.length} results${assessment.value.assessment_observation_id ? ` · ${String(assessment.value.assessment_observation_id).slice(0, 8)}` : ''}` : 'Assessment values appear after explicit collection'}</p></div><span className={assessment.value ? 'live-badge' : 'state-tag muted'}>{assessment.value && <i/>}{sourceState}</span></div>
    {assessment.value && <div className="policy-decision"><div><small>TRUSTED CONTROLLER DECISION</small><StatusBadge status={String(policy?.decision || 'UNKNOWN')}/></div><div><small>REPORTED ASSESSMENT DECISION</small><StatusBadge status={String(policy?.reported_decision || 'UNKNOWN')}/></div><div><small>AGENT IDENTITY</small><b>{String(policy?.identity_status || 'UNKNOWN')}</b></div>{reasons.length > 0 && <ul>{reasons.map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}</ul>}</div>}
    <div className="filter-row"><label className="search-box"><Search size={16}/><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search control or finding…"/></label><FilterSelect value={env} onChange={setEnv} options={['All environments', ...new Set(allFindings.map((f) => f.environment))]}/><FilterSelect value={severity} onChange={setSeverity} options={['All severities', 'Critical', 'High', 'Medium', 'Low', 'Info']}/><FilterSelect value={status} onChange={setStatus} options={['All statuses', 'Fail', 'Pass', 'Error', 'Unknown', 'Blocked', 'Indeterminate', 'Not run', 'Not applicable']}/><button className="button secondary small" onClick={() => { setQuery(''); setEnv('All environments'); setSeverity('All severities'); setStatus('All statuses') }}><SlidersHorizontal size={14}/> Reset</button></div>{assessment.loading ? <LoadingState label="Collecting assessment from Controller…"/> : assessment.error ? <InlineState error={assessment.error} auth={assessment.auth}/> : !allFindings.length ? <EmptyState title={assessment.value ? 'No assessment findings' : 'Assessment not collected'} detail={assessment.value ? 'The live assessment returned no findings. This is not interpreted as a passing result.' : 'Use Collect assessment in the page header. Collection records an observation and audit event in the Controller.'}/> : findings.length ? <FindingTable findings={findings}/> : <EmptyState title="No matching findings" detail="Try changing or clearing the filters."/>}<div className="table-foot"><span><i className={`legend-dot ${assessment.value ? 'live-legend' : 'muted-legend'}`}/>{assessment.value ? 'LIVE Controller response' : assessment.error ? 'LIVE DATA UNAVAILABLE' : 'NOT RUN · no assessment collected'}</span><span>Reported finding statuses remain separate from the trusted policy decision.</span></div></section></>
}

function FindingTable({ findings, compact = false, empty }: { findings: Finding[]; compact?: boolean; empty?: string }) {
  if (empty) return <div className="table-empty"><AlertTriangle size={17}/><span>{empty}</span></div>
  if (!findings.length) return <div className="table-empty"><Shield size={17}/><span>No live findings available</span></div>
  return <div className="table-wrap"><table><thead><tr><th>CONTROL</th><th>FINDING</th><th>ENVIRONMENT</th><th>SEVERITY</th><th>STATUS</th></tr></thead><tbody>{findings.map((f) => <tr key={f.id}><td><code>{f.control}</code></td><td><b>{f.title}</b>{!compact && <><small>{f.message || f.evidence || 'No evidence detail returned'}</small><details className="evidence-disclosure"><summary>View evidence and values</summary>{f.message && <span>Message: {f.message}</span>}<span>Observed: {f.observed || 'UNKNOWN'}</span><span>Expected: {f.expected || 'UNKNOWN'}</span>{f.evidence && <span>Evidence: {f.evidence}</span>}</details></>}</td><td><span className="env-cell"><span className={`dot ${f.environment === 'Ubuntu' ? 'green-dot' : 'gray-dot'}`}/>{f.environment}</span></td><td><span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span></td><td><StatusBadge status={f.status}/></td></tr>)}</tbody></table></div>
}

function PlanPage({ plan, target }: { plan: ResourceState<Record<string, unknown>>; target?: Target }) {
  const planData = (plan.value?.plan && typeof plan.value.plan === 'object' ? plan.value.plan : plan.value) as Record<string, unknown> | null
  const actions = Array.isArray(planData?.actions) ? planData.actions : []
  const planSource = plan.value ? 'LIVE DATA' : plan.loading ? 'LOADING' : plan.auth ? 'AUTH REQUIRED' : plan.error ? 'UNAVAILABLE' : 'UNKNOWN'
  return <><div className="notice amber-notice"><div className="notice-icon"><LockKeyhole size={17}/></div><div><b>Planning is not authorization</b><span>Recommendations do not indicate approval, execution, or verified remediation. This frontend does not expose execution controls.</span></div><span className="source-label">READ ONLY</span></div><section className="panel"><div className="panel-head"><div><h2>Remediation plan</h2><p>{target ? `Target · ${target.name}` : 'Select a target from Environments'}</p></div><span className={plan.value ? 'live-badge' : 'state-tag muted'}>{plan.value && <i/>}{planSource}</span></div>{plan.loading ? <LoadingState label="Loading plan…"/> : plan.error ? <InlineState error={plan.error} auth={plan.auth}/> : !plan.value ? <EmptyState title="Plan not available" detail="UNKNOWN until a selected target returns a plan from the Controller."/> : <><div className="plan-summary"><div><small>PLAN STATUS</small><b>{planStatus(plan.value)}</b></div><div><small>RECOMMENDED ACTIONS</small><b>{actions.length}</b></div><div><small>EXECUTION</small><b className="muted-value">BLOCKED · unavailable</b></div><div><small>VERIFICATION</small><b className="muted-value">NOT RUN</b></div></div>{actions.length ? <div className="action-list">{actions.map((raw, i) => { const a = raw as Record<string, unknown>; const needsApproval = String(a.execution_mode || '').toUpperCase() === 'APPROVAL'; return <div className="action-row" key={String(a.action_id || i)}><div className="action-number">{String(i + 1).padStart(2, '0')}</div><div><b>{String(a.title || a.action_id || `Recommendation ${i + 1}`)}</b><span>{String(a.reason || a.control_id || 'Recommendation returned by the Controller plan')}{a.current_value !== undefined || a.desired_value !== undefined ? ` · ${String(a.current_value ?? 'unknown')} → ${String(a.desired_value ?? 'unknown')}` : ''}</span></div><StatusBadge status={needsApproval ? 'Approval required' : String(a.execution_mode || 'Recommended')}/></div> })}</div> : <EmptyState title="No remediation actions recommended" detail="The Controller returned a plan with no actions. No execution was attempted."/>}<div className="unavailable-actions"><button className="button disabled-btn" disabled aria-disabled="true"><CheckCircle2 size={14}/> Execute · BLOCKED</button><button className="button disabled-btn" disabled aria-disabled="true"><RefreshCw size={14}/> Rollback · BLOCKED</button><span>Unavailable in the Controller workflow. These controls cannot send requests.</span></div><div className="lifecycle"><LifecycleItem icon={FileCheck2} title="Recommendation" state="Returned by plan endpoint" done/><LifecycleItem icon={LockKeyhole} title="Approval" state="No approval workflow available"/><LifecycleItem icon={Terminal} title="Execution" state="BLOCKED · not called"/><LifecycleItem icon={CheckCircle2} title="Verified outcome" state="UNKNOWN · no verification evidence"/></div></>}</section></>
}

function SandboxPage() {
  const [runs, loadRuns] = useResource<DemoRemediationRun[]>()
  const [scenarioFilter, setScenarioFilter] = useState('All scenarios')
  useEffect(() => { void loadRuns(getRemediationRuns) }, [loadRuns])
  const phase = resourcePhase({ loading: runs.loading, error: runs.error, auth: runs.auth, hasValue: runs.value !== null, empty: runs.value?.length === 0 })
  const visible = (runs.value || []).filter((run) => scenarioFilter === 'All scenarios' || run.scenario === scenarioFilter)
  return <>
    <div className="notice blue-notice"><div className="notice-icon"><Terminal size={17}/></div><div><b>Local remediation fixture · test-only trust</b><span>Runs use a generated temporary OpenSSH tree, ephemeral signing key, test-only policy, and no listener. The Controller exposes results as read-only records.</span></div><span className="fixture-badge">SANDBOX ONLY</span></div>
    <section className="panel"><div className="panel-head"><div><h2>Remediation lifecycle runs</h2><p>Execute, independently verify, and restore the exact captured temporary state.</p></div><span className="source-label">READ ONLY</span></div>
      <div className="filter-row"><FilterSelect value={scenarioFilter} onChange={setScenarioFilter} options={['All scenarios', ...new Set((runs.value || []).map((run) => run.scenario))]}/><button className="button secondary small" onClick={() => void loadRuns(getRemediationRuns)}><RefreshCw size={14}/> Refresh</button><span className="source-label">{phase.toUpperCase()}</span></div>
      {phase === 'loading' ? <LoadingState label="Loading persisted sandbox runs…"/> : phase === 'auth-required' || phase === 'error' ? <InlineState error={runs.error || 'Authentication is required to read sandbox run records.'} auth={runs.auth}/> : phase === 'not-run' ? <EmptyState title="Sandbox run records unavailable" detail="Enable the read-only demo API and run the fixed local CLI. No run is invented in the dashboard."/> : phase === 'empty' ? <EmptyState title="No persisted sandbox runs" detail="Run `AHA_ENABLE_LOCAL_DEMO_CLI=1 python -m app.demo remediation run --scenario roundtrip` from controller/ to create a local run record."/> : visible.length === 0 ? <EmptyState title="No matching runs" detail="Change the scenario filter to show other persisted runs."/> : <div className="run-list">{visible.map((run) => {
        const data = run.result
        const execution = asRecord(data.execution)
        const verification = asRecord(data.verification)
        const recovery = asRecord(data.recovery)
        const approval = asRecord(data.approval)
        const findings = Array.isArray(data.findings) ? data.findings as Array<Record<string, unknown>> : []
        const rootFinding = findings.find((finding) => finding.control_id === '5.1.20')
        const lifecycle = Array.isArray(data.lifecycle) ? data.lifecycle as Array<Record<string, unknown>> : []
        return <article className="run-card" key={run.run_id}>
          <div className="run-card-head"><div><b>{run.scenario}</b><span>{run.run_id} · {run.recorded_at}</span></div><StatusBadge status={run.status}/><span className="fixture-badge">TEST ONLY</span></div>
          <div className="run-facts"><Detail label="Target" value={run.target_id}/><Detail label="Policy / catalog" value={`${String(data.policy_version || 'unknown')} · ${String(data.catalog_version || 'unknown')}`}/><Detail label="Root login before" value={String(rootFinding?.current_value || 'UNKNOWN')}/><Detail label="Approval" value={`${String(approval?.status || 'UNKNOWN')} · ${String(approval?.subject || 'unknown')}`}/><Detail label="Action result" value={String(execution?.status || 'NO ACTION')}/><Detail label="Independent verify" value={`${String(verification?.status || 'NOT RUN')} · ${String(verification?.observed || 'UNKNOWN')}`}/><Detail label="Recovery" value={`${String(recovery?.status || 'NOT RUN')} · ${String(recovery?.restored_effective_value || 'UNKNOWN')}`}/></div>
          <div className="run-lifecycle">{lifecycle.map((item, index) => <span key={`${String(item.state)}-${index}`}><b>{String(item.state)}</b>{item.detail ? ` · ${String(item.detail)}` : ''}</span>)}</div>
          <small className="run-safety">sandbox_only={String(run.sandbox_only)} · test_only_trust={String(run.test_only_trust)} · live_target_modified={String(run.live_target_modified)} · {Array.isArray(data.audit_events) ? `${data.audit_events.length} helper audit records` : 'audit evidence unavailable'}</small>
        </article>
      })}</div>}
      <div className="table-foot"><span><i className="legend-dot fixture-legend"/> LOCAL SANDBOX RESULTS</span><span>No Controller execution or rollback route exists.</span></div>
    </section>
  </>
}

function DecoyPage() {
  const [feed, loadFeed] = useResource<{ active_listener_count: number; events: DemoDecoyEvent[] }>()
  const [category, setCategory] = useState('All categories')
  useEffect(() => { void loadFeed(getDecoyEvents) }, [loadFeed])
  const phase = resourcePhase({ loading: feed.loading, error: feed.error, auth: feed.auth, hasValue: feed.value !== null, empty: feed.value?.events.length === 0 })
  const events = filterByCategory(feed.value?.events || [], category)
  const categories = ['All categories', ...new Set((feed.value?.events || []).map((event) => event.category))]
  const last = feed.value?.events[0]?.occurred_at
  return <>
    <div className="notice amber-notice"><div className="notice-icon"><Network size={17}/></div><div><b>SIMULATED event feed · no active decoy listener</b><span>These records are generated locally from RFC 5737 documentation addresses. The simulator has no network socket and cannot invoke remediation.</span></div><span className="fixture-badge">SIMULATED</span></div>
    <section className="panel"><div className="panel-head"><div><h2>Attacker / decoy event feed</h2><p>Persisted simulation events · separate from target and execution state</p></div><div className="feed-indicator"><span/> SIMULATED FEED</div></div>
      <div className="filter-row"><FilterSelect value={category} onChange={setCategory} options={categories}/><button className="button secondary small" onClick={() => void loadFeed(getDecoyEvents)}><RefreshCw size={14}/> Refresh</button><span className="source-label">{phase.toUpperCase()}</span></div>
      <div className="event-summary"><div><small>EVENTS SHOWN</small><b>{feed.value ? events.length : '—'}</b></div><div><small>ACTIVE LISTENERS</small><b>0</b></div><div><small>LAST EVENT</small><b>{last ? new Date(last).toLocaleTimeString() : '—'}</b></div><div><small>CLASSIFICATION</small><b>SIMULATED</b></div></div>
      {phase === 'loading' ? <LoadingState label="Loading simulated events…"/> : phase === 'auth-required' || phase === 'error' ? <InlineState error={feed.error || 'Authentication is required to read simulated events.'} auth={feed.auth}/> : phase === 'not-run' ? <EmptyState title="Decoy event API unavailable" detail="Enable the read-only demo API to retrieve persisted simulated events. No sample rows are fabricated in the UI."/> : events.length === 0 ? <EmptyState title={phase === 'empty' ? 'No simulated events' : 'No matching events'} detail="Use the local demo CLI to generate a fixed safe batch, or change the category filter."/> : <div className="event-table"><div className="event-table-head"><span>TIME</span><span>EVENT CATEGORY</span><span>SOURCE</span><span>CORRELATION</span><span>CLASSIFICATION</span></div>{events.map((event) => <div className="event-row" key={event.event_id}><code>{new Date(event.occurred_at).toLocaleTimeString()}</code><span className="event-name"><i className="event-type-dot blue"/>{event.category}</span><code>{event.source_address}</code><code>{event.correlation_id}</code><span className="state-tag blue">SIMULATED</span></div>)}</div>}
      <div className="table-foot"><span><i className="legend-dot fixture-legend"/> RFC 5737 source ranges · synthetic only</span><span>CLI reset deletes only demo_decoy_events rows.</span></div>
    </section>
  </>
}

function AuditPage({ target, assessment, plan }: { target?: Target; assessment: ResourceState<Record<string, unknown>>; plan: ResourceState<Record<string, unknown>> }) {
  const [audit, loadAudit] = useResource<{ integrity: { status: string; event_count: number; error: string | null }; events: AuditEvent[] }>()
  useEffect(() => { void loadAudit(getAuditEvents) }, [loadAudit])
  const a = assessment.value || {}
  const p = plan.value || {}
  const rows = [
    { label: 'Assessment observation', value: a.assessment_observation_id, source: 'GET /assessment' },
    { label: 'Assessment trust status', value: a.assessment_trust_status, source: 'Controller response' },
    { label: 'Policy status', value: a.policy_status, source: 'Controller response' },
    { label: 'Trusted policy decision', value: asRecord(a.policy_evaluation)?.decision, source: 'Controller evaluation' },
    { label: 'Reported assessment decision', value: asRecord(a.policy_evaluation)?.reported_decision, source: 'Agent result · untrusted separately' },
    { label: 'Policy version', value: asRecord(a.policy)?.policy_version, source: 'Controller response' },
    { label: 'Catalog version', value: asRecord(a.policy)?.catalog_version, source: 'Controller response' },
    { label: 'Plan status', value: plan.error ? 'UNAVAILABLE' : plan.loading ? 'LOADING' : asRecord(p.plan)?.status || p.status || 'UNKNOWN', source: 'GET /plan' },
  ]
  const phase = resourcePhase({ loading: audit.loading, error: audit.error, auth: audit.auth, hasValue: audit.value !== null, empty: audit.value?.events.length === 0 })
  return <><div className="notice"><div className="notice-icon"><Database size={17}/></div><div><b>Controller evidence and audit chain</b><span>Assessment provenance remains indeterminate unless independently established. Audit chain verification reports local SQLite integrity only.</span></div><span className={audit.value?.integrity.status === 'VALID' ? 'live-badge' : 'state-tag muted'}>{audit.value?.integrity.status || phase.toUpperCase()}</span></div><div className="two-col audit-grid"><section className="panel"><div className="panel-head"><div><h2>Evidence references</h2><p>{target ? `Target · ${target.name}` : 'No target selected'}</p></div><span className={assessment.value ? 'live-badge' : 'state-tag muted'}>{assessment.value ? 'LIVE REFERENCES' : assessment.loading ? 'LOADING' : assessment.auth ? 'AUTH REQUIRED' : assessment.error ? 'UNAVAILABLE' : 'NOT RUN'}</span></div>{assessment.error ? <InlineState error={assessment.error} auth={assessment.auth}/> : assessment.loading ? <LoadingState label="Loading evidence references…"/> : !assessment.value ? <EmptyState title="Evidence collection NOT RUN" detail="Use Collect assessment in the page header. Collection stores a Controller observation and audit event."/> : <div className="evidence-list">{rows.map((row) => <div className="evidence-row" key={row.label}><div className="evidence-icon"><FileCheck2 size={16}/></div><div><b>{row.label}</b><span>{row.source}</span></div><code>{row.value ? String(row.value) : 'UNKNOWN'}</code></div>)}</div>}<div className="integrity-note"><ShieldCheck size={16}/><span>Payload digests bind stored observations. Audit-chain validity detects ordinary edits but does not establish external or authenticated immutability.</span></div></section><section className="panel"><div className="panel-head"><div><h2>Audit history</h2><p>{audit.value ? `${audit.value.integrity.event_count} stored events` : 'Read-only Controller audit endpoint'}</p></div><span className={`state-tag ${audit.value?.integrity.status === 'VALID' ? 'green' : audit.value?.integrity.status === 'INVALID' ? 'red' : 'muted'}`}>{audit.value?.integrity.status || phase.toUpperCase()}</span></div>
      {phase === 'loading' ? <LoadingState label="Verifying and loading audit history…"/> : phase === 'auth-required' || phase === 'error' ? <InlineState error={audit.error || 'Authentication is required to read audit history.'} auth={audit.auth}/> : phase === 'not-run' ? <EmptyState title="Audit API unavailable" detail="The Controller did not return audit history. No audit entries are synthesized."/> : audit.value?.events.length === 0 ? <EmptyState title="No audit events" detail="The chain currently contains no events."/> : <div className="audit-events">{audit.value?.events.map((event) => <div className="audit-event" key={event.event_id}><code>#{event.sequence} · {new Date(event.occurred_at).toLocaleString()}</code><b>{event.event_type}</b><span>{event.target_id || 'No target binding'} · {event.event_digest}</span></div>)}</div>}
      {audit.value?.integrity.status === 'INVALID' && <div className="integrity-note"><AlertTriangle size={16}/><span>Audit-chain verification failed: {audit.value.integrity.error || 'integrity error unavailable'}.</span></div>}
    </section></div></>
}

function normalizeFindings(value: Record<string, unknown> | null, target?: Target): Finding[] {
  const assessment = asRecord(value?.assessment) || value
  const raw = Array.isArray(assessment?.findings) ? assessment.findings : []
  return raw.map((item, i) => {
    const f = asRecord(item) || {}
    const rawStatus = String(f.status || f.result || 'UNKNOWN')
    const evidence = Array.isArray(f.evidence)
      ? f.evidence.map((entry) => { const e = asRecord(entry) || {}; return `${String(e.name || 'Evidence')}: ${String(e.value || 'value unavailable')}${e.source ? ` · ${String(e.source)}` : ''}` }).join('; ')
      : typeof f.evidence === 'string' ? f.evidence : String(f.message || '')
    return {
      id: String(f.finding_id || f.id || f.control_id || i), control: String(f.control_id || f.id || `CONTROL-${i + 1}`),
      title: String(f.title || f.name || f.description || f.control_id || 'Assessment control'),
      environment: normalizePlatform(target?.platform || String(assessment?.platform || 'Unknown')),
      severity: String(f.severity || 'Info'), status: normalizeFindingStatus(rawStatus), message: typeof f.message === 'string' ? f.message : undefined,
      evidence: Array.isArray(f.evidence) ? evidence : typeof f.evidence === 'string' ? f.evidence : undefined,
      observed: String(f.current_value ?? f.observed_value ?? f.actual_value ?? ''), expected: String(f.expected_value ?? f.expected ?? ''),
    }
  })
}
function asRecord(value: unknown): Record<string, unknown> | null { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null }
function normalizePlatform(raw: string) { const x = raw.toLowerCase(); if (x.includes('ubuntu')) return 'Ubuntu'; if (x.includes('centos')) return 'CentOS'; if (x.includes('windows')) return 'Windows'; if (x.includes('docker')) return 'Docker'; if (x.includes('aws')) return 'AWS Cloud'; if (x.includes('arm') || x.includes('edge')) return 'Edge ARM64'; return raw || 'Unknown' }
function agentReachable(value: Record<string, unknown>) { const agent = value.agent && typeof value.agent === 'object' ? value.agent as Record<string, unknown> : value; return agent.reachable === true || agent.status === 'online' }
function agentId(value: Record<string, unknown>) { const agent = value.agent && typeof value.agent === 'object' ? value.agent as Record<string, unknown> : value; return String(agent.agent_id || agent.status || 'status unknown') }
function planStatus(value: Record<string, unknown>) { const plan = value.plan && typeof value.plan === 'object' ? value.plan as Record<string, unknown> : value; return String(plan.status || plan.readiness || 'Returned') }

function InlineState({ error, auth, onRetry }: { error: string; auth: boolean; onRetry?: () => void }) { return <div className={`request-state ${auth ? 'auth-state' : 'error-state'}`}><div className="request-state-icon">{auth ? <LockKeyhole size={20}/> : <AlertTriangle size={20}/>}</div><div><b>{auth ? 'Authentication required' : 'Live request failed'}</b><p>{error}</p>{auth && <small>Configure an authorized local token or use an authenticated Controller session.</small>}</div>{onRetry && <button className="button secondary small" onClick={onRetry}><RefreshCw size={14}/> Retry</button>}</div> }
function LoadingState({ label }: { label: string }) { return <div className="loading-state"><span className="spinner"/>{label}</div> }
function EmptyState({ title, detail }: { title: string; detail: string }) { return <div className="empty-state"><div><Database size={21}/></div><b>{title}</b><p>{detail}</p></div> }
function Detail({ label, value }: { label: string; value: string }) { return <div className="detail-cell"><small>{label}</small><b>{value}</b></div> }
function StateLine({ loading, error, auth, value }: { loading: boolean; error: string; auth: boolean; value: string }) { if (loading) return <LoadingState label="Request in progress…"/>; if (error) return <div className="state-line error"><AlertTriangle size={14}/>{auth ? 'Authentication required' : 'Request failed'}<span>{error}</span></div>; const dot = value.toLowerCase().includes('reachable') ? value.toLowerCase().includes('unreachable') ? 'amber-dot' : 'green-dot' : 'gray-dot'; return <div className="state-line"><span className={`dot ${dot}`}/>{value || 'Unknown'}</div> }
function StatusBadge({ status }: { status: string }) { const s = status.toLowerCase(); let cls = 'muted'; if (s.includes('pass') || s.includes('ready') || s.includes('verified') || s === 'compliant' || s.includes('rolled_back')) cls = 'green'; else if (s === 'error') cls = 'error'; else if (s.includes('fail') || s.includes('critical') || s.includes('recovery_failed') || s === 'non-compliant') cls = 'red'; else if (s.includes('approval') || s.includes('recommended') || s.includes('pending') || s.includes('blocked') || s.includes('indeterminate')) cls = 'amber'; return <span className={`status-badge ${cls}`}><i/>{status}</span> }
function FilterSelect({ value, onChange, options }: { value: string; onChange: (s: string) => void; options: Iterable<string> }) { return <label className="filter-select"><Filter size={13}/><select value={value} onChange={(e) => onChange(e.target.value)}>{Array.from(options).map((o) => <option key={o}>{o}</option>)}</select><ChevronDown size={13}/></label> }
function LifecycleItem({ icon: Icon, title, state, done = false }: { icon: typeof Activity; title: string; state: string; done?: boolean }) { return <div className="lifecycle-item"><div className={`lifecycle-icon ${done ? 'done' : ''}`}><Icon size={15}/></div><div><b>{title}</b><span>{state}</span></div>{done && <Check size={15} className="check-icon"/>}</div> }

export default App
