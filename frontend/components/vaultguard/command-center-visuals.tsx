'use client'

import { useEffect, useMemo, useState } from "react"
import { Activity, ArrowRight, Check, ChevronRight, CircleAlert, Clock3, LockKeyhole, Radar, RotateCcw, ScanLine, Shield, ShieldCheck, Sparkles, X } from "lucide-react"
import type { VaultMetrics } from "@/lib/vault-metrics"

const accountNodes = [
  { id: "email", name: "Email", service: "Northstar Mail", status: "strong", score: "Strong · unique", x: 112, y: 57, icon: "M" },
  { id: "bank", name: "Banking", service: "Meridian Bank", status: "strong", score: "Strong · unique", x: 257, y: 90, icon: "$" },
  { id: "social", name: "Social", service: "Orbit Social", status: "weak", score: "Weak · reused", x: 266, y: 208, icon: "@" },
  { id: "shopping", name: "Shopping", service: "Northstar Shop", status: "moderate", score: "Moderate · unique", x: 170, y: 260, icon: "S" },
  { id: "work", name: "Work", service: "Aperture Work", status: "strong", score: "Strong · unique", x: 56, y: 204, icon: "W" },
  { id: "entertainment", name: "Entertainment", service: "Lumen Play", status: "weak", score: "Weak · reused", x: 54, y: 105, icon: "P" },
] as const

const radarEvents = [
  { id: "weak", title: "Weak password", detail: "One credential needs a longer, unique passphrase.", level: "critical", x: 70, y: 83 },
  { id: "reuse", title: "Password reuse", detail: "Two demo accounts share a password pattern.", level: "warning", x: 128, y: 51 },
  { id: "config", title: "Setting review", detail: "Review recovery options in your account settings.", level: "warning", x: 145, y: 119 },
  { id: "check", title: "Health check", detail: "The last local demo check completed successfully.", level: "good", x: 103, y: 136 },
] as const

export function HolographicShield({ size = 90 }: { size?: number }) {
  return <svg className="holo-shield" width={size} height={size * 1.12} viewBox="0 0 100 112" role="img" aria-label="VaultGuard holographic shield emblem">
    <defs>
      <linearGradient id="shield-fill" x1="0" y1="0" x2="1" y2="1"><stop stopColor="#77F3FA" stopOpacity=".32"/><stop offset=".52" stopColor="#237F9A" stopOpacity=".12"/><stop offset="1" stopColor="#9B83FF" stopOpacity=".3"/></linearGradient>
      <linearGradient id="shield-stroke" x1=".1" y1="0" x2=".9" y2="1"><stop stopColor="#70F5FF"/><stop offset=".55" stopColor="#36D6E8"/><stop offset="1" stopColor="#A38BFF"/></linearGradient>
      <filter id="shield-glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    </defs>
    <path d="M50 5 88 19v31c0 25-14 43-38 56C26 93 12 75 12 50V19L50 5Z" fill="url(#shield-fill)" stroke="url(#shield-stroke)" strokeWidth="1.6" filter="url(#shield-glow)"/>
    <path d="M50 13 80 24v26c0 20-11 35-30 45-19-10-30-25-30-45V24l30-11Z" fill="none" stroke="#B9F9FF" strokeOpacity=".38" strokeWidth=".8"/>
    <path d="m50 22 21 8v20c0 15-7 26-21 34-14-8-21-19-21-34V30l21-8Z" fill="none" stroke="#5DE5F1" strokeOpacity=".58" strokeWidth=".8"/>
    <path d="M50 14v74M22 39h56M28 67h44M35 27l30 51M65 27 35 78" stroke="#B9F9FF" strokeOpacity=".16" strokeWidth=".65"/>
    <path d="m39 53 8 8 16-18" fill="none" stroke="#E5FFFF" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" filter="url(#shield-glow)"/>
    <circle cx="50" cy="5" r="2" fill="#B6FBFF"/><circle cx="88" cy="19" r="1.6" fill="#A38BFF"/><circle cx="12" cy="19" r="1.6" fill="#70F5FF"/>
  </svg>
}

export function SecurityCore({ onReport, metrics }: { onReport: () => void; metrics?: VaultMetrics }) {
  const isLocked = metrics?.isLocked ?? false
  const isEmpty = (metrics?.isEmpty ?? false) && !isLocked
  const score = metrics ? metrics.healthScore : 82
  const totalRecords = metrics ? metrics.totalEntries : 24
  const statusLabel = isLocked
    ? "VAULT LOCKED"
    : isEmpty
    ? "NO CREDENTIALS"
    : score !== null && score >= 80
    ? "ALL SYSTEMS NOMINAL"
    : score !== null && score >= 50
    ? "REVIEW RECOMMENDED"
    : "ACTION REQUIRED"

  const statusProtection = isLocked
    ? "Vault locked"
    : isEmpty
    ? "Empty vault"
    : score !== null && score >= 80
    ? "Good protection"
    : score !== null && score >= 50
    ? "Moderate protection"
    : "At risk"

  const dashOffset = score !== null ? Math.round(679 * (1 - score / 100)) : 679

  return <section className="security-core panel" aria-label={`Security score ${score !== null ? `${score} out of 100` : "locked"}`}>
    <div className="core-topline"><span className="eyebrow"><span className="eyebrow-dot"/> PERSONAL SECURITY CORE</span><span className="core-live"><i style={{ background: isLocked ? "#E9AA62" : undefined }}/> {statusLabel}</span></div>
    <div className="core-layout"><div className="core-copy"><span className="core-label">SECURITY SCORE</span><div className="core-score">{score !== null ? score : "—"}<span>/100</span></div><div className="core-status"><ShieldCheck size={15}/> {statusProtection}</div><p>{isLocked ? "Your vault is locked. Master password unlock required to compute live security metrics." : isEmpty ? "No passwords saved in this vault yet. Add credentials to evaluate password health." : "Zero-knowledge security score calculated locally from your decrypted vault items."}</p><button className="core-report" onClick={onReport}>Open security report <ArrowRight size={14}/></button></div>
      <div className="core-visual" aria-hidden="true"><div className="core-orbit core-orbit-outer"><i/><i/></div><div className="core-orbit core-orbit-mid"><i/><i/><i/></div><div className="core-orbit core-orbit-inner"/><div className="core-progress"><svg viewBox="0 0 240 240"><circle className="core-track" cx="120" cy="120" r="108"/><circle className="core-arc" cx="120" cy="120" r="108" style={{ strokeDashoffset: dashOffset }}/></svg></div><div className="core-shield-wrap"><HolographicShield size={86}/></div><span className="core-data-point point-a"/><span className="core-data-point point-b"/><span className="core-data-point point-c"/><span className="core-axis axis-x"/><span className="core-axis axis-y"/><div className="core-hud hud-left"><b>VAULT HEALTH</b><span>{totalRecords} RECORDS</span></div><div className="core-hud hud-right"><b>PROTECTION</b><span>{score !== null ? `${score.toFixed(1)} INDEX` : "LOCKED"}</span></div></div>
    </div><div className="core-footer"><span><i className="status-dot good"/> Password integrity <b>{metrics ? (metrics.weakCount === 0 && !isLocked && !isEmpty ? "OPTIMAL" : metrics.weakCount > 0 ? `${metrics.weakCount} WEAK` : "NORMAL") : "GOOD"}</b></span><span><i className="status-dot violet"/> Exposure review <b>{metrics ? (metrics.reusedPasswordCount > 0 ? `${metrics.reusedPasswordCount} REUSED` : "0 REUSED") : "2 ITEMS"}</b></span><span>{metrics ? (isLocked ? "VAULT LOCKED" : "LOCAL ZERO-KNOWLEDGE") : "LOCAL DEMO TELEMETRY"}</span></div>
  </section>
}

export function SecurityNetwork({ metrics }: { metrics?: VaultMetrics }) {
  const [selectedId, setSelectedId] = useState<string>("social")
  const selected = accountNodes.find(node => node.id === selectedId) ?? accountNodes[0]
  const links = [[0,1],[1,2],[2,3],[3,4],[4,5],[5,0],[0,4],[2,5]]
  const totalCount = metrics ? metrics.totalEntries : 24
  return <section className="network-panel panel">
    <div className="viz-heading"><div><span className="eyebrow">{metrics ? "LOCAL CREDENTIAL TOPOLOGY" : "DEMO SECURITY VISUALIZATION"}</span><h2>Digital account network</h2><p>Credential health across saved accounts.</p></div><span className="network-legend"><i className="legend-strong"/> Secure <i className="legend-moderate"/> Review <i className="legend-weak"/> Action</span></div>
    <div className="network-layout"><div className="network-canvas"><svg viewBox="0 0 320 300" role="group" aria-label="Interactive account network">
      <defs><radialGradient id="networkGlow"><stop stopColor="#36D6E8" stopOpacity=".14"/><stop offset="1" stopColor="#36D6E8" stopOpacity="0"/></radialGradient></defs><circle cx="160" cy="150" r="118" fill="url(#networkGlow)"/>
      {links.map(([from,to], index) => { const a=accountNodes[from],b=accountNodes[to]; return <g key={`${from}-${to}`}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className={`network-link ${from===2||to===2||from===5||to===5 ? "network-link-risk" : ""}`}/><circle className="network-particle" r="2.2"><animateMotion dur={`${5+index%3}s`} repeatCount="indefinite" path={`M${a.x} ${a.y} L${b.x} ${b.y}`}/></circle></g> })}
      <circle cx="160" cy="150" r="35" className="network-hub"/><text x="160" y="147" className="network-hub-label" textAnchor="middle">VAULT</text><text x="160" y="161" className="network-hub-count" textAnchor="middle">{totalCount} ACCOUNTS</text>
      {accountNodes.map(node => <g key={node.id} className={`network-node ${node.status} ${selectedId===node.id ? "selected" : ""}`} role="button" tabIndex={0} aria-label={`${node.name}: ${node.score}`} aria-pressed={selectedId===node.id} onClick={()=>setSelectedId(node.id)} onKeyDown={event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();setSelectedId(node.id)}}}><circle cx={node.x} cy={node.y} r="20" className="node-halo"/><circle cx={node.x} cy={node.y} r="14" className="node-core"/><text x={node.x} y={node.y+3.5} textAnchor="middle" className="node-glyph">{node.icon}</text><text x={node.x} y={node.y+31} textAnchor="middle" className="node-label">{node.name}</text></g>)}
    </svg><div className="network-caption"><span><Activity size={12}/> CONNECTIONS SHOW PASSWORD REUSE PATTERNS</span><span>{metrics ? "LOCAL MEMORY" : "SIMULATED DATA"}</span></div></div>
    <div className={`account-detail ${selected.status}`}><div className="account-detail-icon">{selected.icon}</div><span className="eyebrow">SELECTED ACCOUNT</span><h3>{selected.service}</h3><p>{selected.score}</p><div className="account-health-line"><span/><span/></div><div className="account-detail-note">{selected.status === "weak" ? "This account is flagged for a unique password review." : selected.status === "moderate" ? "Consider increasing the length for added resilience." : "This account has a unique, healthy password."}</div><div className="account-detail-footer"><span className={`status-dot ${selected.status}`}/>{selected.status === "weak" ? "PRIORITY REVIEW" : selected.status === "moderate" ? "IMPROVEMENT AVAILABLE" : "HEALTHY"}<ChevronRight size={13}/></div></div></div>
  </section>
}

export function ThreatRadar({ metrics }: { metrics?: VaultMetrics }) {
  const isLocked = metrics?.isLocked ?? false
  const isEmpty = (metrics?.isEmpty ?? false) && !isLocked

  const events = useMemo(() => {
    if (!metrics) {
      return radarEvents
    }

    if (isLocked) {
      return [
        {
          id: "locked",
          title: "Vault locked",
          detail: "Threat radar telemetry is unavailable while the vault is locked.",
          level: "warning" as const,
          x: 100,
          y: 100
        }
      ]
    }

    if (isEmpty) {
      return [
        {
          id: "empty",
          title: "Empty vault",
          detail: "Add credentials to your vault to activate real-time credential risk monitoring.",
          level: "good" as const,
          x: 103,
          y: 136
        }
      ]
    }

    const items = []

    // 1. Weak passwords signal
    if (metrics.weakCount > 0) {
      items.push({
        id: "weak",
        title: `${metrics.weakCount} Weak password${metrics.weakCount > 1 ? "s" : ""}`,
        detail: `${metrics.weakCount} credential${metrics.weakCount > 1 ? "s" : ""} identified with low complexity or length.`,
        level: "critical" as const,
        x: 70,
        y: 83
      })
    } else {
      items.push({
        id: "weak",
        title: "No weak passwords",
        detail: "All saved credentials meet security complexity standards.",
        level: "good" as const,
        x: 70,
        y: 83
      })
    }

    // 2. Password reuse signal
    if (metrics.reusedPasswordCount > 0) {
      items.push({
        id: "reuse",
        title: `${metrics.reusedPasswordCount} Reused pattern${metrics.reusedPasswordCount > 1 ? "s" : ""}`,
        detail: `Password reuse detected across ${metrics.affectedAccountsCount} accounts.`,
        level: "warning" as const,
        x: 128,
        y: 51
      })
    } else {
      items.push({
        id: "reuse",
        title: "Unique credentials",
        detail: "Zero password reuse detected in your vault.",
        level: "good" as const,
        x: 128,
        y: 51
      })
    }

    // 3. Missing password values signal (if any)
    if (metrics.missingPasswordCount > 0) {
      items.push({
        id: "missing",
        title: `${metrics.missingPasswordCount} Incomplete record${metrics.missingPasswordCount > 1 ? "s" : ""}`,
        detail: `${metrics.missingPasswordCount} vault record${metrics.missingPasswordCount > 1 ? "s" : ""} have blank or missing passwords.`,
        level: "warning" as const,
        x: 145,
        y: 119
      })
    } else {
      items.push({
        id: "complete",
        title: "Complete records",
        detail: "All saved vault records contain usable credentials.",
        level: "good" as const,
        x: 145,
        y: 119
      })
    }

    // 4. Overall health index signal
    const score = metrics.healthScore ?? 0
    items.push({
      id: "health",
      title: `Health index ${score}/100`,
      detail: score >= 70
        ? "Credential perimeter is strong. Keep maintaining unique passphrases."
        : "Improve weak or reused credentials to raise your health index.",
      level: score >= 70 ? ("good" as const) : score >= 50 ? ("warning" as const) : ("critical" as const),
      x: 103,
      y: 136
    })

    return items
  }, [metrics, isLocked, isEmpty])

  const [selectedId, setSelectedId] = useState<string>(events[0]?.id ?? "weak")

  useEffect(() => {
    if (!events.some(e => e.id === selectedId)) {
      setSelectedId(events[0]?.id ?? "weak")
    }
  }, [events, selectedId])

  const selected = events.find(event => event.id === selectedId) ?? events[0]
  return <section className="radar-panel panel"><div className="viz-heading"><div><span className="eyebrow">{metrics ? "LOCAL ZERO-KNOWLEDGE RADAR" : "SIMULATED DEMO DATA"}</span><h2>Threat radar</h2><p>Local account-health signals, not live external threat detection.</p></div><span className="radar-scanning"><i/> {isLocked ? "LOCKED" : "ACTIVE"}</span></div><div className="radar-layout"><div className="radar-view"><div className="radar-crosshair radar-x"/><div className="radar-crosshair radar-y"/><div className="radar-rings"><div className="radar-sweep"/></div>{events.map(event=><button key={event.id} aria-label={`${event.title}: view recommendation`} aria-pressed={selectedId===event.id} className={`radar-blip ${event.level} ${selectedId===event.id?"selected":""}`} style={{left:`${event.x/2.1}%`,top:`${event.y/2.1}%`}} onClick={()=>setSelectedId(event.id)}><i/></button>)}<span className="radar-center"><Radar size={13}/></span></div><div className="radar-event"><div className={`radar-event-icon ${selected.level}`}>{selected.level==="good"?<Check size={15}/>:<CircleAlert size={15}/>}</div><span className="eyebrow">SELECTED SIGNAL</span><h3>{selected.title}</h3><p>{selected.detail}</p><div className="radar-event-footer"><span className={`status-dot ${selected.level}`}/>{selected.level.toUpperCase()} PRIORITY<span>{metrics ? "LOCAL" : "DEMO"}</span></div></div></div><div className="radar-list">{events.map((event,index)=><button key={event.id} className={selectedId===event.id?"active":""} onClick={()=>setSelectedId(event.id)}><span className={`radar-list-index ${event.level}`}>0{index+1}</span><span>{event.title}</span><span className={`status-dot ${event.level}`}/></button>)}</div></section>
}

const scanChecks = ["Password strength", "Password reuse", "Weak credentials", "Security configuration", "Overall vault health"]
export function SecurityScan({ onRecommendations, metrics }: { onRecommendations: () => void; metrics?: VaultMetrics }) {
  const [open,setOpen]=useState(false)
  const [step,setStep]=useState(-1)
  useEffect(()=>{ if(!open||step<0||step>=scanChecks.length)return; const timer=window.setTimeout(()=>setStep(current=>current+1),520); return ()=>window.clearTimeout(timer) },[open,step])
  const running=open&&step<scanChecks.length
  const progress=step<0?0:Math.min(100,Math.round(step/scanChecks.length*100))
  const score = metrics?.healthScore ?? 82
  const weak = metrics?.weakCount ?? 3
  const reused = metrics?.reusedPasswordCount ?? 2
  return <><button className="scan-launch" onClick={()=>{setStep(0);setOpen(true)}}><ScanLine size={16}/><span>RUN SECURITY SCAN</span><i/></button>{open&&<div className="scan-backdrop" role="presentation" onMouseDown={event=>{if(event.target===event.currentTarget&&!running)setOpen(false)}}><section className={`scan-dialog ${running?"is-scanning":"scan-complete"}`} role="dialog" aria-modal="true" aria-labelledby="scan-title"><button className="scan-close" aria-label="Close scan report" disabled={running} onClick={()=>setOpen(false)}><X size={18}/></button><div className="scan-dialog-visual"><div className="scan-pulse scan-pulse-one"/><div className="scan-pulse scan-pulse-two"/><div className="scan-emblem"><HolographicShield size={58}/></div><span className="scan-beam"/></div><span className="eyebrow">LOCAL DIAGNOSTIC</span><h2 id="scan-title">{running?"Scanning your security":"Security scan complete"}</h2><p className="scan-intro">{running?"Reviewing credential health signals in this browser.":"Your workspace has been reviewed locally. No external systems were scanned."}</p><div className="scan-progress-meta"><span>{running?"ANALYSIS PROGRESS":"CHECKS COMPLETE"}</span><strong>{running?`${progress}%`:"100%"}</strong></div><div className="scan-progress-track"><span style={{width:`${running?progress:100}%`}}/></div><div className="scan-checks">{scanChecks.map((label,index)=>{const done=!running||index<step;const attention=index===1||index===2;return <div className={`scan-check ${done?"done":""} ${done&&attention?"attention":""}`} key={label}><span>{done?(attention?<CircleAlert size={14}/>:<Check size={14}/>):<i/>}</span><span>{label}</span><small>{done?(attention?"REVIEW":"CLEAR"):"WAITING"}</small></div>})}</div>{!running&&<div className="scan-summary"><ShieldCheck size={17}/><span><strong>{score} / 100 · {score >= 70 ? "Good protection" : "Needs attention"}</strong><small>{weak} weak password{weak === 1 ? "" : "s"} and {reused} reused pattern{reused === 1 ? "" : "s"} need attention.</small></span></div>}<div className="scan-actions">{running?<span className="scan-running-label"><i/> RUNNING LOCAL CHECKS</span>:<><button className="scan-secondary" onClick={()=>{setStep(0)}}><RotateCcw size={14}/> Scan again</button><button className="scan-primary" onClick={()=>{setOpen(false);onRecommendations()}}>View recommendations <ArrowRight size={14}/></button><button className="scan-close-report" onClick={()=>setOpen(false)}>Close report</button></>}</div><div className="scan-disclaimer"><LockKeyhole size={12}/> Local zero-knowledge check. Not antivirus or external threat detection.</div></section></div>}</>
}

export function SecurityStatusIndicator() { return <span className="core-status-chip"><span className="status-dot good"/> ALL SYSTEMS NORMAL</span> }
export function AssistantOrb({ thinking = false }: { thinking?: boolean }) { return <div className={`assistant-orb ${thinking?"thinking":""}`} aria-hidden="true"><div className="assistant-orb-ring ring-one"/><div className="assistant-orb-ring ring-two"/><div className="assistant-orb-center"><Sparkles size={22}/></div><span/></div> }
