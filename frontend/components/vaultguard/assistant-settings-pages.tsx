'use client'

import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react"
import { ArrowRight, Check, CheckCircle2, ChevronDown, Cloud, Download, FileUp, Fingerprint, HardDrive, Info, KeyRound, LockKeyhole, Monitor, Moon, RotateCw, Send, Shield, ShieldAlert, ShieldCheck, Sparkles, Smartphone, Trash2, UserRound, X } from "lucide-react"
import { AssistantOrb } from "@/components/vaultguard/command-center-visuals"
import { useVault } from "@/lib/crypto/vault-context"
import { useAuth } from "@/lib/auth/auth-context"
import { deviceApi } from "@/lib/api/devices"
import type { DeviceResponse } from "@/lib/api/types"
import { computeVaultMetrics, getLockedVaultMetrics } from "@/lib/vault-metrics"
import {
  analyzeVaultSecurity,
  getAssistantResponse,
  getContextualSuggestedPrompts,
  type VaultAssistantAnalysis,
  type AssistantRecommendation
} from "@/lib/security-assistant"

type ChatMessage = { role: "assistant" | "user"; text: string; time: string }

export function AssistantPage() {
  const { user, isAuthenticated } = useAuth()
  const { items, keyState } = useVault()
  const isLocked = keyState !== "unlocked"
  const currentUserId = user?.id ?? null

  const userName = user?.email ? user.email.split("@")[0] : "Alex Morgan"
  const userInitials = userName.slice(0, 2).toUpperCase()

  const metrics = useMemo(() => {
    return isLocked ? getLockedVaultMetrics() : computeVaultMetrics(items)
  }, [items, isLocked])

  const analysis = useMemo(() => {
    return analyzeVaultSecurity(items, metrics, { isLocked, userEmail: user?.email })
  }, [items, metrics, isLocked, user?.email])

  const initialGreeting = useMemo<ChatMessage>(() => {
    if (isLocked) {
      return {
        role: "assistant",
        text: `Hi ${userName}. Your vault is currently locked. To safeguard zero-knowledge privacy, credentials and health metrics are completely inaccessible until you unlock your vault with your master password.`,
        time: "Just now"
      }
    }
    if (analysis.isEmpty) {
      return {
        role: "assistant",
        text: `Hi ${userName}. Your vault is currently empty with 0 saved accounts. Add your first entry or import an encrypted backup to receive personalized security guidance.`,
        time: "Just now"
      }
    }
    const scoreText = analysis.healthScore !== null ? ` (health score: ${analysis.healthScore}/100)` : ""
    return {
      role: "assistant",
      text: `Hi ${userName}. I’ve analyzed your ${analysis.totalEntries} saved vault ${analysis.totalEntries === 1 ? "entry" : "entries"}${scoreText} locally in your browser. All analysis runs 100% on your device with zero data sent to external AI services.`,
      time: "Just now"
    }
  }, [isLocked, analysis.isEmpty, analysis.totalEntries, analysis.healthScore, userName])

  const [messages, setMessages] = useState<ChatMessage[]>([initialGreeting])
  const [conversationUserId, setConversationUserId] = useState<string | null>(currentUserId)
  const [input, setInput] = useState("")
  const [typing, setTyping] = useState(false)
  const [feedback, setFeedback] = useState("")
  const timeout = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Clear assistant conversation state when vault locks, logs out, or user switches
  useEffect(() => {
    if (timeout.current) clearTimeout(timeout.current)
    setTyping(false)
    setMessages([initialGreeting])
    setConversationUserId(currentUserId)
    setFeedback("")
    setInput("")
  }, [isLocked, currentUserId, user?.email, initialGreeting])

  useEffect(() => () => {
    if (timeout.current) clearTimeout(timeout.current)
  }, [])

  const contextualPrompts = useMemo(() => getContextualSuggestedPrompts(analysis), [analysis])

  const sendMessage = (text = input) => {
    const prompt = text.trim()
    if (!prompt || typing) return
    setMessages(current => [...current, { role: "user", text: prompt, time: "Just now" }])
    setInput("")
    setTyping(true)
    setFeedback("")

    if (timeout.current) clearTimeout(timeout.current)
    timeout.current = setTimeout(() => {
      const response = getAssistantResponse(prompt, analysis, { userName })
      setMessages(current => [...current, { role: "assistant", text: response.text, time: "Just now" }])
      setTyping(false)
    }, 350)
  }

  const handleReset = () => {
    if (timeout.current) clearTimeout(timeout.current)
    setTyping(false)
    setMessages([initialGreeting])
    setFeedback("Conversation reset to current vault state.")
  }

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing && event.keyCode !== 229) {
      event.preventDefault()
      sendMessage()
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Synchronous Render Privacy Guard 1: Locked Vault State
  // ─────────────────────────────────────────────────────────────────────────────
  // When locked, render dedicated locked view synchronously. Never render previous
  // chat transcript, advice cards, or composer input even for a single render frame.
  if (isLocked) {
    return (
      <div className="feature-page">
        <div className="assistant-page-grid">
          <section className="assistant-chat panel">
            <div className="chat-header">
              <AssistantOrb thinking={false} />
              <div>
                <span className="eyebrow">VAULTGUARD SECURITY ASSISTANT</span>
                <h1>Vault is locked.</h1>
                <span className="chat-disclaimer">
                  <i style={{ background: "#f5bd5a" }} /> In-memory security analysis offline
                </span>
              </div>
            </div>

            <div
              className="chat-transcript"
              aria-live="polite"
              style={{
                display: "flex",
                flexDirection: "column",
                justifyContent: "center",
                alignItems: "center",
                minHeight: "350px",
                textAlign: "center"
              }}
            >
              <div
                style={{
                  maxWidth: "420px",
                  padding: "24px 20px",
                  background: "rgba(25, 38, 48, 0.6)",
                  border: "1px solid #2a3a44",
                  borderRadius: "14px"
                }}
              >
                <div
                  style={{
                    width: "42px",
                    height: "42px",
                    margin: "0 auto 14px",
                    borderRadius: "12px",
                    background: "rgba(245, 189, 90, 0.12)",
                    border: "1px solid rgba(245, 189, 90, 0.3)",
                    display: "grid",
                    placeItems: "center",
                    color: "#f5bd5a"
                  }}
                >
                  <LockKeyhole size={20} />
                </div>
                <h2 style={{ fontSize: "16px", fontWeight: "600", color: "#edf7fa", margin: "0 0 8px" }}>
                  Zero-Knowledge Protection Active
                </h2>
                <p style={{ fontSize: "10px", lineHeight: "1.6", color: "#92a6b2", margin: "0 0 16px" }}>
                  To maintain strict zero-knowledge confidentiality, your credentials and security metrics are not accessible in browser memory. Please unlock your vault with your master password to view contextual security guidance.
                </p>
                <div
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "6px",
                    fontSize: "9px",
                    color: "#65d0a2",
                    background: "rgba(69, 214, 160, 0.1)",
                    padding: "5px 10px",
                    borderRadius: "6px",
                    border: "1px solid rgba(69, 214, 160, 0.2)"
                  }}
                >
                  <ShieldCheck size={13} /> Zero plaintext stored in browser
                </div>
              </div>
            </div>

            <div className="chat-footnote">
              <LockKeyhole size={13} /> Unlock your vault from the top navigation to analyze password health.
            </div>
          </section>

          <aside className="assistant-side">
            <div className="assistant-advice panel">
              <span className="eyebrow">VAULT STATUS</span>
              <h2>Locked for your security.</h2>
              <div className="advice-item">
                <div className="priority-label amber">LOCKED</div>
                <strong>Decryption key offline</strong>
                <p>In-memory AES-256-GCM encryption key was purged. Credentials cannot be analyzed until you unlock.</p>
              </div>
            </div>

            <div className="assistant-safety panel">
              <Shield size={17} />
              <div>
                <strong>Zero-knowledge by design</strong>
                <p>VaultGuard never caches decrypted data or sends prompts to external AI servers.</p>
              </div>
            </div>
          </aside>
        </div>
      </div>
    )
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Synchronous Render Privacy Guard 2: Account Isolation Gating
  // ─────────────────────────────────────────────────────────────────────────────
  // If active conversation belongs to a different account ID or unauthenticated,
  // render safe transition view synchronously to prevent cross-account leakage.
  if (conversationUserId !== currentUserId || !isAuthenticated) {
    return (
      <div className="feature-page">
        <div className="assistant-page-grid">
          <section className="assistant-chat panel">
            <div className="chat-header">
              <AssistantOrb thinking={true} />
              <div>
                <span className="eyebrow">VAULTGUARD SECURITY ASSISTANT</span>
                <h1>Switching account context...</h1>
                <span className="chat-disclaimer">
                  <i style={{ background: "#9275F5" }} /> Isolating account data
                </span>
              </div>
            </div>
            <div
              className="chat-transcript"
              aria-live="polite"
              style={{
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                minHeight: "350px"
              }}
            >
              <div style={{ textAlign: "center", color: "#92a6b2", fontSize: "11px" }}>
                Establishing clean assistant session for active account...
              </div>
            </div>
          </section>
          <aside className="assistant-side">
            <div className="assistant-safety panel">
              <Shield size={17} />
              <div>
                <strong>Strict account isolation</strong>
                <p>Assistant sessions are strictly bounded to the active authenticated account.</p>
              </div>
            </div>
          </aside>
        </div>
      </div>
    )
  }

  return (
    <div className="feature-page">
      <div className="assistant-page-grid">
        <section className="assistant-chat panel">
          <div className="chat-header">
            <AssistantOrb thinking={typing} />
            <div>
              <span className="eyebrow">VAULTGUARD SECURITY ASSISTANT</span>
              <h1>Contextual security guidance, zero knowledge.</h1>
              <span className="chat-disclaimer">
                <i style={{ background: isLocked ? "#f5bd5a" : "#45D6A0" }} />{" "}
                {isLocked ? "Vault locked · In-memory analysis offline" : "Local rule-based engine · 100% zero-knowledge"}
              </span>
            </div>
            <button className="quiet-action chat-reset" onClick={handleReset} aria-label="Reset conversation">
              <RotateCw size={13} /> Reset
            </button>
          </div>

          <div className="chat-transcript" aria-live="polite">
            {messages.map((message, index) => (
              <div className={`chat-message ${message.role}`} key={`${index}-${message.role}`}>
                <div className="chat-avatar">
                  {message.role === "assistant" ? <ShieldCheck size={14} /> : userInitials}
                </div>
                <div className="chat-bubble">
                  <div style={{ whiteSpace: "pre-line" }}>{message.text}</div>
                  <time>{message.time}</time>
                </div>
              </div>
            ))}
            {typing && (
              <div className="chat-message assistant">
                <div className="chat-avatar"><ShieldCheck size={14} /></div>
                <div className="typing-bubble" aria-label="Assistant is analyzing vault records locally">
                  <i /><i /><i />
                </div>
              </div>
            )}
          </div>

          <div className="suggested-prompts">
            <span>TRY ASKING</span>
            <div>
              {contextualPrompts.map(prompt => (
                <button key={prompt} onClick={() => sendMessage(prompt)} disabled={typing}>
                  {prompt}
                  <ArrowRight size={12} />
                </button>
              ))}
            </div>
          </div>

          <div className="chat-composer">
            <input
              aria-label="Ask the security assistant"
              value={input}
              onChange={event => setInput(event.target.value)}
              onKeyDown={onKeyDown}
              placeholder={isLocked ? "Unlock vault to ask contextual questions..." : "Ask a question about your vault security..."}
            />
            <button aria-label="Send message" disabled={!input.trim() || typing} onClick={() => sendMessage()}>
              <Send size={16} />
            </button>
          </div>

          <div className="chat-footnote">
            <LockKeyhole size={13} /> Passwords, master keys, and decrypted records are never transmitted or logged.
          </div>
          {feedback && <div className="chat-feedback" role="status">{feedback}</div>}
        </section>

        <aside className="assistant-side">
          <div className="assistant-advice panel">
            <span className="eyebrow">YOUR NEXT BEST STEPS</span>
            <h2>Actionable steps for a stronger vault.</h2>
            {analysis.recommendations.slice(0, 4).map(item => (
              <div className="advice-item" key={item.id}>
                <div className={`priority-label ${item.tone}`}>{item.priority}</div>
                <strong>{item.title}</strong>
                <p>{item.desc}</p>
                <small style={{
                  display: "block",
                  marginTop: "6px",
                  color: item.tone === "rose" ? "#ff8599" : item.tone === "amber" ? "#edbf73" : item.tone === "green" ? "#65d0a2" : "#8ca8b5",
                  fontSize: "8.5px",
                  lineHeight: "1.4"
                }}>
                  <strong>Next:</strong> {item.actionText}
                </small>
              </div>
            ))}
          </div>

          <div className="assistant-safety panel">
            <Shield size={17} />
            <div>
              <strong>Your privacy is built in</strong>
              <p>All recommendations are derived client-side from your decrypted in-memory vault. Nothing is sent to an external AI service.</p>
            </div>
          </div>
        </aside>
      </div>
    </div>
  )
}

const settingTabs=[{id:"profile",label:"Profile",icon:UserRound},{id:"security",label:"Security",icon:ShieldCheck},{id:"sync",label:"Sync & backup",icon:Cloud},{id:"privacy",label:"Privacy & data",icon:HardDrive}] as const
type SettingTab=(typeof settingTabs)[number]["id"]
function Toggle({label,description,checked,onChange}:{label:string;description:string;checked:boolean;onChange:(value:boolean)=>void}){return <label className="setting-toggle"><span><strong>{label}</strong><small>{description}</small></span><input type="checkbox" checked={checked} onChange={event=>onChange(event.target.checked)}/><i aria-hidden="true"/></label>}

export function SettingsPage(){
  const { user, isAuthenticated } = useAuth()
  const { isInitialized, autoLockMinutes, setAutoLockMinutes, resetVault, syncNow, lastSyncTime, syncStatus } = useVault()
  const [tab,setTab]=useState<SettingTab>("profile")
  const [name,setName]=useState(user?.email ? user.email.split("@")[0] : "Alex Morgan")
  const [email,setEmail]=useState(user?.email || "alex.morgan@example.test")
  const [autoLock,setAutoLock]=useState(autoLockMinutes === 0 ? "Immediately" : `${autoLockMinutes} minutes`)
  const [biometric,setBiometric]=useState(false)
  const [twoFactor,setTwoFactor]=useState(false)
  const [notifications,setNotifications]=useState(true)
  const [weekly,setWeekly]=useState(false)
  const [automaticSync,setAutomaticSync]=useState(true)
  const [devices,setDevices]=useState<DeviceResponse[]>([])
  const [demoDevices,setDemoDevices]=useState(["MacBook Pro · This device","iPhone 16 · Last seen today","Chrome on Windows · Last seen Nov 15"])
  const [feedback,setFeedback]=useState("")
  const [importName,setImportName]=useState("")

  // Update profile inputs when authenticated user changes
  useEffect(() => {
    if (user?.email) {
      setEmail(user.email)
      setName(user.email.split("@")[0])
    }
  }, [user])

  // Fetch real registered devices when authenticated
  useEffect(() => {
    if (isAuthenticated) {
      deviceApi.listDevices()
        .then(list => setDevices(list))
        .catch(() => {})
    }
  }, [isAuthenticated])

  const handleRemoveDevice = async (deviceId: string, deviceName: string) => {
    try {
      await deviceApi.removeDevice(deviceId)
      setDevices(prev => prev.filter(d => d.id !== deviceId))
      setFeedback(`Removed device '${deviceName}' and revoked its server sessions.`)
    } catch (err: any) {
      setFeedback(`Error: ${err?.message || "Failed to remove device."}`)
    }
  }

  const handleAutoLockChange = (val: string) => {
    setAutoLock(val)
    const map: Record<string, number> = { "Immediately": 0, "1 minute": 1, "5 minutes": 5, "15 minutes": 15, "30 minutes": 30 }
    if (val in map) {
      setAutoLockMinutes(map[val])
      setFeedback(`Inactivity auto-lock set to ${val}.`)
    }
  }

  const handleResetVault = async () => {
    await resetVault()
    setFeedback("Local encrypted database cleared and reset.")
  }

  const handleManualSync = async () => {
    try {
      setFeedback("Synchronizing vault changes with backend...")
      await syncNow()
      setFeedback("Synchronization completed.")
    } catch (err: any) {
      setFeedback(`Sync error: ${err?.message || "Failed to synchronize."}`)
    }
  }

  const downloadDemoExport=()=>{const data=JSON.stringify({format:"VaultGuard demo metadata",notice:"No passwords or secrets included. This is not a real vault backup.",exportedAt:new Date().toISOString(),profile:{name,email},devices: isAuthenticated ? devices : demoDevices},null,2);const link=document.createElement("a");link.href=URL.createObjectURL(new Blob([data],{type:"application/json"}));link.download="vaultguard-demo-metadata.json";link.click();URL.revokeObjectURL(link.href);setFeedback("Downloaded demo metadata only—no passwords or secrets included.")}

  return <div className="feature-page"><div className="feature-heading settings-page-heading"><div className="feature-heading-icon"><LockKeyhole size={19}/></div><div><span className="eyebrow">PREFERENCES & PROTECTION</span><h1>Settings</h1><p>{isAuthenticated ? "Manage your account, devices, and security controls." : "Review preferences and demo-only security controls."}</p></div></div><div className="settings-layout"><nav className="settings-nav panel" aria-label="Settings sections">{settingTabs.map(item=><button key={item.id} aria-current={tab===item.id?"page":undefined} className={tab===item.id?"settings-nav-item active":"settings-nav-item"} onClick={()=>setTab(item.id)}><item.icon size={16}/>{item.label}<ArrowRight size={13}/></button>)}<div className="settings-nav-note"><Info size={14}/> {isAuthenticated ? "Connected to VaultGuard API." : "Controls are preview state only. No account changes are saved."}</div></nav><div className="settings-content">{tab==="profile"&&<><SettingsSection title="Account profile" description={isAuthenticated ? "Authenticated account information." : "Profile details are sample values and remain in this page session."}><div className="settings-fields"><label>Display name<input value={name} onChange={event=>setName(event.target.value)}/></label><label>Email address<input type="email" value={email} readOnly={isAuthenticated} onChange={event=>setEmail(event.target.value)}/></label></div>{isAuthenticated ? <div className="settings-inline-warning" style={{ color: "#45D6A0" }}><ShieldCheck size={14}/> Account is active. Authenticated with Argon2id credentials.</div> : <div className="settings-inline-warning"><Info size={14}/> No account or authentication service is connected.</div>}<button className="primary-action settings-save" onClick={()=>setFeedback(isAuthenticated ? "Display name updated." : "Profile preview updated in memory only.")}><Check size={14}/> {isAuthenticated ? "Save preferences" : "Save preview"}</button></SettingsSection><SettingsSection title="Appearance" description="Customize this interface."><div className="appearance-choice"><div className="appearance-tile selected"><Moon size={17}/><span>Dark</span><Check size={13}/></div><button className="appearance-tile" onClick={()=>setFeedback("Light appearance is not included in this dark-first theme.")}><span className="light-theme-icon"/><span>Light</span><span className="coming-tag">PREVIEW</span></button></div></SettingsSection></>}{tab==="security"&&<><SettingsSection title="Security preferences" description="Configure your vault and authentication preferences."><Toggle label="Biometric unlock" description="Preview state only—no biometrics are accessed." checked={biometric} onChange={setBiometric}/><div className="settings-row"><div className="setting-row-icon violet"><Fingerprint size={16}/></div><div className="setting-row-copy"><strong>Two-factor authentication</strong><small>Argon2id account security active. 2FA setup available soon.</small></div><button className={twoFactor?"secondary-action":"outline-action"} onClick={()=>{setTwoFactor(!twoFactor);setFeedback(twoFactor?"Two-factor setup preview turned off.":"Setup is not connected. No account security setting changed.")}}>{twoFactor?"Preview enabled":"Set up"}</button></div><label className="settings-select-row"><span><strong>Auto-lock timeout</strong><small>Automatically locks vault and clears in-memory CryptoKey on inactivity.</small></span><select value={autoLock} onChange={event=>handleAutoLockChange(event.target.value)}><option>Immediately</option><option>1 minute</option><option>5 minutes</option><option>15 minutes</option><option>30 minutes</option></select><ChevronDown size={13}/></label><div className="settings-row"><div className="setting-row-icon cyan"><KeyRound size={16}/></div><div className="setting-row-copy"><strong>Master password</strong><small>AES-256-GCM + PBKDF2 (600,000 iterations). {isInitialized ? "Active · Initialized locally." : "Not initialized yet."}</small></div><button className="outline-action" onClick={handleResetVault}>Reset local vault</button></div></SettingsSection><SettingsSection title="Devices & sessions" description={isAuthenticated ? "Active registered devices and sessions for your account." : "Mock devices and sessions for interface preview."}>{isAuthenticated ? (devices.length > 0 ? devices.map((device)=><div className="device-row" key={device.id}><span className="device-icon"><Monitor size={16}/></span><span><strong>{device.deviceName || device.deviceIdentifier}</strong><small>{device.isCurrent ? "Current active session" : `Last seen: ${device.lastSeenAt ? new Date(device.lastSeenAt).toLocaleDateString() : "Recently"}`}</small></span>{device.isCurrent ? <span className="current-device">THIS DEVICE</span> : <button className="device-remove" aria-label={`Remove ${device.deviceName || device.deviceIdentifier}`} onClick={()=>handleRemoveDevice(device.id, device.deviceName || device.deviceIdentifier)}><X size={15}/></button>}</div>) : <div className="device-row"><span className="device-icon"><Monitor size={16}/></span><span><strong>Current session</strong><small>Active device</small></span><span className="current-device">THIS DEVICE</span></div>) : (demoDevices.map((device,index)=><div className="device-row" key={device}><span className="device-icon">{index===1?<Smartphone size={16}/>:<Monitor size={16}/>}</span><span><strong>{device}</strong><small>{index===0?"Current session · demo mode":"Sample device · no real session"}</small></span>{index===0?<span className="current-device">THIS DEVICE</span>:<button className="device-remove" aria-label={`Remove ${device}`} onClick={()=>{setDemoDevices(current=>current.filter(item=>item!==device));setFeedback("Removed the sample device from this page.")}}><X size={15}/></button>}</div>))}</SettingsSection></>}{tab==="sync"&&<><SettingsSection title="Sync & backup" description={isAuthenticated ? "Incremental zero-knowledge cloud synchronization." : "Cloud sync is not connected. This page does not upload, download, or back up any data."}><div className="sync-status-panel"><div className="sync-status-icon"><Cloud size={20}/></div><div><span className="eyebrow">CLOUD CONNECTION</span><strong>{isAuthenticated ? "Connected to VaultGuard API" : "Not connected"}</strong><small>{isAuthenticated ? (syncStatus === "syncing" ? "Syncing changes..." : "Synchronized · 30-second polling active") : "Cloud synchronization will require a future backend."}</small></div><span className="coming-tag" style={{ background: isAuthenticated ? "rgba(69, 214, 160, 0.15)" : undefined, color: isAuthenticated ? "#45D6A0" : undefined }}>{isAuthenticated ? "ACTIVE" : "PREVIEW ONLY"}</span></div><Toggle label="Automatic sync" description="Periodically sync changes with backend every 30 seconds." checked={automaticSync} onChange={setAutomaticSync}/><div className="sync-metadata"><div><span>Last synchronized</span><strong>{lastSyncTime ? lastSyncTime.toLocaleTimeString() : (isAuthenticated ? "Recently" : "Never · not connected")}</strong></div><div><span>Status</span><strong>{isAuthenticated ? syncStatus.toUpperCase() : "DEMO"}</strong></div></div><div className="sync-actions"><button className="secondary-action" onClick={handleManualSync} disabled={!isAuthenticated}><RotateCw size={14}/> Sync now</button></div></SettingsSection></>}{tab==="privacy"&&<><SettingsSection title="Privacy & data" description="Privacy and data management."><Toggle label="Security notifications" description="Show sample activity and reminder controls." checked={notifications} onChange={setNotifications}/><Toggle label="Weekly security digest" description="Mock preference only; no email will be sent." checked={weekly} onChange={setWeekly}/><div className="data-action-row"><div><strong>Export demo metadata</strong><small>Downloads profile and device metadata. Excludes passwords and secrets.</small></div><button className="secondary-action" onClick={downloadDemoExport}><Download size={14}/> Export</button></div><div className="data-action-row"><div><strong>Import preview</strong><small>Choose a file to preview the import control; its contents are not processed.</small></div><label className="secondary-action file-pick"><FileUp size={14}/> Choose file<input type="file" accept=".json,.csv" onChange={event=>{setImportName(event.target.files?.[0]?.name??"");setFeedback("File selection preview only; no data was imported.")}}/></label></div>{importName&&<div className="file-selected"><CheckCircle2 size={14}/>{importName} selected · not imported</div>}<button className="danger-outline" onClick={handleResetVault}><Trash2 size={14}/> Clear local vault data</button></SettingsSection><SettingsSection title="About VaultGuard" description="Zero-knowledge cybersecurity password manager."><div className="about-line"><span>Version</span><strong>1.0 · Phase 9 Integrated</strong></div><div className="about-line"><span>Encryption</span><strong>AES-256-GCM + PBKDF2 (600,000 iterations)</strong></div><div className="about-line"><span>Cloud sync</span><strong>{isAuthenticated ? "Connected · Incremental Sync" : "Not connected"}</strong></div><div className="about-line"><span>Account Security</span><strong>Argon2id + Rotating Refresh Sessions</strong></div></SettingsSection></>}{feedback&&<div className="toast-message settings-toast" role="status">{feedback}<button aria-label="Dismiss" onClick={()=>setFeedback("")}><X size={14}/></button></div>}</div></div></div>
}

function SettingsSection({title,description,children}:{title:string;description:string;children:ReactNode}){return <section className="panel settings-section"><div className="settings-section-heading"><h2>{title}</h2><p>{description}</p></div>{children}</section>}
