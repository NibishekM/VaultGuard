'use client'

import { useEffect, useMemo, useRef, useState } from "react"
import { Activity, ArrowDownRight, ArrowRight, ArrowUpRight, Bell, Check, ChevronDown, CircleHelp, Cloud, Command, Fingerprint, FolderKey, Gauge, KeyRound, LayoutDashboard, LockKeyhole, LogOut, Menu, MoreHorizontal, Search, Settings, Shield, ShieldAlert, ShieldCheck, Sparkles, WandSparkles, X } from "lucide-react"
import { AuthPortal } from "@/components/vaultguard/auth-portal"
import { AnalyzerPage, GeneratorPage } from "@/components/vaultguard/password-tools-pages"
import { AssistantPage, SettingsPage } from "@/components/vaultguard/assistant-settings-pages"
import { VaultPage } from "@/components/vaultguard/vault-page"
import { healthBreakdown, navigationItems, securityEvents, type NavigationItem } from "@/lib/vaultguard-data"
import { HolographicShield, SecurityCore, SecurityNetwork, SecurityScan, SecurityStatusIndicator, ThreatRadar } from "@/components/vaultguard/command-center-visuals"
import { useVault } from "@/lib/crypto/vault-context"
import { useAuth } from "@/lib/auth/auth-context"
import { computeVaultMetrics, getLockedVaultMetrics, type VaultMetrics } from "@/lib/vault-metrics"
import { demoVaultEntries } from "@/lib/vaultguard-service"

const navIcons = [LayoutDashboard, Gauge, WandSparkles, FolderKey, Sparkles, Settings]

function Brand() {
  return <div className="brand"><div className="brand-mark"><HolographicShield size={23} /></div><span>vault<span className="brand-light">guard</span></span></div>
}

function Sidebar({
  active,
  onNavigate,
  mobileOpen,
  onClose,
  userName,
  userInitials,
  isSynced,
  weakCount
}: {
  active: NavigationItem
  onNavigate: (item: NavigationItem) => void
  mobileOpen: boolean
  onClose: () => void
  userName: string
  userInitials: string
  isSynced: boolean
  weakCount?: number
}) {
  return <>
    {mobileOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={onClose} />}
    <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
      <div className="sidebar-top"><Brand /><button className="icon-button close-nav" aria-label="Close navigation" onClick={onClose}><X size={18} /></button></div>
      <div className="workspace-label">WORKSPACE</div>
      <nav className="side-nav" aria-label="Main navigation">{navigationItems.map((item, i) => { const Icon = navIcons[i]; return <button key={item} onClick={() => { onNavigate(item); onClose() }} className={`nav-item ${active === item ? "nav-active" : ""}`} aria-current={active === item ? "page" : undefined}><Icon size={17} strokeWidth={1.8} /><span>{item}</span>{item === "Password Analyzer" && (weakCount !== undefined ? (weakCount > 0 && <span className="nav-count">{weakCount}</span>) : <span className="nav-count">3</span>)}</button> })}</nav>
      <div className="sidebar-bottom">
        <div className="sync-card">
          <div className="sync-icon"><Cloud size={16} /></div>
          <div>
            <strong>{isSynced ? "Cloud Sync Active" : "Demo workspace"}</strong>
            <span>{isSynced ? "Zero-knowledge synchronized" : "Cloud sync not connected"}</span>
          </div>
          <span className="sync-dot" style={{ background: isSynced ? "#45D6A0" : undefined }} />
        </div>
        <button className="user-row" onClick={() => onNavigate("Settings")}>
          <div className="avatar">{userInitials}</div>
          <span className="user-info"><strong>{userName}</strong><small>{isSynced ? "Encrypted vault" : "Personal workspace"}</small></span>
          <MoreHorizontal size={18} className="user-more" />
        </button>
      </div>
    </aside>
  </>
}

function Popover({
  kind,
  onClose,
  onSelect,
  onSignOut,
  onMarkRead,
  userName,
  userEmail,
  userInitials
}: {
  kind: "notifications" | "profile"
  onClose: () => void
  onSelect: (item: NavigationItem) => void
  onSignOut: () => void
  onMarkRead: () => void
  userName: string
  userEmail: string
  userInitials: string
}) {
  return <div className={`popover popover-${kind}`} role="dialog" aria-label={kind === "notifications" ? "Notifications" : "Profile menu"}>
    {kind === "notifications" ? (
      <>
        <div className="popover-heading"><div><strong>Notifications</strong><span>Recent security updates</span></div><button className="text-button" onClick={onMarkRead}>Mark all read</button></div>
        <div className="notification-row"><span className="notification-icon green"><ShieldCheck size={16} /></span><div><strong>Security scan complete</strong><span>Your vault is looking healthy.</span><small>18 minutes ago</small></div></div>
        <div className="notification-row"><span className="notification-icon amber"><ShieldAlert size={16} /></span><div><strong>3 passwords need attention</strong><span>Review your weak passwords.</span><small>2 hours ago</small></div></div>
      </>
    ) : (
      <>
        <div className="profile-popover-head">
          <div className="avatar">{userInitials}</div>
          <div><strong>{userName}</strong><span>{userEmail}</span></div>
        </div>
        <button className="popover-action" onClick={() => onSelect("Settings")}><Settings size={16} /> Account settings</button>
        <button className="popover-action" onClick={() => onSelect("Settings")}><CircleHelp size={16} /> Help & support</button>
        <div className="popover-divider" />
        <button className="popover-action danger" onClick={onSignOut}><LogOut size={16} /> Sign out</button>
      </>
    )}
  </div>
}

function Header({
  active,
  onNavigate,
  onSearch,
  onSignOut,
  userName,
  userEmail,
  userInitials,
  isSynced
}: {
  active: NavigationItem
  onNavigate: (item: NavigationItem) => void
  onSearch: (query: string) => void
  onSignOut: () => void
  userName: string
  userEmail: string
  userInitials: string
  isSynced: boolean
}) {
  const { keyState, lockVault, syncNow, syncStatus } = useVault()
  const [menu, setMenu] = useState<"notifications" | "profile" | null>(null)
  const [search, setSearch] = useState("")
  const [hasUnread, setHasUnread] = useState(true)
  const searchRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const focusSearch = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener("keydown", focusSearch)
    return () => window.removeEventListener("keydown", focusSearch)
  }, [])

  return (
    <header className="topbar">
      <div className="mobile-brand"><Brand /></div>
      <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => window.dispatchEvent(new Event("vaultguard:open-nav"))}><Menu size={19} /></button>
      <div className="topbar-title"><span>Workspace</span><span className="crumb-slash">/</span><strong>{active}</strong></div>
      <label className="search-box">
        <Search size={16} />
        <input
          ref={searchRef}
          aria-label="Search VaultGuard"
          placeholder="Search your vault..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={event => { if (event.key === "Enter" && !event.nativeEvent.isComposing && event.keyCode !== 229) { event.preventDefault(); onSearch(search) } }}
        />
        <kbd><Command size={11} /> K</kbd>
      </label>
      <div className="topbar-actions">
        <div className="header-sync">
          <span className="sync-dot" style={{ background: keyState === "unlocked" ? "#45D6A0" : undefined }} />
          {keyState === "unlocked"
            ? (isSynced ? (syncStatus === "syncing" ? "Syncing..." : "Vault Unlocked · AES-256-GCM") : "Vault Unlocked · Local")
            : "Vault Locked"}
        </div>
        {keyState === "unlocked" && isSynced && (
          <button
            className="icon-button"
            style={{ padding: "6px 10px", fontSize: "12px", gap: "4px" }}
            title="Synchronize with backend"
            aria-label="Synchronize with backend"
            onClick={() => syncNow()}
          >
            <Cloud size={14} /> Sync
          </button>
        )}
        {keyState === "unlocked" && (
          <button
            className="icon-button"
            style={{ padding: "6px 10px", fontSize: "12px", gap: "4px" }}
            title="Lock vault"
            aria-label="Lock vault"
            onClick={lockVault}
          >
            <LockKeyhole size={14} /> Lock
          </button>
        )}
        <div className="popover-anchor">
          <button
            className={`icon-button notification-button ${menu === "notifications" ? "icon-button-active" : ""}`}
            aria-label="Notifications"
            aria-expanded={menu === "notifications"}
            onClick={() => setMenu(menu === "notifications" ? null : "notifications")}
          >
            <Bell size={18} />
            {hasUnread && <i />}
          </button>
          {menu === "notifications" && (
            <Popover
              kind="notifications"
              onClose={() => setMenu(null)}
              onSelect={onNavigate}
              onSignOut={onSignOut}
              onMarkRead={() => { setHasUnread(false); setMenu(null) }}
              userName={userName}
              userEmail={userEmail}
              userInitials={userInitials}
            />
          )}
        </div>
        <div className="popover-anchor">
          <button
            className="header-profile"
            aria-label="Open profile menu"
            aria-expanded={menu === "profile"}
            onClick={() => setMenu(menu === "profile" ? null : "profile")}
          >
            <div className="avatar avatar-small">{userInitials}</div>
            <ChevronDown size={14} />
          </button>
          {menu === "profile" && (
            <Popover
              kind="profile"
              onClose={() => setMenu(null)}
              onSelect={item => { onNavigate(item); setMenu(null) }}
              onSignOut={() => { setMenu(null); onSignOut() }}
              onMarkRead={() => { setHasUnread(false); setMenu(null) }}
              userName={userName}
              userEmail={userEmail}
              userInitials={userInitials}
            />
          )}
        </div>
      </div>
    </header>
  )
}

function SectionTitle({ title, action }: { title: string; action?: string }) {
  return <div className="section-heading"><h2>{title}</h2>{action && <button className="subtle-link" onClick={() => window.dispatchEvent(new CustomEvent("vaultguard:navigate"))}>{action}<ArrowRight size={14} /></button>}</div>
}

function ScoreCard({ metrics, onNavigate }: { metrics?: VaultMetrics; onNavigate?: () => void }) {
  const isLocked = metrics?.isLocked ?? false
  const isEmpty = (metrics?.isEmpty ?? false) && !isLocked
  const score = metrics ? metrics.healthScore : 82

  const title = isLocked
    ? "Vault is locked."
    : isEmpty
    ? "No passwords saved yet."
    : score !== null && score >= 80
    ? "Your security is looking good."
    : score !== null && score >= 60
    ? "Moderate protection level."
    : "Your vault needs attention."

  const description = isLocked
    ? "Unlock your vault to view real-time password health and security analytics."
    : isEmpty
    ? "Add credentials to your secure vault to evaluate password strength and reuse."
    : "Local zero-knowledge calculation based on your decrypted vault items."

  const statusText = isLocked
    ? "Locked"
    : isEmpty
    ? "Empty vault"
    : score !== null && score >= 80
    ? "Good protection"
    : score !== null && score >= 60
    ? "Moderate protection"
    : "Review needed"

  const strokeOffset = score !== null ? Math.round(434 * (1 - score / 100)) : 434

  return (
    <section className="score-card panel">
      <div className="score-copy">
        <div className="eyebrow"><span className="eyebrow-dot" /> SECURITY OVERVIEW</div>
        <h2>{title}</h2>
        <p>{description}</p>
        <button
          className="score-link"
          onClick={() => onNavigate ? onNavigate() : window.dispatchEvent(new CustomEvent("vaultguard:navigate", { detail: "Password Analyzer" }))}
        >
          View security report <ArrowRight size={15} />
        </button>
      </div>
      <div className="score-visual">
        <div className="score-ring">
          <svg viewBox="0 0 160 160" aria-label={`Security score ${score !== null ? `${score} out of 100` : "locked"}`} role="img">
            <circle className="ring-track" cx="80" cy="80" r="69" />
            <circle className="ring-progress" cx="80" cy="80" r="69" style={{ strokeDashoffset: strokeOffset }} />
          </svg>
          <div className="score-number">
            <strong>{score !== null ? score : "—"}</strong>
            <span>OUT OF 100</span>
          </div>
        </div>
        <div className="score-status">
          <span className="status-check"><Check size={12} /></span> {statusText}
        </div>
      </div>
      <div className="score-decoration" aria-hidden="true">
        <div className="orbit orbit-one"/>
        <div className="orbit orbit-two"/>
      </div>
    </section>
  )
}

function MetricCards({ metrics }: { metrics?: VaultMetrics }) {
  const isLocked = metrics?.isLocked ?? false
  const isEmpty = (metrics?.isEmpty ?? false) && !isLocked

  const cards = [
    {
      label: "Saved passwords",
      value: isLocked ? "—" : metrics ? String(metrics.totalEntries) : "24",
      icon: KeyRound,
      tone: "cyan",
      caption: isLocked
        ? "Vault is locked"
        : isEmpty
        ? "No accounts saved"
        : metrics
        ? (metrics.usablePasswordEntries === metrics.totalEntries
          ? `Across ${metrics.totalEntries} account${metrics.totalEntries === 1 ? "" : "s"}`
          : `${metrics.usablePasswordEntries} with passwords (${metrics.missingPasswordCount} missing)`)
        : "Across 18 accounts"
    },
    {
      label: "Weak passwords",
      value: isLocked ? "—" : metrics ? String(metrics.weakCount) : "3",
      icon: ShieldAlert,
      tone: "amber",
      caption: isLocked
        ? "Vault is locked"
        : isEmpty
        ? "No passwords saved"
        : metrics
        ? (metrics.weakCount === 0 ? "No weak passwords found" : `${metrics.weakCount} need${metrics.weakCount === 1 ? "s" : ""} your attention`)
        : "Need your attention"
    },
    {
      label: "Reused passwords",
      value: isLocked ? "—" : metrics ? String(metrics.reusedPasswordCount) : "2",
      icon: Fingerprint,
      tone: "violet",
      caption: isLocked
        ? "Vault is locked"
        : isEmpty
        ? "No passwords saved"
        : metrics
        ? (metrics.reusedPasswordCount === 0 ? "All passwords unique" : `Used across ${metrics.affectedAccountsCount} account${metrics.affectedAccountsCount === 1 ? "" : "s"}`)
        : "Used on multiple sites"
    }
  ]

  return (
    <div className="metric-grid">
      {cards.map(({ label, value, icon: Icon, tone, caption }) => (
        <article className="metric-card panel" key={label}>
          <div className={`metric-icon ${tone}`}><Icon size={17} /></div>
          <div className="metric-top">
            <span>{label}</span>
            <ArrowUpRight size={14} className="metric-arrow" />
          </div>
          <div className="metric-value">{value}</div>
          <div className="metric-caption">{caption}</div>
        </article>
      ))}
    </div>
  )
}

function HealthCard({ metrics }: { metrics?: VaultMetrics }) {
  const isLocked = metrics?.isLocked ?? false
  const isEmpty = (metrics?.isEmpty ?? false) && !isLocked
  const analyzed = isLocked ? 0 : metrics ? metrics.usablePasswordEntries : 24
  const strongPct = analyzed > 0 && metrics ? Math.round((metrics.strongCount / analyzed) * 100) : (metrics ? 0 : 67)

  const breakdown = metrics ? metrics.healthBreakdown : healthBreakdown

  const healthNote = isLocked
    ? "Vault is locked. Master password required to inspect credential health."
    : isEmpty
    ? "Your vault contains no passwords yet. Add an entry to analyze password health."
    : metrics
    ? (metrics.reusedPasswordCount === 0 && metrics.weakCount === 0 && analyzed > 0
      ? `All ${analyzed} account${analyzed === 1 ? "" : "s"} have unique, strong passwords.`
      : metrics.reusedPasswordCount > 0
      ? `${metrics.affectedAccountsCount} account${metrics.affectedAccountsCount === 1 ? "" : "s"} share reused password patterns.`
      : `${metrics.weakCount} weak password${metrics.weakCount === 1 ? "" : "s"} require attention.`)
    : "Your strongest streak is 12 accounts with unique passwords."

  return (
    <section className="panel content-card health-card">
      <SectionTitle title="Password health" action="View details" />
      <div className="health-summary">
        <div>
          <strong>{isLocked ? "—" : analyzed}</strong>
          <span>passwords analyzed</span>
        </div>
        <span className="health-badge">
          <span /> {isLocked || isEmpty ? "—" : `${strongPct}% strong`}
        </span>
      </div>
      <div
        className="health-bar"
        role="img"
        aria-label={
          isLocked
            ? "Vault is locked"
            : isEmpty
            ? "No passwords analyzed"
            : metrics
            ? `${metrics.strongCount} strong, ${metrics.fairCount} moderate, ${metrics.weakCount} weak passwords`
            : "16 strong, 5 moderate, 3 weak passwords"
        }
      >
        {analyzed > 0
          ? breakdown.map(x => (
              <span
                key={x.label}
                style={{ width: `${(x.count / analyzed) * 100}%`, background: x.color }}
              />
            ))
          : <span style={{ width: "100%", background: "#26453f", opacity: 0.4 }} />}
      </div>
      <div className="health-legend">
        {breakdown.map(x => (
          <div key={x.label}>
            <span className="legend-dot" style={{ background: x.color }} />
            <span>{x.label}</span>
            <strong>{isLocked ? "—" : x.count}</strong>
          </div>
        ))}
      </div>
      <div className="health-note">
        <ShieldCheck size={15} />
        <span>{healthNote}</span>
      </div>
    </section>
  )
}

function ActivityCard() {
  return <section className="panel content-card activity-card"><SectionTitle title="Recent activity" action="View all" /><div className="activity-list">{securityEvents.map((event, i) => <div className="activity-row" key={event.title}><div className={`activity-icon ${event.tone}`}>{event.tone === "green" ? <ShieldCheck size={15} /> : event.tone === "amber" ? <ShieldAlert size={15} /> : event.tone === "violet" ? <KeyRound size={15} /> : <LockKeyhole size={15} />}</div><div className="activity-copy"><strong>{event.title}</strong><span>{event.detail}</span></div><time>{event.time}</time>{i < securityEvents.length - 1 && <span className="activity-line" />}</div>)}</div></section>
}

function QuickActions({ onNavigate }: { onNavigate: (item: NavigationItem) => void }) {
  const actions = [{ title: "Analyze password", description: "Check strength & safety", icon: Gauge, target: "Password Analyzer" as const, tone: "cyan" }, { title: "Generate password", description: "Create a stronger one", icon: WandSparkles, target: "Password Generator" as const, tone: "violet" }, { title: "Open secure vault", description: "Browse saved accounts", icon: FolderKey, target: "Secure Vault" as const, tone: "green" }]
  return <section className="panel content-card quick-card"><SectionTitle title="Quick actions" />{actions.map(({ title, description, icon: Icon, target, tone }) => <button key={title} className="quick-action" onClick={() => onNavigate(target)}><span className={`quick-icon ${tone}`}><Icon size={17} /></span><span className="quick-copy"><strong>{title}</strong><small>{description}</small></span><ArrowRight size={15} className="quick-arrow" /></button>)}</section>
}

function AssistantCard({ onNavigate, metrics }: { onNavigate: (item: NavigationItem) => void; metrics?: VaultMetrics }) {
  const text = !metrics || metrics.isLocked
    ? "Your security assistant is ready. Unlock your vault to receive tailored password advice."
    : metrics.isEmpty
    ? "Your vault is empty. Add your first account to receive personalized recommendations."
    : metrics.weakCount > 0
    ? `Your security score is looking good. You have ${metrics.weakCount} weak password${metrics.weakCount === 1 ? "" : "s"} that could use attention.`
    : metrics.reusedPasswordCount > 0
    ? `You have ${metrics.affectedAccountsCount} account${metrics.affectedAccountsCount === 1 ? "" : "s"} sharing reused passwords.`
    : "Your security score is looking great. All saved passwords are strong and unique."

  return (
    <section className="assistant-card">
      <div className="assistant-top">
        <div className="assistant-mark"><Sparkles size={17} /></div>
        <span>VAULTGUARD ASSISTANT</span>
        <span className="assistant-live"><i /> READY</span>
      </div>
      <p>{text}</p>
      <button onClick={() => onNavigate("Security Assistant")}>
        View recommendations <ArrowRight size={14} />
      </button>
      <div className="assistant-glow" aria-hidden="true" />
    </section>
  )
}

export function VaultGuardDashboard() {
  const { user, isAuthenticated, isDemoMode, logout, enterDemoMode } = useAuth()
  const { lockVault, items: decryptedItems, keyState } = useVault()

  const [active, setActive] = useState<NavigationItem>("Overview")
  const [mobileOpen, setMobileOpen] = useState(false)
  const [vaultSearch, setVaultSearch] = useState("")

  const navigate = (item: NavigationItem) => setActive(item)

  useEffect(() => {
    const openNavigation = () => setMobileOpen(true)
    const goToPage = (event: Event) => {
      const target = (event as CustomEvent<NavigationItem>).detail
      navigate(target ?? "Password Analyzer")
    }
    window.addEventListener("vaultguard:open-nav", openNavigation)
    window.addEventListener("vaultguard:navigate", goToPage)
    return () => {
      window.removeEventListener("vaultguard:open-nav", openNavigation)
      window.removeEventListener("vaultguard:navigate", goToPage)
    }
  }, [])

  const isSynced = isAuthenticated
  const userName = user?.email ? user.email.split("@")[0] : "Alex Morgan"
  const userEmail = user?.email || "alex.morgan@example.com"
  const userInitials = user?.email ? user.email.substring(0, 2).toUpperCase() : "AM"

  // Dynamically calculate metrics strictly from decrypted vault items in VaultContext
  const metrics = useMemo<VaultMetrics>(() => {
    if (isSynced) {
      if (keyState !== "unlocked") {
        return getLockedVaultMetrics()
      }
      return computeVaultMetrics(decryptedItems)
    } else {
      // Demo mode fallback using demoVaultEntries mapped to demo secrets
      return computeVaultMetrics(
        demoVaultEntries.map(e => ({
          id: e.id,
          service: e.service,
          username: e.username,
          password: e.demoSecret,
          category: e.category,
          health: e.health,
          favorite: e.favorite,
          notes: e.notes,
          createdAt: "",
          updatedAt: ""
        }))
      )
    }
  }, [isSynced, keyState, decryptedItems])

  if (!isAuthenticated && !isDemoMode) {
    return <AuthPortal onEnterDemo={enterDemoMode} />
  }

  const handleSignOut = async () => {
    lockVault()
    await logout()
    setActive("Overview")
  }

  return (
    <div className="app-shell">
      <Sidebar
        active={active}
        onNavigate={navigate}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
        userName={userName}
        userInitials={userInitials}
        isSynced={isSynced}
        weakCount={metrics.weakCount}
      />
      <main className="main-area">
        <Header
          active={active}
          onNavigate={navigate}
          onSearch={query => { setVaultSearch(query); navigate("Secure Vault") }}
          onSignOut={handleSignOut}
          userName={userName}
          userEmail={userEmail}
          userInitials={userInitials}
          isSynced={isSynced}
        />
        <div className="mobile-bottom-nav">
          <button onClick={() => setMobileOpen(true)}><Menu size={17} /><span>Menu</span></button>
          <button className={active === "Overview" ? "selected" : ""} onClick={() => navigate("Overview")}><LayoutDashboard size={17} /><span>Overview</span></button>
          <button onClick={() => navigate("Secure Vault")}><FolderKey size={17} /><span>Vault</span></button>
          <button onClick={() => navigate("Settings")}><Settings size={17} /><span>Settings</span></button>
        </div>
        <div hidden={active !== "Overview"}>
          <div className="dashboard-content">
            <div className="welcome-row">
              <div>
                <div className="welcome-kicker">
                  {isSynced ? "AUTHENTICATED WORKSPACE" : "DEMO WORKSPACE"} <span>·</span> ZERO-KNOWLEDGE
                </div>
                <h1>Good day, {userName}<span className="welcome-period">.</span></h1>
                <p>
                  {isSynced
                    ? "Your vault is protected with client-side AES-256-GCM authenticated encryption."
                    : "Your digital security, at a glance. Sample metrics for this frontend demo."}
                </p>
              </div>
              <div className="welcome-actions">
                <SecurityStatusIndicator />
                <SecurityScan onRecommendations={() => navigate("Security Assistant")} metrics={metrics} />
              </div>
            </div>
            <div className="dashboard-grid">
              <div className="dashboard-primary">
                <SecurityCore onReport={() => navigate("Password Analyzer")} metrics={metrics} />
                <MetricCards metrics={metrics} />
                <div className="command-viz-grid">
                  <SecurityNetwork metrics={metrics} />
                  <ThreatRadar metrics={metrics} />
                </div>
                <div className="lower-grid">
                  <HealthCard metrics={metrics} />
                  <ActivityCard />
                </div>
              </div>
              <aside className="dashboard-aside">
                <QuickActions onNavigate={navigate} />
                <AssistantCard onNavigate={navigate} metrics={metrics} />
                <div className="privacy-note">
                  <span><LockKeyhole size={14} /></span>
                  <p>
                    <strong>{isSynced ? "Cloud sync connected" : "Frontend demo"}</strong><br />
                    {isSynced
                      ? "Incremental sync active every 30s."
                      : "No accounts or cloud sync are connected."}
                  </p>
                </div>
              </aside>
            </div>
            <footer className="dashboard-footer">
              <span><Shield size={13} /> VaultGuard keeps your digital life protected.</span>
              <button onClick={() => navigate("Settings")}>Privacy & security <ArrowRight size={12} /></button>
            </footer>
          </div>
        </div>
        <div hidden={active !== "Password Analyzer"}><AnalyzerPage /></div>
        <div hidden={active !== "Password Generator"}><GeneratorPage onNavigate={navigate} /></div>
        <div hidden={active !== "Secure Vault"}><VaultPage initialSearch={vaultSearch} /></div>
        <div hidden={active !== "Security Assistant"}><AssistantPage /></div>
        <div hidden={active !== "Settings"}><SettingsPage /></div>
      </main>
    </div>
  )
}
