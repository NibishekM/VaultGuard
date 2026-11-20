'use client'

import { useEffect, useMemo, useState, type FormEvent } from "react"
import { ArrowRight, Check, ChevronDown, Copy, Download, Edit3, Eye, EyeOff, FileKey2, Heart, KeyRound, LockKeyhole, Plus, RotateCw, Search, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, Trash2, Upload, WandSparkles, X } from "lucide-react"
import { localDemoService, type VaultCategory, type VaultEntry } from "@/lib/vaultguard-service"
import { useVault } from "@/lib/crypto/vault-context"
import { useAuth } from "@/lib/auth/auth-context"
import type { DecryptedVaultItem } from "@/lib/crypto/types"
import { copyToClipboardWithAutoClear } from "@/lib/clipboard"
import { analyzePassword, generateRandomPassword } from "@/lib/password-tools"
import { validateVaultBackup, triggerBackupDownload, type VaultBackupFile } from "@/lib/crypto/export-import"

const categories: Array<"All" | VaultCategory> = ["All", "Personal", "Work", "Finance", "Social"]

interface UnifiedEntry {
  id: string
  service: string
  username: string
  secret: string
  category: VaultCategory
  health: "Strong" | "Moderate" | "Weak"
  favorite: boolean
  notes: string
  isEncrypted: boolean
}

function EntryEditor({
  entry,
  isEncryptedMode,
  onSave,
  onCancel
}: {
  entry?: UnifiedEntry
  isEncryptedMode: boolean
  onSave: (entry: { service: string; username: string; secret: string; category: VaultCategory; notes: string }) => void
  onCancel: () => void
}) {
  const [service, setService] = useState(entry?.service ?? "")
  const [username, setUsername] = useState(entry?.username ?? "")
  const [secret, setSecret] = useState(entry?.secret ?? "")
  const [secretVisible, setSecretVisible] = useState(false)
  const [category, setCategory] = useState<VaultCategory>(entry?.category ?? "Personal")
  const [notes, setNotes] = useState(entry?.notes ?? "")
  const [error, setError] = useState("")

  // Inline Password Generator State
  const [showGenerator, setShowGenerator] = useState(false)
  const [genLength, setGenLength] = useState(20)
  const [genOptions, setGenOptions] = useState({ upper: true, lower: true, numbers: true, symbols: true })
  const [genPassword, setGenPassword] = useState("")
  const [genVisible, setGenVisible] = useState(true)
  const [genCopied, setGenCopied] = useState(false)
  const [genMessage, setGenMessage] = useState("")

  const genReport = useMemo(() => {
    return genPassword ? analyzePassword(genPassword) : null
  }, [genPassword])

  const generateCandidate = (customLength?: number, customOpts?: typeof genOptions) => {
    try {
      const len = customLength ?? genLength
      const opts = customOpts ?? genOptions
      const pwd = generateRandomPassword(len, opts)
      setGenPassword(pwd)
      setGenCopied(false)
      setGenMessage("")
    } catch (err) {
      setGenMessage(err instanceof Error ? err.message : "Failed to generate password")
    }
  }

  const handleToggleGenerator = () => {
    const nextShow = !showGenerator
    setShowGenerator(nextShow)
    if (nextShow && !genPassword) {
      generateCandidate()
    }
  }

  const handleApplyCandidate = () => {
    if (genPassword) {
      setSecret(genPassword)
      setShowGenerator(false)
      setError("")
    }
  }

  const handleCopyCandidate = async () => {
    if (!genPassword) return
    const res = await copyToClipboardWithAutoClear(genPassword)
    if (res.success) {
      setGenCopied(true)
      setGenMessage(res.message)
      setTimeout(() => setGenCopied(false), 2000)
    } else {
      setGenMessage(res.message)
    }
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!service.trim() || !username.trim()) {
      setError("Service and username are required.")
      return
    }
    onSave({
      service: service.trim(),
      username: username.trim(),
      secret: secret.trim(),
      category,
      notes: notes.trim()
    })
  }

  return (
    <div className="dialog-backdrop" role="presentation" onMouseDown={event => { if (event.target === event.currentTarget) onCancel() }}>
      <section className="demo-dialog" role="dialog" aria-modal="true" aria-labelledby="entry-dialog-title">
        <div className="dialog-header">
          <div>
            <span className="eyebrow">{isEncryptedMode ? "AES-256-GCM · CLIENT ENCRYPTED" : "DEMO DATA · IN-MEMORY ONLY"}</span>
            <h2 id="entry-dialog-title">{entry ? (isEncryptedMode ? "Edit encrypted entry" : "Edit demo entry") : (isEncryptedMode ? "Add encrypted entry" : "Add a demo entry")}</h2>
          </div>
          <button className="icon-button" onClick={onCancel} aria-label="Close dialog"><X size={18} /></button>
        </div>
        <form onSubmit={submit} className="entry-form">
          <label>Website or service
            <input value={service} onChange={event => setService(event.target.value)} placeholder="e.g. ProtonMail" />
          </label>
          <label>Username
            <input value={username} onChange={event => setUsername(event.target.value)} placeholder="user@example.test" />
          </label>
          <div className="entry-field-group">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
              <label htmlFor="entry-secret-input" style={{ margin: 0, color: "#b8c5cc", fontSize: "10px", fontWeight: 500 }}>
                {isEncryptedMode ? "Password (encrypted with AES-256-GCM)" : "Demo password"}
              </label>
              <button
                type="button"
                className="text-button"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "4px",
                  fontSize: "10px",
                  color: showGenerator ? "#58cad5" : "#36d6e8",
                  cursor: "pointer",
                  background: "transparent",
                  border: 0,
                  padding: "2px 4px"
                }}
                onClick={handleToggleGenerator}
                aria-expanded={showGenerator}
              >
                <WandSparkles size={12} />
                {showGenerator ? "Hide generator" : "Generate password"}
              </button>
            </div>
            <div className="tool-input password-input">
              <input
                id="entry-secret-input"
                type={secretVisible ? "text" : "password"}
                autoComplete="off"
                value={secret}
                onChange={event => setSecret(event.target.value)}
                placeholder={entry ? "Leave blank to keep current value" : (isEncryptedMode ? "Enter password to encrypt" : "Use sample text only")}
              />
              <button
                type="button"
                aria-label={secretVisible ? "Hide password" : "Show password"}
                onClick={() => setSecretVisible(!secretVisible)}
              >
                {secretVisible ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <small style={{ color: "#d5b277", fontSize: "9px", lineHeight: "1.5", marginTop: "4px", display: "block" }}>
              {isEncryptedMode ? "Payload is encrypted in-memory and stored as ciphertext in IndexedDB." : "Never enter a real password. This value remains only in temporary page memory."}
            </small>

            {showGenerator && (
              <div
                className="inline-generator-panel"
                data-testid="inline-generator-panel"
                style={{
                  marginTop: "10px",
                  padding: "12px",
                  background: "#0d1720",
                  border: "1px solid #283e4c",
                  borderRadius: "10px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px"
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                    <WandSparkles size={13} style={{ color: "#36D6E8" }} />
                    <span style={{ fontSize: "11px", fontWeight: 600, color: "#e8f0f5" }}>Password Generator</span>
                  </div>
                  <span className="local-only-pill" style={{ fontSize: "8px", padding: "2px 6px" }}>
                    <LockKeyhole size={10} /> SECURE CLIENT-SIDE
                  </span>
                </div>

                {/* Candidate password row */}
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    padding: "6px 8px",
                    borderRadius: "8px",
                    background: "#080e14",
                    border: "1px solid #233541"
                  }}
                >
                  <input
                    type={genVisible ? "text" : "password"}
                    readOnly
                    value={genPassword}
                    aria-label="Generated password preview"
                    placeholder="Generating password..."
                    style={{
                      flex: 1,
                      minWidth: 0,
                      background: "transparent",
                      border: 0,
                      outline: 0,
                      color: "#36D6E8",
                      fontFamily: "monospace",
                      fontSize: "12px",
                      letterSpacing: genVisible ? "0.5px" : "2px"
                    }}
                  />
                  <button
                    type="button"
                    title={genVisible ? "Hide candidate" : "Show candidate"}
                    aria-label={genVisible ? "Hide candidate" : "Show candidate"}
                    style={{
                      background: "transparent",
                      border: 0,
                      color: "#83939d",
                      cursor: "pointer",
                      padding: "4px",
                      display: "grid",
                      placeItems: "center"
                    }}
                    onClick={() => setGenVisible(!genVisible)}
                  >
                    {genVisible ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                  <button
                    type="button"
                    title="Regenerate password"
                    aria-label="Regenerate password"
                    style={{
                      background: "transparent",
                      border: 0,
                      color: "#83939d",
                      cursor: "pointer",
                      padding: "4px",
                      display: "grid",
                      placeItems: "center"
                    }}
                    onClick={() => generateCandidate()}
                  >
                    <RotateCw size={15} />
                  </button>
                  <button
                    type="button"
                    title="Copy candidate with 30s auto-clear"
                    aria-label="Copy candidate password"
                    style={{
                      background: "transparent",
                      border: 0,
                      color: genCopied ? "#45d6a0" : "#83939d",
                      cursor: "pointer",
                      padding: "4px",
                      display: "grid",
                      placeItems: "center"
                    }}
                    onClick={handleCopyCandidate}
                  >
                    {genCopied ? <Check size={15} /> : <Copy size={15} />}
                  </button>
                </div>

                {/* Strength meter */}
                {genReport && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "9px" }}>
                      <span style={{ color: "#85959e" }}>
                        Strength: <strong className={`strength-${genReport.level.toLowerCase().replace(" ", "-")}`}>{genReport.score}/100 · {genReport.level}</strong>
                      </span>
                      <span style={{ color: "#72848f" }}>{genLength} chars</span>
                    </div>
                    <div style={{ height: "4px", background: "#1c2b35", borderRadius: "2px", overflow: "hidden" }}>
                      <div
                        className={`meter-fill strength-${genReport.level.toLowerCase().replace(" ", "-")}`}
                        style={{ width: `${genReport.score}%`, height: "100%", transition: "width 0.2s" }}
                      />
                    </div>
                  </div>
                )}

                {/* Length slider */}
                <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "10px", color: "#a0afb8" }}>
                    <label htmlFor="inline-generator-length" style={{ margin: 0, color: "inherit", fontSize: "inherit", cursor: "pointer" }}>Length</label>
                    <strong style={{ color: "#e8f0f5" }}>{genLength} characters</strong>
                  </div>
                  <input
                    id="inline-generator-length"
                    type="range"
                    aria-label="Password length"
                    min={8}
                    max={48}
                    value={genLength}
                    style={{ accentColor: "#36D6E8", cursor: "pointer", height: "4px" }}
                    onChange={e => {
                      const len = Number(e.target.value)
                      setGenLength(len)
                      generateCandidate(len)
                    }}
                  />
                  <div style={{ display: "flex", justifyContent: "space-between", color: "#687a85", fontSize: "8px" }}>
                    <span>8</span>
                    <span>48</span>
                  </div>
                </div>

                {/* Character sets */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
                  {[
                    { key: "upper" as const, label: "Uppercase", hint: "A-Z" },
                    { key: "lower" as const, label: "Lowercase", hint: "a-z" },
                    { key: "numbers" as const, label: "Numbers", hint: "0-9" },
                    { key: "symbols" as const, label: "Symbols", hint: "!@#" }
                  ].map(({ key, label, hint }) => (
                    <label
                      key={key}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "6px",
                        fontSize: "9px",
                        color: "#9db0b9",
                        cursor: "pointer",
                        background: "#101b24",
                        padding: "5px 8px",
                        borderRadius: "6px",
                        border: "1px solid #233440"
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={genOptions[key]}
                        style={{ accentColor: "#36D6E8", width: "13px", height: "13px" }}
                        onChange={e => {
                          const nextOpts = { ...genOptions, [key]: e.target.checked }
                          if (!nextOpts.upper && !nextOpts.lower && !nextOpts.numbers && !nextOpts.symbols) {
                            return
                          }
                          setGenOptions(nextOpts)
                          generateCandidate(genLength, nextOpts)
                        }}
                      />
                      <span><strong>{label}</strong> <span style={{ color: "#6b7d87" }}>{hint}</span></span>
                    </label>
                  ))}
                </div>

                {/* Message / status */}
                {genMessage && (
                  <div style={{ fontSize: "9px", color: genCopied ? "#45d6a0" : "#e97474" }}>
                    {genMessage}
                  </div>
                )}

                {/* Action buttons */}
                <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px", marginTop: "2px" }}>
                  <button
                    type="button"
                    className="secondary-action"
                    style={{ minHeight: "28px", padding: "0 10px", fontSize: "9px" }}
                    onClick={() => setShowGenerator(false)}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    className="primary-action"
                    style={{ minHeight: "28px", padding: "0 10px", fontSize: "9px" }}
                    onClick={handleApplyCandidate}
                  >
                    <Check size={12} />
                    Use Password
                  </button>
                </div>
              </div>
            )}
          </div>
          <label>Category
            <select value={category} onChange={event => setCategory(event.target.value as VaultCategory)}>
              {categories.slice(1).map(item => <option key={item}>{item}</option>)}
            </select>
          </label>
          <label>Notes
            <textarea rows={3} value={notes} onChange={event => setNotes(event.target.value)} placeholder="Optional note" />
          </label>
          {error && <div className="form-error" role="alert">{error}</div>}
          <div className="dialog-actions">
            <button type="button" className="secondary-action" onClick={onCancel}>Cancel</button>
            <button type="submit" className="primary-action"><Check size={15} />{entry ? "Update entry" : (isEncryptedMode ? "Encrypt & save" : "Add demo entry")}</button>
          </div>
        </form>
      </section>
    </div>
  )
}

export function VaultPage({ initialSearch = "" }: { initialSearch?: string }) {
  const {
    keyState,
    items: encryptedItems,
    isInitialized,
    unlockVault,
    initializeVault,
    lockVault,
    addItem,
    updateItem,
    deleteItem,
    exportVault,
    importVault,
    error: vaultContextError
  } = useVault()

  const { isAuthenticated, isDemoMode, user } = useAuth()
  const [vaultMode, setVaultMode] = useState<"encrypted" | "demo">(isDemoMode ? "demo" : "encrypted")

  useEffect(() => {
    if (isAuthenticated) {
      setVaultMode("encrypted")
    } else if (isDemoMode) {
      setVaultMode("demo")
    }
  }, [isAuthenticated, isDemoMode])
  const [demoEntries, setDemoEntries] = useState<VaultEntry[]>(() => localDemoService.listVaultEntries())
  const [selectedCategory, setSelectedCategory] = useState<"All" | VaultCategory>("All")
  const [search, setSearch] = useState("")
  const [sort, setSort] = useState("name")
  const [favoritesOnly, setFavoritesOnly] = useState(false)
  const [revealed, setRevealed] = useState<string[]>([])
  const [dialog, setDialog] = useState<{ mode: "add" } | { mode: "edit"; entry: UnifiedEntry } | null>(null)
  const [deleting, setDeleting] = useState<UnifiedEntry | null>(null)
  const [feedback, setFeedback] = useState("")

  // Encrypted Vault Backup Import / Export State
  const [isImportOpen, setIsImportOpen] = useState(false)
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importJson, setImportJson] = useState("")
  const [importPreview, setImportPreview] = useState<VaultBackupFile["vaultguardBackup"] | null>(null)
  const [importStrategy, setImportStrategy] = useState<"error" | "skip">("skip")
  const [importLoading, setImportLoading] = useState(false)
  const [importError, setImportError] = useState("")

  // Automatically dismiss open dialogs (Add/Edit entry, Delete confirmation, Import modal)
  // when the vault transitions away from the unlocked state or authentication resets
  // (handles manual lock, inactivity auto-lock, logout, session expiration, and account switching)
  useEffect(() => {
    if (vaultMode === "encrypted" && (keyState !== "unlocked" || !isAuthenticated)) {
      if (dialog !== null) {
        setDialog(null)
      }
      if (deleting !== null) {
        setDeleting(null)
      }
      if (isImportOpen) {
        setIsImportOpen(false)
        setImportFile(null)
        setImportJson("")
        setImportPreview(null)
        setImportError("")
      }
    }
  }, [vaultMode, keyState, isAuthenticated, user?.id, dialog, deleting, isImportOpen])

  // Master password unlock inline form state
  const [unlockPassword, setUnlockPassword] = useState("")
  const [unlockError, setUnlockError] = useState("")

  useEffect(() => setSearch(initialSearch), [initialSearch])

  // Map active items depending on current mode
  const currentEntries: UnifiedEntry[] = useMemo(() => {
    if (vaultMode === "encrypted") {
      if (keyState !== "unlocked") return []
      return encryptedItems.map(item => ({
        id: item.id,
        service: item.service,
        username: item.username,
        secret: item.password || "",
        category: item.category,
        health: item.health,
        favorite: item.favorite,
        notes: item.notes,
        isEncrypted: true
      }))
    } else {
      return demoEntries.map(entry => ({
        id: entry.id,
        service: entry.service,
        username: entry.username,
        secret: entry.demoSecret,
        category: entry.category,
        health: entry.health,
        favorite: entry.favorite,
        notes: entry.notes,
        isEncrypted: false
      }))
    }
  }, [vaultMode, keyState, encryptedItems, demoEntries])

  const filtered = useMemo(() => {
    return currentEntries
      .filter(entry => (selectedCategory === "All" || entry.category === selectedCategory) && (!favoritesOnly || entry.favorite) && `${entry.service} ${entry.username} ${entry.category}`.toLowerCase().includes(search.toLowerCase()))
      .sort((a, b) => sort === "health" ? a.health.localeCompare(b.health) : sort === "category" ? a.category.localeCompare(b.category) : a.service.localeCompare(b.service))
  }, [currentEntries, selectedCategory, favoritesOnly, search, sort])

  const handleUnlockSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setUnlockError("")
    if (unlockPassword.length < 8) {
      setUnlockError("Master password must be at least 8 characters.")
      return
    }

    if (!isInitialized) {
      const ok = await initializeVault(unlockPassword)
      if (ok) {
        setUnlockPassword("")
        setFeedback("Local vault initialized with PBKDF2 (600,000 iterations).")
      } else {
        setUnlockError(vaultContextError || "Failed to initialize vault.")
      }
    } else {
      const ok = await unlockVault(unlockPassword)
      if (ok) {
        setUnlockPassword("")
        setFeedback("Vault unlocked successfully with AES-256-GCM key.")
      } else {
        setUnlockError(vaultContextError || "Incorrect master password.")
      }
    }
  }

  const handleSaveEntry = async (data: { service: string; username: string; secret: string; category: VaultCategory; notes: string }) => {
    try {
      if (vaultMode === "encrypted") {
        if (dialog?.mode === "edit") {
          const original = encryptedItems.find(i => i.id === dialog.entry.id)
          if (original) {
            await updateItem({
              ...original,
              service: data.service,
              username: data.username,
              password: data.secret || original.password,
              category: data.category,
              notes: data.notes
            })
            setFeedback("Encrypted vault entry updated.")
          }
        } else {
          await addItem({
            service: data.service,
            username: data.username,
            password: data.secret,
            category: data.category,
            health: data.secret.length >= 14 ? "Strong" : data.secret.length >= 8 ? "Moderate" : "Weak",
            favorite: false,
            notes: data.notes
          })
          setFeedback("Encrypted vault entry saved to IndexedDB.")
        }
      } else {
        // Demo mode update
        if (dialog?.mode === "edit") {
          setDemoEntries(prev => prev.map(item => item.id === dialog.entry.id ? {
            ...item,
            service: data.service,
            username: data.username,
            category: data.category,
            notes: data.notes,
            demoSecret: data.secret || item.demoSecret
          } : item))
          setFeedback("Demo entry updated in temporary page memory.")
        } else {
          const newEntry: VaultEntry = {
            id: `demo-${crypto.randomUUID()}`,
            service: data.service,
            username: data.username,
            category: data.category,
            health: "Strong",
            favorite: false,
            notes: data.notes,
            demoSecret: data.secret || "DEMO-ONLY · NOT A REAL PASSWORD"
          }
          setDemoEntries(prev => [newEntry, ...prev])
          setFeedback("Demo entry added to temporary page memory.")
        }
      }
      setDialog(null)
    } catch (err: any) {
      setFeedback(`Error saving entry: ${err?.message || "Unknown error"}`)
    }
  }

  const handleDeleteEntry = async () => {
    if (!deleting) return
    try {
      if (deleting.isEncrypted) {
        await deleteItem(deleting.id)
        setFeedback("Encrypted entry removed from local storage.")
      } else {
        setDemoEntries(prev => prev.filter(item => item.id !== deleting.id))
        setFeedback("Demo entry removed from page memory.")
      }
      setDeleting(null)
    } catch (err: any) {
      setFeedback(`Failed to delete entry: ${err?.message || "Unknown error"}`)
    }
  }

  const toggleReveal = (id: string) => {
    setRevealed(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id])
  }

  const copyValue = async (value: string, label: string) => {
    if (label.toLowerCase().includes("password") || label.toLowerCase().includes("secret")) {
      const res = await copyToClipboardWithAutoClear(value)
      setFeedback(res.message)
    } else {
      try {
        await navigator.clipboard.writeText(value)
        setFeedback(`${label} copied to clipboard.`)
      } catch {
        setFeedback("Clipboard access is unavailable. Select the text to copy manually.")
      }
    }
  }

  const handleExport = async () => {
    try {
      const res = await exportVault()
      triggerBackupDownload(res.backup, res.filename)
      setFeedback(`Exported ${res.recordCount} encrypted records to ${res.filename}.`)
    } catch (err: any) {
      setFeedback(`Export failed: ${err?.message || "Unknown error"}`)
    }
  }

  const handleImportFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImportError("")
    setImportPreview(null)
    setImportJson("")
    setImportFile(file)

    if (file.size > 5 * 1024 * 1024) {
      setImportError("File exceeds maximum allowed size of 5 MiB.")
      return
    }

    try {
      const text = await file.text()
      const validation = validateVaultBackup(text)
      if (!validation.success || !validation.data) {
        setImportError(validation.error || "Invalid backup file structure.")
        return
      }
      setImportJson(text)
      setImportPreview(validation.data.vaultguardBackup)
    } catch (err: any) {
      setImportError(`Failed to read backup file: ${err?.message || "Unknown error"}`)
    }
  }

  const handleConfirmImport = async () => {
    if (!importJson) {
      setImportError("Please select a valid VaultGuard backup file first.")
      return
    }
    setImportLoading(true)
    setImportError("")
    try {
      const res = await importVault(importJson, importStrategy)
      if (res.totalProcessed === 0) {
        setFeedback("Backup verified: file contains 0 entries. No changes made to your vault.")
      } else {
        setFeedback(`Successfully imported ${res.insertedCount} records (${res.skippedCount} skipped).`)
      }
      setIsImportOpen(false)
      setImportFile(null)
      setImportJson("")
      setImportPreview(null)
    } catch (err: any) {
      setImportError(err?.message || "Failed to import vault backup.")
    } finally {
      setImportLoading(false)
    }
  }

  return (
    <div className="feature-page">
      <div className="vault-heading-row">
        <div className="feature-heading">
          <div className="feature-heading-icon"><FileKey2 size={19} /></div>
          <div>
            <span className="eyebrow">PERSONAL CREDENTIAL LIBRARY</span>
            <h1>Secure vault</h1>
            <p>{vaultMode === "encrypted" ? (keyState === "unlocked" ? "Client-side zero-knowledge encrypted vault (AES-256-GCM)." : "Encrypted local vault is locked.") : "Browse fictional sample records. Changes last only in this page session."}</p>
          </div>
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          {vaultMode === "encrypted" && keyState === "unlocked" && (
            <>
              <button
                type="button"
                className="secondary-action"
                onClick={handleExport}
                title="Export encrypted vault backup (JSON)"
              >
                <Download size={14} /> Export
              </button>
              <button
                type="button"
                className="secondary-action"
                onClick={() => {
                  setImportError("")
                  setImportFile(null)
                  setImportJson("")
                  setImportPreview(null)
                  setIsImportOpen(true)
                }}
                title="Import encrypted vault backup"
              >
                <Upload size={14} /> Import
              </button>
              <button type="button" className="secondary-action" onClick={lockVault}>
                <LockKeyhole size={14} /> Lock vault
              </button>
            </>
          )}
          <button
            className="primary-action"
            onClick={() => {
              if (vaultMode === "encrypted" && keyState !== "unlocked") {
                setFeedback("Please unlock your encrypted vault first.")
                return
              }
              setDialog({ mode: "add" })
            }}
          >
            <Plus size={16} /> {vaultMode === "encrypted" ? "Add encrypted entry" : "Add demo entry"}
          </button>
        </div>
      </div>

      {/* Mode Switcher Tabs */}
      <div style={{ display: "flex", gap: "10px", marginBottom: "14px", alignItems: "center" }}>
        <button
          className={`auth-tab ${vaultMode === "encrypted" ? "active" : ""}`}
          style={{ padding: "8px 16px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.1)" }}
          onClick={() => setVaultMode("encrypted")}
        >
          <LockKeyhole size={14} style={{ display: "inline", marginRight: "6px" }} />
          Encrypted Vault (Zero-Knowledge)
        </button>
        <button
          className={`auth-tab ${vaultMode === "demo" ? "active" : ""}`}
          style={{ padding: "8px 16px", borderRadius: "8px", border: "1px solid rgba(255,255,255,0.1)" }}
          onClick={() => setVaultMode("demo")}
        >
          Sample Demo Data (24 Records)
        </button>
      </div>

      {vaultMode === "encrypted" ? (
        <div className="demo-warning" style={{ borderColor: keyState === "unlocked" ? "rgba(69,214,160,0.3)" : "rgba(146,117,245,0.3)" }}>
          <ShieldCheck size={16} color={keyState === "unlocked" ? "#45D6A0" : "#9275F5"} />
          <span>
            <strong>Zero-Knowledge Cryptographic Vault:</strong> Encrypted client-side with AES-256-GCM. Master password derives a 256-bit key via PBKDF2 (600,000 iterations, SHA-256) and is never transmitted.
          </span>
          <span className="demo-badge">{keyState === "unlocked" ? "VAULT UNLOCKED" : "VAULT LOCKED"}</span>
        </div>
      ) : (
        <div className="demo-warning">
          <AlertTriangleIcon />
          <span><strong>Demo vault—not encrypted storage.</strong> These records and edits exist only in this browser page. Never enter real credentials.</span>
          <span className="demo-badge">SAMPLE DATA</span>
        </div>
      )}

      {/* Locked Vault Prompt in Encrypted Mode */}
      {vaultMode === "encrypted" && keyState !== "unlocked" && (
        <section className="panel content-card" style={{ padding: "32px", textAlign: "center", marginBottom: "20px" }}>
          <div style={{ display: "inline-flex", padding: "14px", borderRadius: "50%", background: "rgba(146,117,245,0.12)", marginBottom: "16px" }}>
            <LockKeyhole size={36} color="#9275F5" />
          </div>
          <h2 style={{ fontSize: "20px", fontWeight: "600", marginBottom: "8px" }}>
            {isInitialized ? "Unlock your encrypted vault" : "Initialize your encrypted vault"}
          </h2>
          <p style={{ color: "rgba(255,255,255,0.6)", fontSize: "14px", maxWidth: "480px", margin: "0 auto 20px" }}>
            {isInitialized
              ? "Your vault is protected with client-side AES-256-GCM encryption. Enter your master password to derive the key in memory."
              : "Set a master password to initialize your zero-knowledge vault. A 16-byte random salt will be generated and saved locally."}
          </p>

          <form onSubmit={handleUnlockSubmit} style={{ maxWidth: "360px", margin: "0 auto", display: "flex", flexDirection: "column", gap: "12px" }}>
            <input
              type="password"
              placeholder={isInitialized ? "Enter master password" : "Create master password (min 8 chars)"}
              value={unlockPassword}
              onChange={e => setUnlockPassword(e.target.value)}
              style={{
                width: "100%",
                padding: "10px 14px",
                borderRadius: "8px",
                background: "rgba(255,255,255,0.06)",
                border: "1px solid rgba(255,255,255,0.12)",
                color: "white",
                fontSize: "14px"
              }}
            />
            {unlockError && <div className="form-error" style={{ margin: "0" }}>{unlockError}</div>}
            <button type="submit" className="primary-action" style={{ width: "100%", justifyContent: "center" }}>
              <KeyRound size={15} />
              {isInitialized ? "Unlock vault" : "Initialize & unlock vault"}
            </button>
          </form>
        </section>
      )}

      {/* Summary Grid */}
      <div className="vault-summary-grid">
        <div className="vault-summary panel">
          <span className="summary-icon cyan"><KeyRound size={17} /></span>
          <div><strong>{currentEntries.length}</strong><span>{vaultMode === "encrypted" ? "encrypted entries" : "demo entries"}</span></div>
          <span className="summary-end">{vaultMode === "encrypted" ? (keyState === "unlocked" ? "IN MEMORY" : "LOCKED") : "IN MEMORY"}</span>
        </div>
        <div className="vault-summary panel">
          <span className="summary-icon green"><ShieldCheck size={17} /></span>
          <div><strong>{currentEntries.filter(entry => entry.health === "Strong").length}</strong><span>strong items</span></div>
          <span className="summary-end green-text">GOOD</span>
        </div>
        <div className="vault-summary panel">
          <span className="summary-icon amber"><ShieldAlert size={17} /></span>
          <div><strong>{currentEntries.filter(entry => entry.health === "Weak").length}</strong><span>need review</span></div>
          <span className="summary-end amber-text">REVIEW</span>
        </div>
      </div>

      {/* Main List Section */}
      <section className="panel vault-browser">
        <div className="vault-toolbar">
          <div className="vault-filter-tabs" role="tablist" aria-label="Filter vault by category">
            {categories.map(category => (
              <button
                key={category}
                role="tab"
                aria-selected={selectedCategory === category}
                className={selectedCategory === category ? "vault-filter active" : "vault-filter"}
                onClick={() => setSelectedCategory(category)}
              >
                {category}
                <span>{category === "All" ? currentEntries.length : currentEntries.filter(entry => entry.category === category).length}</span>
              </button>
            ))}
          </div>
          <div className="vault-controls">
            <label className="vault-search">
              <Search size={15} />
              <input aria-label="Search vault entries" value={search} onChange={event => setSearch(event.target.value)} placeholder="Search vault..." />
              <kbd>⌘ K</kbd>
            </label>
            <label className="sort-select">
              <span>Sort</span>
              <select aria-label="Sort vault entries" value={sort} onChange={event => setSort(event.target.value)}>
                <option value="name">Name</option>
                <option value="category">Category</option>
                <option value="health">Health</option>
              </select>
              <ChevronDown size={12} />
            </label>
          </div>
        </div>

        <div className="vault-subtoolbar">
          <span>Showing <strong>{filtered.length}</strong> of {currentEntries.length} entries</span>
          <button className={favoritesOnly ? "favorite-filter active" : "favorite-filter"} onClick={() => setFavoritesOnly(!favoritesOnly)}>
            <Heart size={14} fill={favoritesOnly ? "currentColor" : "none"} /> Favorites only
          </button>
        </div>

        {filtered.length ? (
          <div className="vault-list">
            {filtered.map((entry, index) => (
              <article className="vault-entry" key={entry.id}>
                <div className={`service-monogram monogram-${index % 6}`}>
                  {entry.service.split(/\s+/).map(word => word[0]).slice(0, 2).join("")}
                </div>
                <div className="vault-entry-main">
                  <div className="vault-entry-title">
                    <strong>{entry.service}</strong>
                    <span className={`category-tag tag-${entry.category.toLowerCase()}`}>{entry.category}</span>
                  </div>
                  <span className="vault-username">{entry.username}</span>
                  <div className="vault-secret-line">
                    <span className="secret-dots" aria-label={revealed.includes(entry.id) ? "Password shown" : "Password hidden"}>
                      {revealed.includes(entry.id) ? entry.secret : "••••••••••••••••"}
                    </span>
                    <button aria-label={revealed.includes(entry.id) ? "Hide password" : "Reveal password"} onClick={() => toggleReveal(entry.id)}>
                      {revealed.includes(entry.id) ? <EyeOff size={13} /> : <Eye size={13} />}
                    </button>
                    <button aria-label="Copy password" onClick={() => void copyValue(entry.secret, "Password")}>
                      <Copy size={13} />
                    </button>
                  </div>
                </div>
                <div className={`health-tag health-${entry.health.toLowerCase()}`}><i />{entry.health}</div>
                <button
                  className={`favorite-button ${entry.favorite ? "is-favorite" : ""}`}
                  aria-label={entry.favorite ? "Remove from favorites" : "Add to favorites"}
                  onClick={() => {
                    if (entry.isEncrypted) {
                      const item = encryptedItems.find(i => i.id === entry.id)
                      if (item) updateItem({ ...item, favorite: !item.favorite })
                    } else {
                      setDemoEntries(curr => curr.map(item => item.id === entry.id ? { ...item, favorite: !item.favorite } : item))
                    }
                  }}
                >
                  <Heart size={15} fill={entry.favorite ? "currentColor" : "none"} />
                </button>
                <div className="entry-actions">
                  <button aria-label={`Edit ${entry.service}`} onClick={() => setDialog({ mode: "edit", entry })}><Edit3 size={14} /></button>
                  <button aria-label={`Delete ${entry.service}`} onClick={() => setDeleting(entry)}><Trash2 size={14} /></button>
                </div>
              </article>
            ))}
          </div>
        ) : (
          <div className="vault-empty">
            <div className="empty-icon"><Search size={21} /></div>
            <strong>{vaultMode === "encrypted" && keyState !== "unlocked" ? "Vault is locked" : "No entries found"}</strong>
            <span>{vaultMode === "encrypted" && keyState !== "unlocked" ? "Unlock your vault above to decrypt and view records." : "Try another search or category, or add a new entry."}</span>
            <button className="secondary-action" onClick={() => { setSearch(""); setSelectedCategory("All"); setFavoritesOnly(false) }}>Clear filters</button>
          </div>
        )}

        <div className="vault-footnote">
          <LockKeyhole size={14} />
          {vaultMode === "encrypted"
            ? "Zero-knowledge encryption active. Ciphertext and 12-byte IV stored in IndexedDB. Decrypted only in page memory while unlocked."
            : "Sample records are fictional demo entries and are not encrypted or synced."}
        </div>
      </section>

      {feedback && (
        <div className="toast-message" role="status">
          {feedback}
          <button aria-label="Dismiss" onClick={() => setFeedback("")}><X size={14} /></button>
        </div>
      )}

      {dialog && (
        <EntryEditor
          entry={dialog.mode === "edit" ? dialog.entry : undefined}
          isEncryptedMode={vaultMode === "encrypted"}
          onCancel={() => setDialog(null)}
          onSave={handleSaveEntry}
        />
      )}

      {deleting && (
        <div className="dialog-backdrop">
          <section className="demo-dialog confirm-dialog" role="alertdialog" aria-modal="true">
            <span className="confirm-icon"><Trash2 size={18} /></span>
            <h2>Delete entry?</h2>
            <p>“{deleting.service}” will be permanently removed.</p>
            <div className="dialog-actions">
              <button className="secondary-action" onClick={() => setDeleting(null)}>Keep entry</button>
              <button className="danger-action" onClick={handleDeleteEntry}>Delete entry</button>
            </div>
          </section>
        </div>
      )}

      {isImportOpen && (
        <div
          className="dialog-backdrop"
          role="presentation"
          onMouseDown={e => {
            if (e.target === e.currentTarget && !importLoading) {
              setIsImportOpen(false)
            }
          }}
        >
          <section
            className="demo-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="import-dialog-title"
            style={{ maxWidth: "480px" }}
          >
            <div className="dialog-header">
              <div>
                <span className="eyebrow">AES-256-GCM · ZERO-KNOWLEDGE RESTORATION</span>
                <h2 id="import-dialog-title">Import encrypted vault</h2>
              </div>
              <button
                className="icon-button"
                disabled={importLoading}
                onClick={() => setIsImportOpen(false)}
                aria-label="Close dialog"
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "16px 0 8px" }}>
              <p style={{ margin: 0, fontSize: "12px", color: "#8f9da7", lineHeight: "1.6" }}>
                Restore credentials from a VaultGuard encrypted JSON backup. All records will be verified with your active encryption key before being saved.
              </p>

              <div
                style={{
                  display: "flex",
                  gap: "8px",
                  padding: "10px 12px",
                  borderRadius: "8px",
                  background: "#111b24",
                  border: "1px solid #233440",
                  fontSize: "11px",
                  color: "#8ca0ac",
                  lineHeight: "1.5"
                }}
              >
                <ShieldAlert size={16} color="#36D6E8" style={{ flexShrink: 0, marginTop: "2px" }} />
                <span>
                  <strong style={{ color: "#dce6eb" }}>Backup Policy:</strong> Backups contain active encrypted vault entries only. Deleted-entry history (tombstones) is not preserved. Importing a backup will not resurrect previously soft-deleted server records.
                </span>
              </div>

              <label
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "8px",
                  fontSize: "11px",
                  color: "#b8c5cc"
                }}
              >
                Select encrypted backup file (.json)
                <input
                  type="file"
                  accept=".json,application/json"
                  disabled={importLoading}
                  onChange={handleImportFileSelect}
                  style={{
                    padding: "10px",
                    borderRadius: "8px",
                    background: "#080e14",
                    border: "1px solid #233541",
                    color: "#e8f0f5",
                    fontSize: "12px",
                    cursor: "pointer"
                  }}
                />
              </label>

              {importPreview && (
                <div
                  style={{
                    padding: "12px 14px",
                    borderRadius: "8px",
                    background: "#0c151c",
                    border: "1px solid #283a46",
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                    fontSize: "11px"
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "#7f9099" }}>Backup Format:</span>
                    <strong style={{ color: "#36d6e8" }}>{importPreview.formatName} v{importPreview.formatVersion}</strong>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "#7f9099" }}>Records to restore:</span>
                    <strong style={{ color: "#e8f0f5" }}>{importPreview.recordCount} items</strong>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "#7f9099" }}>Created date:</span>
                    <span style={{ color: "#a0afb8" }}>{new Date(importPreview.createdAt).toLocaleString()}</span>
                  </div>
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <span style={{ color: "#7f9099" }}>PBKDF2 Iterations:</span>
                    <span style={{ color: "#a0afb8" }}>{importPreview.kdfMetadata.vaultKdfParameters.iterations.toLocaleString()}</span>
                  </div>
                </div>
              )}

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label htmlFor="import-strategy" style={{ fontSize: "11px", color: "#b8c5cc" }}>
                  Duplicate / conflict resolution
                </label>
                <select
                  id="import-strategy"
                  value={importStrategy}
                  disabled={importLoading}
                  onChange={e => setImportStrategy(e.target.value as "error" | "skip")}
                  style={{
                    padding: "8px 12px",
                    borderRadius: "8px",
                    background: "#080e14",
                    border: "1px solid #233541",
                    color: "#e8f0f5",
                    fontSize: "12px"
                  }}
                >
                  <option value="skip">Skip duplicates (keep existing records)</option>
                  <option value="error">Strict (fail entire import on any conflict)</option>
                </select>
              </div>

              {importError && (
                <div className="form-error" role="alert" style={{ margin: "4px 0" }}>
                  {importError}
                </div>
              )}

              <div className="dialog-actions" style={{ marginTop: "8px" }}>
                <button
                  type="button"
                  className="secondary-action"
                  disabled={importLoading}
                  onClick={() => setIsImportOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  className="primary-action"
                  disabled={!importPreview || importLoading}
                  onClick={handleConfirmImport}
                >
                  {importLoading ? (
                    <>
                      <RotateCw size={14} className="spin" /> Restoring & Decrypting...
                    </>
                  ) : (
                    <>
                      <Upload size={14} /> Restore Encrypted Vault
                    </>
                  )}
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}

function AlertTriangleIcon() {
  return <span className="warning-symbol"><ShieldAlert size={15} /></span>
}
