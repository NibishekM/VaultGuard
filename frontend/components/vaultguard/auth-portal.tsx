'use client'

import { useState, type FormEvent } from "react"
import { ArrowRight, Eye, EyeOff, Fingerprint, KeyRound, LockKeyhole, Sparkles } from "lucide-react"
import { HolographicShield } from "@/components/vaultguard/command-center-visuals"
import { useVault } from "@/lib/crypto/vault-context"
import { useAuth } from "@/lib/auth/auth-context"

type AuthMode = "signin" | "create" | "unlock"

export function AuthPortal({ onEnterDemo }: { onEnterDemo: () => void }) {
  const { isInitialized, unlockVault, initializeVault } = useVault()
  const { login, register } = useAuth()

  const [mode, setMode] = useState<AuthMode>("signin")
  const [showPassword, setShowPassword] = useState(false)
  const [showMasterPassword, setShowMasterPassword] = useState(false)
  const [notice, setNotice] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [masterPassword, setMasterPassword] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)

  const strength = Math.min(
    100,
    (password.length >= 12 ? 35 : password.length * 2) +
      (/[A-Z]/.test(password) ? 15 : 0) +
      (/[a-z]/.test(password) ? 15 : 0) +
      (/[0-9]/.test(password) ? 15 : 0) +
      (/[^A-Za-z0-9]/.test(password) ? 20 : 0)
  )

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setNotice("")

    if (mode !== "unlock" && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setNotice("Enter a valid email address to continue.")
      return
    }

    if (mode === "unlock") {
      if (!password || password.length < 8) {
        setNotice("Enter your master password (at least 8 characters).")
        return
      }

      setIsSubmitting(true)
      try {
        if (!isInitialized) {
          const ok = await initializeVault(password)
          if (ok) {
            onEnterDemo()
          } else {
            setNotice("Failed to initialize vault with this master password.")
          }
        } else {
          const ok = await unlockVault(password)
          if (ok) {
            onEnterDemo()
          } else {
            setNotice("Incorrect master password. Authentication tag verification failed.")
          }
        }
      } finally {
        setIsSubmitting(false)
      }
      return
    }

    if (mode === "create") {
      if (password.length < 12) {
        setNotice("Account password must be at least 12 characters long.")
        return
      }
      if (!masterPassword || masterPassword.length < 8) {
        setNotice("Master password must be at least 8 characters long.")
        return
      }

      setIsSubmitting(true)
      try {
        const res = await register(email, password, masterPassword)
        if (res.success) {
          // Initialize local vault with the master password
          await initializeVault(masterPassword)
          setNotice("Account registered successfully and zero-knowledge vault initialized.")
        } else {
          setNotice(res.error || "Failed to create account.")
        }
      } catch (err: any) {
        setNotice(err?.message || "Failed to create account.")
      } finally {
        setIsSubmitting(false)
      }
      return
    }

    // Sign in mode
    if (!password) {
      setNotice("Enter your account password.")
      return
    }

    setIsSubmitting(true)
    try {
      const res = await login(email, password)
      if (res.success) {
        setNotice("Signed in successfully. Please unlock your vault.")
      } else {
        setNotice(res.error || "Invalid email or password.")
      }
    } catch (err: any) {
      setNotice(err?.message || "Authentication failed.")
    } finally {
      setIsSubmitting(false)
    }
  }

  const titles: Record<AuthMode, string> = {
    signin: "Welcome back",
    create: "Create your account",
    unlock: "Unlock your vault"
  }

  return (
    <main className="auth-screen">
      <div className="auth-top">
        <a className="brand auth-brand" href="#" aria-label="VaultGuard home">
          <span className="brand-mark">
            <HolographicShield size={23} />
          </span>
          <span>
            vault<span className="brand-light">guard</span>
          </span>
        </a>
        <span className="auth-demo-label">
          <span /> ZERO-KNOWLEDGE
        </span>
      </div>
      <div className="auth-layout">
        <section className="auth-story">
          <div className="auth-orb auth-orb-a" />
          <div className="auth-orb auth-orb-b" />
          <div className="auth-grid-lines" />
          <div className="auth-story-content">
            <div className="auth-kicker">
              <Sparkles size={14} /> A CALMER KIND OF SECURITY
            </div>
            <div className="auth-emblem">
              <div className="auth-emblem-ring">
                <HolographicShield size={62} />
              </div>
              <div className="auth-scan-line" />
            </div>
            <h1>
              Your digital life,
              <br />
              <span>under your control.</span>
            </h1>
            <p>
              One thoughtful place to check your security, build stronger habits, and keep your credentials protected with client-side AES-256-GCM encryption.
            </p>
            <div className="auth-feature-list">
              <div>
                <span>
                  <LockKeyhole size={14} />
                </span>{" "}
                Zero-knowledge encryption
              </div>
              <div>
                <span>
                  <Fingerprint size={14} />
                </span>{" "}
                Argon2id account security
              </div>
              <div>
                <span>
                  <KeyRound size={14} />
                </span>{" "}
                PBKDF2 key derivation (600,000 iter)
              </div>
            </div>
          </div>
          <div className="auth-story-footer">
            <span>VAULTGUARD / PERSONAL SECURITY</span>
            <span>PHASE 9 INTEGRATED</span>
          </div>
        </section>
        <section className="auth-form-side">
          <div className="auth-form-card">
            <div className="auth-mobile-brand">
              <span className="brand-mark">
                <HolographicShield size={21} />
              </span>
              <span>
                vault<span className="brand-light">guard</span>
              </span>
            </div>
            <div className="auth-tabs" role="tablist" aria-label="Access options">
              {(["signin", "create", "unlock"] as const).map((value) => (
                <button
                  key={value}
                  role="tab"
                  aria-selected={mode === value}
                  className={mode === value ? "auth-tab active" : "auth-tab"}
                  onClick={() => {
                    setMode(value)
                    setNotice("")
                  }}
                >
                  {value === "signin" ? "Sign in" : value === "create" ? "Create account" : "Unlock"}
                </button>
              ))}
            </div>
            <span className="auth-kicker">
              {mode === "unlock" ? "CLIENT-SIDE UNLOCK" : "ZERO-KNOWLEDGE AUTHENTICATION"}
            </span>
            <h2>{titles[mode]}</h2>
            <p className="auth-intro">
              {mode === "unlock"
                ? "Master passwords are used exclusively in browser memory to derive your AES-256 key."
                : mode === "create"
                ? "Create your account with an account password and a local master password."
                : "Sign in with your email and account password to connect to your vault."}
            </p>
            <form onSubmit={submit} className="auth-form" noValidate>
              {mode !== "unlock" && (
                <label>
                  Email address
                  <input
                    type="email"
                    autoComplete="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                  />
                </label>
              )}
              <label>
                {mode === "unlock" ? "Master password" : mode === "create" ? "Account password" : "Password"}
                <span className="password-control">
                  <input
                    type={showPassword ? "text" : "password"}
                    autoComplete={mode === "create" ? "new-password" : "current-password"}
                    placeholder={
                      mode === "unlock"
                        ? "Enter your master password"
                        : mode === "create"
                        ? "At least 12 characters"
                        : "Enter account password"
                    }
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                  <button
                    type="button"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </span>
              </label>

              {mode === "create" && (
                <>
                  <div className="auth-password-strength">
                    <span>
                      <i style={{ width: `${strength}%` }} />
                    </span>
                    <small>
                      Password strength{" "}
                      <strong>
                        {strength > 75 ? "Strong" : strength > 40 ? "Getting there" : "Add more variety"}
                      </strong>
                    </small>
                  </div>
                  <label>
                    Master password (vault encryption only)
                    <span className="password-control">
                      <input
                        type={showMasterPassword ? "text" : "password"}
                        autoComplete="new-password"
                        placeholder="At least 8 characters (never sent to server)"
                        value={masterPassword}
                        onChange={(event) => setMasterPassword(event.target.value)}
                      />
                      <button
                        type="button"
                        aria-label={showMasterPassword ? "Hide master password" : "Show master password"}
                        onClick={() => setShowMasterPassword(!showMasterPassword)}
                      >
                        {showMasterPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </span>
                    <small style={{ color: "#8E9EB5", fontSize: "11px", marginTop: "4px" }}>
                      Used strictly client-side with PBKDF2 (600,000 iterations) to derive your AES-256 vault key.
                    </small>
                  </label>
                </>
              )}

              {mode === "signin" && (
                <label className="remember-line">
                  <input type="checkbox" defaultChecked /> Remember this device
                </label>
              )}

              {notice && (
                <div className="auth-notice" role="status">
                  {notice}
                </div>
              )}

              <button className="auth-submit" type="submit" disabled={isSubmitting}>
                {isSubmitting
                  ? "Processing..."
                  : mode === "unlock"
                  ? "Unlock vault"
                  : mode === "create"
                  ? "Create secure account"
                  : "Sign in"}
                <ArrowRight size={16} />
              </button>
            </form>
            <div className="auth-or">
              <span /> OR <span />
            </div>
            <button className="demo-entry" onClick={onEnterDemo}>
              <Sparkles size={15} /> Explore in demo mode (isolated)
            </button>
            <div className="auth-safety">
              <LockKeyhole size={14} />
              <span>Zero-knowledge security: Master passwords and encryption keys never leave your browser.</span>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
