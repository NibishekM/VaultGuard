'use client'

/**
 * VaultGuard – Authentication Context & State Management (Phase 9)
 *
 * Implements real backend authentication integration:
 * - Session tracking (access token held in-memory only)
 * - Rotating refresh token lifecycle via HttpOnly cookies
 * - Distinct separation between Account Password and Master Password
 * - First-time registration with client-generated 16-byte KDF salt
 * - Session restoration on app boot via refresh token
 * - Demo mode isolation
 * - Complete state clearing on logout
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode
} from "react";
import { authApi } from "../api/auth";
import { onSessionExpired, setAccessToken } from "../api/client";
import type { SafeUser } from "../api/types";
import { getOrCreateDeviceIdentifier, getDeviceName } from "./device-info";
import { createDefaultKdfMetadata, deriveVaultKey } from "../crypto/kdf";
import { encryptVaultPayload } from "../crypto/aes";
import {
  saveAuthVerification,
  saveKdfMetadata,
  resetVaultDatabase,
  setActiveStorageUser,
  clearAccountCache
} from "../storage/vault-db";
import { syncEngine } from "../sync/sync-engine";
import { clearVaultClipboardImmediately } from "../clipboard";

type AuthResetCallback = () => void;
const authResetCallbacks = new Set<AuthResetCallback>();

export function onAuthReset(callback: AuthResetCallback): () => void {
  authResetCallbacks.add(callback);
  return () => {
    authResetCallbacks.delete(callback);
  };
}

export function triggerAuthReset(): void {
  authResetCallbacks.forEach((cb) => {
    try {
      cb();
    } catch {
      // Ignore callback errors
    }
  });
}

interface AuthContextType {
  user: SafeUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  isDemoMode: boolean;
  error: string | null;
  login: (email: string, password: string) => Promise<{ success: boolean; user?: SafeUser; error?: string }>;
  register: (
    email: string,
    accountPassword: string,
    masterPassword: string
  ) => Promise<{ success: boolean; user?: SafeUser; error?: string }>;
  logout: () => Promise<void>;
  enterDemoMode: () => void;
  exitDemoMode: () => void;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SafeUser | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Check active session on initial mount
  useEffect(() => {
    let mounted = true;

    async function restoreSession() {
      try {
        // Attempt silent refresh using HttpOnly cookie
        const refreshResult = await authApi.refresh();
        if (refreshResult.token && mounted) {
          const profile = await authApi.getMe();
          if (mounted) {
            setActiveStorageUser(profile.id);
            setUser(profile);
            // Sync user KDF metadata locally
            if (profile.vaultKdfSalt) {
              await saveKdfMetadata({
                vaultKdfSalt: profile.vaultKdfSalt,
                vaultKdfAlgorithm: profile.vaultKdfAlgorithm as "PBKDF2-HMAC-SHA256",
                vaultKdfParameters: profile.vaultKdfParameters as any
              }, profile.id);
            }
          }
        }
      } catch {
        // No active session or refresh token expired — normal logged-out state
        if (mounted) {
          setActiveStorageUser(null);
          setUser(null);
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }

    restoreSession();

    // Register 401 session expiration handler
    const unsubscribe = onSessionExpired(async () => {
      // Phase 9.2 (Fix D): Immediate lock, cancel sync, invalidate tokens & clear cache
      syncEngine.cancelSync();
      triggerAuthReset();
      setAccessToken(null);
      clearVaultClipboardImmediately().catch(() => {});

      const expiredUserId = user?.id;
      if (expiredUserId) {
        await clearAccountCache(expiredUserId).catch(() => {});
      }
      setActiveStorageUser(null);

      if (mounted) {
        setUser(null);
        setError("Your session has expired. Please sign in again.");
      }
    });

    return () => {
      mounted = false;
      unsubscribe();
    };
  }, []);

  /**
   * Logs into an existing account with email and account password.
   * Master password is NOT processed here (it is entered when unlocking vault).
   */
  const login = useCallback(
    async (email: string, password: string): Promise<{ success: boolean; user?: SafeUser; error?: string }> => {
      setError(null);
      setIsLoading(true);
      try {
        const deviceIdentifier = getOrCreateDeviceIdentifier();
        const deviceName = getDeviceName();

        const result = await authApi.login({
          email: email.trim(),
          password,
          deviceIdentifier,
          deviceName
        });

        const safeUser = result.user;
        setActiveStorageUser(safeUser.id);
        setUser(safeUser);
        setIsDemoMode(false);

        // Store non-secret KDF metadata locally for subsequent vault unlock operations
        if (safeUser.vaultKdfSalt) {
          await saveKdfMetadata({
            vaultKdfSalt: safeUser.vaultKdfSalt,
            vaultKdfAlgorithm: safeUser.vaultKdfAlgorithm as "PBKDF2-HMAC-SHA256",
            vaultKdfParameters: safeUser.vaultKdfParameters as any
          }, safeUser.id);
        }

        return { success: true, user: safeUser };
      } catch (err: any) {
        const message = err?.message || "Authentication failed. Please check your credentials.";
        setError(message);
        return { success: false, error: message };
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  /**
   * Registers a new account.
   * - Client generates a 16-byte random salt and derives the AES-256-GCM key with PBKDF2.
   * - Client saves the non-secret KDF metadata and encrypted canary verification locally.
   * - Client sends email, account password, and non-secret KDF metadata to backend.
   * - Master password and derived key NEVER leave the browser.
   */
  const register = useCallback(
    async (
      email: string,
      accountPassword: string,
      masterPassword: string
    ): Promise<{ success: boolean; user?: SafeUser; error?: string }> => {
      setError(null);
      setIsLoading(true);
      try {
        if (!masterPassword || masterPassword.length < 8) {
          throw new Error("Master password must be at least 8 characters long.");
        }
        if (!accountPassword || accountPassword.length < 12) {
          throw new Error("Account password must be at least 12 characters long.");
        }

        // 1. Generate fresh 16-byte random salt and KDF metadata locally
        const kdfMetadata = createDefaultKdfMetadata();

        // 2. Derive non-extractable AES-256-GCM key in browser memory
        const key = await deriveVaultKey(
          masterPassword,
          kdfMetadata.vaultKdfSalt,
          kdfMetadata.vaultKdfParameters.iterations
        );

        // 3. Encrypt an authentication canary verification record
        const canaryPayload = { verifier: "vaultguard-master-key-verified", createdAt: new Date().toISOString() };
        const encryptedCanary = await encryptVaultPayload(canaryPayload, key);

        // 4. Save metadata and canary verifier locally in IndexedDB
        await saveKdfMetadata(kdfMetadata);
        await saveAuthVerification(encryptedCanary);

        // 5. Send account registration request with non-secret KDF metadata
        // Zero-Knowledge: Master password and derived key are strictly excluded!
        await authApi.register({
          email: email.trim(),
          password: accountPassword,
          vaultKdfSalt: kdfMetadata.vaultKdfSalt,
          vaultKdfAlgorithm: kdfMetadata.vaultKdfAlgorithm,
          vaultKdfParameters: kdfMetadata.vaultKdfParameters
        });

        // 6. Automatically log in to establish session
        const deviceIdentifier = getOrCreateDeviceIdentifier();
        const deviceName = getDeviceName();
        const loginResult = await authApi.login({
          email: email.trim(),
          password: accountPassword,
          deviceIdentifier,
          deviceName
        });

        const safeUser = loginResult.user;
        setActiveStorageUser(safeUser.id);
        setUser(safeUser);
        setIsDemoMode(false);

        // Store KDF metadata and verification canary scoped to user
        if (kdfMetadata) {
          await saveKdfMetadata(kdfMetadata, safeUser.id);
        }
        if (encryptedCanary) {
          await saveAuthVerification(encryptedCanary, safeUser.id);
        }

        // Also create server verification record if not already created
        try {
          if (encryptedCanary) {
            await (await import("../api/vault")).vaultApi.createVerification({
              encryptedPayload: encryptedCanary.encryptedPayload,
              initializationVector: encryptedCanary.initializationVector,
              authenticationTag: encryptedCanary.authenticationTag,
              encryptionAlgorithm: encryptedCanary.encryptionAlgorithm,
              encryptionVersion: encryptedCanary.encryptionVersion,
              isLegacyMigration: false
            });
          }
        } catch {
          // If already exists or handled by initializeVault, continue
        }

        return { success: true, user: safeUser };
      } catch (err: any) {
        const message = err?.message || "Registration failed. Please try again.";
        setError(message);
        return { success: false, error: message };
      } finally {
        setIsLoading(false);
      }
    },
    []
  );

  /**
   * Logs out user, revoking server session, clearing tokens and purging account-specific local cache.
   */
  const logout = useCallback(async (): Promise<void> => {
    setIsLoading(true);
    const currentUserId = user?.id;

    // Phase 9.2 (Fix D): Immediate lock, cancel sync, invalidate tokens
    syncEngine.cancelSync();
    triggerAuthReset();
    setAccessToken(null);
    clearVaultClipboardImmediately().catch(() => {});

    try {
      await authApi.logout();
    } catch {
      // Ignore network errors during logout
    } finally {
      setUser(null);
      setIsDemoMode(false);
      setError(null);
      setIsLoading(false);
      // Clean up account-specific cache to guarantee zero residue for subsequent users
      if (currentUserId) {
        await clearAccountCache(currentUserId).catch(() => {});
      }
      setActiveStorageUser(null);
    }
  }, [user]);

  const enterDemoMode = useCallback(() => {
    setIsDemoMode(true);
    setUser(null);
    setError(null);
  }, []);

  const exitDemoMode = useCallback(() => {
    setIsDemoMode(false);
    setError(null);
  }, []);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  const value: AuthContextType = {
    user,
    isAuthenticated: user !== null,
    isLoading,
    isDemoMode,
    error,
    login,
    register,
    logout,
    enterDemoMode,
    exitDemoMode,
    clearError
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider.");
  }
  return context;
}
