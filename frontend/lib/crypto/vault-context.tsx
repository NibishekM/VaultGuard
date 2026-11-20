'use client'

/**
 * VaultGuard – Vault Cryptographic Lifecycle and Context (Phases 8 & 9.1)
 *
 * Manages the in-memory lifecycle of the derived AES-GCM CryptoKey:
 * - States: locked | unlocking | unlocked | locking | error
 * - CryptoKey is stored exclusively in a mutable ref (useRef), NEVER in React state or browser storage.
 * - Decrypted vault items are held in React state ONLY while unlocked.
 * - Master password verification: strictly verifies authentication tag against server-synchronized canary.
 * - Multi-device synchronization: enables safe cross-device unlock with verified remote canary.
 * - Safe legacy migration: permits authorized migration of existing local canaries to the server.
 * - Strict integrity checking: rejects unlock on canary tag failure or corrupt item payload.
 * - In-flight synchronization cancellation: aborts network requests and discards stale callbacks on lock.
 * - Integrated with backend Vault CRUD and incremental synchronization.
 * - Concurrency control with expectedRevision.
 * - Configurable inactivity auto-lock.
 */

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode
} from "react";
import { VAULT_CRYPTO_CONSTANTS } from "./constants";
import {
  createDefaultKdfMetadata,
  deriveVaultKey,
  validateKdfMetadata
} from "./kdf";
import { decryptVaultPayload, encryptVaultPayload } from "./aes";
import {
  createVaultExport,
  validateVaultBackup,
  type VaultBackupFile
} from "./export-import";
import {
  deleteEncryptedRecord,
  getAuthVerification,
  getKdfMetadata,
  isVaultInitialized,
  listEncryptedRecords,
  resetVaultDatabase,
  saveAuthVerification,
  saveEncryptedRecord,
  saveKdfMetadata
} from "../storage/vault-db";
import {
  CryptographicError,
  DecryptionError,
  type DecryptedVaultItem,
  type EncryptedVaultRecord,
  type VaultKeyState
} from "./types";
import { vaultApi } from "../api/vault";
import { authApi } from "../api/auth";
import { getAccessToken } from "../api/client";
import { syncEngine, type SyncStatus } from "../sync/sync-engine";
import { onAuthReset } from "../auth/auth-context";
import { clearVaultClipboardImmediately } from "../clipboard";

interface VaultContextType {
  keyState: VaultKeyState;
  error: string | null;
  items: DecryptedVaultItem[];
  isInitialized: boolean;
  autoLockMinutes: number;
  syncStatus: SyncStatus;
  lastSyncTime: Date | null;
  initializeVault: (masterPassword: string) => Promise<boolean>;
  unlockVault: (masterPassword: string) => Promise<boolean>;
  lockVault: () => void;
  addItem: (item: Omit<DecryptedVaultItem, "id" | "createdAt" | "updatedAt">) => Promise<DecryptedVaultItem>;
  updateItem: (item: DecryptedVaultItem) => Promise<void>;
  deleteItem: (id: string) => Promise<void>;
  setAutoLockMinutes: (minutes: number) => void;
  resetVault: () => Promise<void>;
  syncNow: () => Promise<void>;
  exportVault: () => Promise<{ backup: VaultBackupFile; json: string; filename: string; recordCount: number }>;
  importVault: (backupJson: string, strategy?: "error" | "skip") => Promise<{ totalProcessed: number; insertedCount: number; skippedCount: number }>;
}

const VaultContext = createContext<VaultContextType | null>(null);

export function VaultProvider({ children }: { children: ReactNode }) {
  const [keyState, setKeyState] = useState<VaultKeyState>("locked");
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<DecryptedVaultItem[]>([]);
  const [isInitialized, setIsInitialized] = useState<boolean>(false);
  const [autoLockMinutes, setAutoLockMinutesState] = useState<number>(
    VAULT_CRYPTO_CONSTANTS.DEFAULT_AUTO_LOCK_MINUTES
  );
  const [syncStatus, setSyncStatus] = useState<SyncStatus>("idle");
  const [lastSyncTime, setLastSyncTime] = useState<Date | null>(null);

  // INVARIANT: The CryptoKey is stored exclusively in memory via a ref.
  // It is never stored in state, never serialized, and never persisted.
  const activeKeyRef = useRef<CryptoKey | null>(null);

  // Concurrency guard to prevent overlapping unlock/lock operations
  const isOperatingRef = useRef<boolean>(false);

  // Lock generation counter to invalidate in-flight async operations
  const lockGenerationRef = useRef<number>(0);

  // Inactivity auto-lock timer ref
  const autoLockTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Periodic sync cleanup ref
  const syncCleanupRef = useRef<(() => void) | null>(null);

  // Subscribe to sync status updates
  useEffect(() => {
    const unsub = syncEngine.subscribe((status) => {
      setSyncStatus(status);
      const engineStatus = syncEngine.getStatus();
      setLastSyncTime(engineStatus.lastSyncTime);
    });
    return unsub;
  }, []);

  // Check initialization status on mount
  useEffect(() => {
    let mounted = true;
    isVaultInitialized()
      .then((initialized) => {
        if (mounted) setIsInitialized(initialized);
      })
      .catch(() => {
        if (mounted) setIsInitialized(false);
      });
    return () => {
      mounted = false;
    };
  }, []);

  /**
   * Resets the inactivity timer. If autoLockMinutes > 0, arms the lock timeout.
   */
  const resetInactivityTimer = useCallback(() => {
    if (autoLockTimerRef.current) {
      clearTimeout(autoLockTimerRef.current);
      autoLockTimerRef.current = null;
    }

    if (activeKeyRef.current !== null && autoLockMinutes > 0) {
      autoLockTimerRef.current = setTimeout(() => {
        lockVault();
      }, autoLockMinutes * 60 * 1000);
    }
  }, [autoLockMinutes]);

  /**
   * Locks the vault immediately.
   * Clears the CryptoKey reference and all decrypted items from memory.
   * Cancels in-flight synchronization requests and invalidates pending operations.
   */
  const lockVault = useCallback(() => {
    setKeyState("locking");
    lockGenerationRef.current++;

    // 1. Clear key reference
    activeKeyRef.current = null;

    // 2. Clear decrypted records from state
    setItems([]);

    // 3. Stop background synchronization and cancel in-flight requests immediately
    if (syncCleanupRef.current) {
      syncCleanupRef.current();
      syncCleanupRef.current = null;
    }
    syncEngine.stopPeriodicSync();
    syncEngine.cancelSync();

    // 4. Clear active auto-lock timer
    if (autoLockTimerRef.current) {
      clearTimeout(autoLockTimerRef.current);
      autoLockTimerRef.current = null;
    }

    // 5. Clear VaultGuard-owned clipboard secret immediately if still in clipboard
    clearVaultClipboardImmediately().catch(() => {});

    setError(null);
    setKeyState("locked");
  }, []);

  // Phase 9.2 (Fix D): Listen for auth reset (logout or session expiry) to synchronously lock vault
  useEffect(() => {
    const unsub = onAuthReset(() => {
      lockVault();
    });
    return unsub;
  }, [lockVault]);

  /**
   * Listens for user interactions to reset the inactivity timer while unlocked.
   */
  useEffect(() => {
    if (keyState !== "unlocked") return;

    const activityEvents = ["mousedown", "keydown", "touchstart", "scroll"];
    const handleActivity = () => resetInactivityTimer();

    activityEvents.forEach((evt) => window.addEventListener(evt, handleActivity, { passive: true }));
    resetInactivityTimer();

    return () => {
      activityEvents.forEach((evt) => window.removeEventListener(evt, handleActivity));
      if (autoLockTimerRef.current) {
        clearTimeout(autoLockTimerRef.current);
        autoLockTimerRef.current = null;
      }
    };
  }, [keyState, resetInactivityTimer, lockVault]);

  /**
   * Initializes a fresh vault with a new master password.
   * Generates a 16-byte random salt, saves metadata, canary verification, derives key, and unlocks.
   */
  const initializeVault = useCallback(async (masterPassword: string): Promise<boolean> => {
    if (isOperatingRef.current) return false;
    isOperatingRef.current = true;
    setError(null);
    setKeyState("unlocking");

    try {
      if (!masterPassword || masterPassword.length < 8) {
        throw new CryptographicError("Master password must be at least 8 characters long.");
      }

      // If authenticated, ensure vault is genuinely uninitialized on server
      const hasAuthToken = Boolean(getAccessToken());
      if (hasAuthToken) {
        try {
          const remoteStatus = await vaultApi.getVerification();
          if (remoteStatus.hasVerification || remoteStatus.hasItems) {
            throw new CryptographicError("Vault is already initialized on server. Please use unlock instead.");
          }
        } catch (err: any) {
          if (err instanceof CryptographicError) throw err;
        }
      }

      // 1. Generate fresh salt and KDF metadata
      const metadata = createDefaultKdfMetadata();
      await saveKdfMetadata(metadata);

      // 2. Derive non-extractable CryptoKey using PBKDF2 (600,000 iterations)
      const key = await deriveVaultKey(
        masterPassword,
        metadata.vaultKdfSalt,
        metadata.vaultKdfParameters.iterations
      );

      // 3. Create encrypted canary verification record
      const canary = { verifier: "vaultguard-master-key-verified", createdAt: new Date().toISOString() };
      const encryptedCanary = await encryptVaultPayload(canary, key);

      // 4. If authenticated, create verification record on server (create-once)
      if (hasAuthToken) {
        await vaultApi.createVerification({
          encryptedPayload: encryptedCanary.encryptedPayload,
          initializationVector: encryptedCanary.initializationVector,
          authenticationTag: encryptedCanary.authenticationTag,
          encryptionAlgorithm: encryptedCanary.encryptionAlgorithm,
          encryptionVersion: encryptedCanary.encryptionVersion,
          isLegacyMigration: false
        });
      }

      // 5. Save locally in account-scoped storage
      await saveAuthVerification(encryptedCanary);

      // 6. Store key in memory ref only
      activeKeyRef.current = key;
      setItems([]);
      setIsInitialized(true);
      setKeyState("unlocked");

      // 7. Start synchronization if user is authenticated
      if (hasAuthToken) {
        syncCleanupRef.current = syncEngine.startPeriodicSync(
          () => activeKeyRef.current,
          (updater) => setItems(updater),
          () => activeKeyRef.current !== null,
          () => lockGenerationRef.current
        );
      }

      return true;
    } catch (err: any) {
      activeKeyRef.current = null;
      setItems([]);
      setError(err?.message || "Failed to initialize vault.");
      setKeyState("error");
      return false;
    } finally {
      isOperatingRef.current = false;
    }
  }, []);

  /**
   * Unlocks an existing vault using the master password.
   * Loads KDF metadata, derives key, strictly authenticates verification canary / stored items.
   * Supports multi-device unlock and safe legacy canary migration.
   */
  const unlockVault = useCallback(async (masterPassword: string): Promise<boolean> => {
    if (isOperatingRef.current) return false;
    isOperatingRef.current = true;
    setError(null);
    setKeyState("unlocking");
    const currentGeneration = lockGenerationRef.current;

    try {
      if (!masterPassword) {
        throw new CryptographicError("Master password is required.");
      }

      const hasAuthToken = Boolean(getAccessToken());

      // 1. Load KDF metadata from IndexedDB or remote profile
      let metadata = await getKdfMetadata();
      if (!metadata && hasAuthToken) {
        try {
          const profile = await authApi.getMe();
          if (profile.vaultKdfSalt) {
            metadata = {
              vaultKdfSalt: profile.vaultKdfSalt,
              vaultKdfAlgorithm: profile.vaultKdfAlgorithm as "PBKDF2-HMAC-SHA256",
              vaultKdfParameters: {
                iterations: profile.vaultKdfParameters?.iterations || 600000,
                keyLength: 32,
                digest: "SHA-256"
              }
            };
            await saveKdfMetadata(metadata);
          }
        } catch {
          // Ignore network errors fetching profile
        }
      }

      if (!metadata) {
        throw new CryptographicError("Vault is not initialized. Please set up a master password first.");
      }
      validateKdfMetadata(metadata);

      // 2. Derive the 256-bit AES-GCM CryptoKey via PBKDF2 (600,000 iterations)
      const key = await deriveVaultKey(
        masterPassword,
        metadata.vaultKdfSalt,
        metadata.vaultKdfParameters.iterations
      );

      // 3. MASTER PASSWORD VERIFICATION:
      if (hasAuthToken) {
        const remoteStatus = await vaultApi.getVerification();

        if (remoteStatus.hasVerification && remoteStatus.verification) {
          // Scenario C: Server verification canary exists (multi-device standard unlock)
          try {
            await decryptVaultPayload(remoteStatus.verification, key);
          } catch {
            throw new DecryptionError("Incorrect master password. Authentication failed.");
          }
          // Successfully verified against server canary! Cache locally for offline use
          await saveAuthVerification(remoteStatus.verification);
        } else if (!remoteStatus.hasVerification && remoteStatus.hasItems) {
          // Scenario B / D: Legacy vault with server items but no remote canary yet
          let localCanary = await getAuthVerification();

          if (!localCanary) {
            // Phase 9.2.1 (Fix C): Safe legacy recovery when original local canary is missing on client.
            // Attempt to verify master password against an existing encrypted item on the server
            // (either via remoteStatus.recoveryRecord which supports active or soft-deleted items,
            // or by fetching active remote items).
            let targetRecord: any = remoteStatus.recoveryRecord || null;

            if (!targetRecord) {
              try {
                const remoteItems = await vaultApi.listItems();
                if (remoteItems.length > 0) {
                  targetRecord = remoteItems[0];
                }
              } catch {
                // Network error listing items
              }
            }

            if (targetRecord && targetRecord.encryptedPayload) {
              try {
                // Test decrypting the encrypted item to establish local proof of master password
                await decryptVaultPayload(targetRecord, key);
              } catch {
                throw new DecryptionError("Incorrect master password. Authentication failed.");
              }

              // Local proof established! Create a fresh canary verifier locally
              const freshCanary = { verifier: "vaultguard-master-key-verified", createdAt: new Date().toISOString() };
              localCanary = await encryptVaultPayload(freshCanary, key);
              await saveAuthVerification(localCanary);
            } else {
              throw new CryptographicError(
                "Secure migration required from original device: This vault was created before multi-device synchronization. Please log in on your original device first to authorize this vault for multi-device access."
              );
            }
          } else {
            // Scenario B: Legacy original device with local canary -> verify master password
            try {
              await decryptVaultPayload(localCanary, key);
            } catch {
              throw new DecryptionError("Incorrect master password. Authentication failed.");
            }
          }

          // Canary verified! Perform legacy migration to server.
          // The backend independently authorizes whether the session/device is the original enrolled device.
          try {
            await vaultApi.createVerification({
              encryptedPayload: localCanary.encryptedPayload,
              initializationVector: localCanary.initializationVector,
              authenticationTag: localCanary.authenticationTag,
              encryptionAlgorithm: localCanary.encryptionAlgorithm,
              encryptionVersion: localCanary.encryptionVersion,
              isLegacyMigration: true
            });
          } catch (migrateErr: any) {
            // If backend rejects because device is not authorized (403 Forbidden or 409 Conflict):
            if (
              migrateErr?.status === 403 ||
              migrateErr?.statusCode === 403 ||
              migrateErr?.message?.includes("Forbidden") ||
              migrateErr?.message?.includes("original enrolled device")
            ) {
              throw new CryptographicError(
                "Secure migration required from original device: This vault was created before multi-device synchronization. Please log in on your original device first to authorize this vault for multi-device access."
              );
            }
            throw migrateErr;
          }
        } else if (!remoteStatus.hasVerification && !remoteStatus.hasItems) {
          // Scenario E: Genuinely empty, uninitialized account
          throw new CryptographicError("Vault is not initialized. Please set up a master password first.");
        }
      } else {
        // Offline / Unauthenticated Mode
        const canary = await getAuthVerification();
        if (canary) {
          try {
            await decryptVaultPayload(canary, key);
          } catch {
            throw new DecryptionError("Incorrect master password. Authentication failed.");
          }
        } else {
          const existingRecords = await listEncryptedRecords();
          if (existingRecords.length > 0) {
            try {
              await decryptVaultPayload(existingRecords[0], key);
            } catch {
              throw new DecryptionError("Incorrect master password. Authentication failed.");
            }
          } else {
            throw new CryptographicError("Vault is not initialized. Please set up a master password first.");
          }
        }
      }

      // 4. Load items: if authenticated, fetch from backend and sync locally; otherwise read local IndexedDB
      let recordsToDecrypt: EncryptedVaultRecord[] = [];

      if (hasAuthToken) {
        try {
          const remoteItems = await vaultApi.listItems();
          for (const item of remoteItems) {
            const rec: EncryptedVaultRecord = {
              id: item.id,
              encryptedPayload: item.encryptedPayload,
              initializationVector: item.initializationVector,
              authenticationTag: item.authenticationTag,
              encryptionAlgorithm: item.encryptionAlgorithm as "AES-256-GCM",
              encryptionVersion: item.encryptionVersion as 1,
              revision: item.revision,
              syncVersion: item.syncVersion,
              createdAt: item.createdAt,
              updatedAt: item.updatedAt
            };
            await saveEncryptedRecord(rec);
          }
          recordsToDecrypt = await listEncryptedRecords();
        } catch {
          recordsToDecrypt = await listEncryptedRecords();
        }
      } else {
        recordsToDecrypt = await listEncryptedRecords();
      }

      // 5. Decrypt items into in-memory array with strict integrity checks
      const decryptedList: DecryptedVaultItem[] = [];
      let integrityFailureCount = 0;

      for (const record of recordsToDecrypt) {
        try {
          const decryptedPayload = await decryptVaultPayload<any>(record, key);
          decryptedList.push({
            id: record.id,
            service: decryptedPayload.service || "Unnamed Service",
            username: decryptedPayload.username || "",
            password: decryptedPayload.password || "",
            category: decryptedPayload.category || "Personal",
            health: decryptedPayload.health || "Strong",
            favorite: Boolean(decryptedPayload.favorite),
            notes: decryptedPayload.notes || "",
            revision: record.revision,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
          });
        } catch {
          integrityFailureCount++;
        }
      }

      // Strict integrity enforcement: Do NOT silently ignore decryption failures
      if (integrityFailureCount > 0) {
        throw new CryptographicError(
          `Vault item integrity failure: ${integrityFailureCount} item(s) failed integrity verification. Vault remains locked to prevent data loss.`
        );
      }

      // Check lock cancellation guard before committing state
      if (lockGenerationRef.current !== currentGeneration) {
        return false;
      }

      // 6. Success: Hold key in memory ref only
      activeKeyRef.current = key;
      setItems(decryptedList);
      setKeyState("unlocked");
      setIsInitialized(true);

      // 7. Start periodic background synchronization if authenticated
      if (hasAuthToken) {
        syncCleanupRef.current = syncEngine.startPeriodicSync(
          () => activeKeyRef.current,
          (updater) => setItems(updater),
          () => activeKeyRef.current !== null,
          () => lockGenerationRef.current
        );
      }

      return true;
    } catch (err: any) {
      activeKeyRef.current = null;
      setItems([]);

      if (err instanceof DecryptionError) {
        setError("Incorrect master password. Authentication failed.");
      } else {
        setError(err?.message || "Failed to unlock vault.");
      }

      setKeyState("error");
      return false;
    } finally {
      isOperatingRef.current = false;
    }
  }, []);

  /**
   * Encrypts and adds a new item to the vault.
   * If authenticated, posts ciphertext to backend and receives canonical UUID and revision.
   */
  const addItem = useCallback(
    async (item: Omit<DecryptedVaultItem, "id" | "createdAt" | "updatedAt">): Promise<DecryptedVaultItem> => {
      const key = activeKeyRef.current;
      if (!key || keyState !== "unlocked") {
        throw new CryptographicError("Vault is locked. Cannot add item.");
      }

      const now = new Date().toISOString();
      const payloadToEncrypt = {
        service: item.service,
        username: item.username,
        password: item.password,
        category: item.category,
        health: item.health,
        favorite: item.favorite,
        notes: item.notes
      };

      // 1. Encrypt via AES-256-GCM with unique 12-byte IV
      const encrypted = await encryptVaultPayload(payloadToEncrypt, key);

      let recordId: string;
      let revision = 1;
      let syncVersion = 0;
      let createdAt = now;
      let updatedAt = now;

      // 2. If authenticated, store on backend first
      if (getAccessToken()) {
        const createdOnServer = await vaultApi.createItem({
          encryptedPayload: encrypted.encryptedPayload,
          initializationVector: encrypted.initializationVector,
          authenticationTag: encrypted.authenticationTag,
          encryptionAlgorithm: encrypted.encryptionAlgorithm,
          encryptionVersion: encrypted.encryptionVersion
        });

        recordId = createdOnServer.id;
        revision = createdOnServer.revision;
        syncVersion = createdOnServer.syncVersion;
        createdAt = createdOnServer.createdAt;
        updatedAt = createdOnServer.updatedAt;
      } else {
        recordId = crypto.randomUUID();
      }

      // 3. Persist ONLY ciphertext and non-secret metadata to IndexedDB
      const recordToStore: EncryptedVaultRecord = {
        id: recordId,
        createdAt,
        updatedAt,
        revision,
        syncVersion,
        encryptedPayload: encrypted.encryptedPayload,
        initializationVector: encrypted.initializationVector,
        authenticationTag: encrypted.authenticationTag,
        encryptionAlgorithm: encrypted.encryptionAlgorithm,
        encryptionVersion: encrypted.encryptionVersion
      };

      await saveEncryptedRecord(recordToStore);

      // 4. Update in-memory decrypted items
      const newItem: DecryptedVaultItem = {
        id: recordId,
        ...item,
        revision,
        createdAt,
        updatedAt
      };

      setItems((prev) => [newItem, ...prev]);
      resetInactivityTimer();
      return newItem;
    },
    [keyState, resetInactivityTimer]
  );

  /**
   * Updates an existing item in the vault.
   * If authenticated, uses expectedRevision for optimistic concurrency conflict detection.
   */
  const updateItem = useCallback(
    async (item: DecryptedVaultItem): Promise<void> => {
      const key = activeKeyRef.current;
      if (!key || keyState !== "unlocked") {
        throw new CryptographicError("Vault is locked. Cannot update item.");
      }

      const now = new Date().toISOString();
      const payloadToEncrypt = {
        service: item.service,
        username: item.username,
        password: item.password,
        category: item.category,
        health: item.health,
        favorite: item.favorite,
        notes: item.notes
      };

      // 1. Re-encrypt with a fresh unique IV
      const encrypted = await encryptVaultPayload(payloadToEncrypt, key);
      let revision = (item.revision || 1) + 1;
      let updatedAt = now;

      // 2. If authenticated, update on backend with expectedRevision
      if (getAccessToken()) {
        const serverUpdate = await vaultApi.updateItem(item.id, {
          encryptedPayload: encrypted.encryptedPayload,
          initializationVector: encrypted.initializationVector,
          authenticationTag: encrypted.authenticationTag,
          encryptionAlgorithm: encrypted.encryptionAlgorithm,
          encryptionVersion: encrypted.encryptionVersion,
          expectedRevision: item.revision || 1
        });
        revision = serverUpdate.revision;
        updatedAt = serverUpdate.updatedAt;
      }

      // 3. Persist updated ciphertext to IndexedDB
      const recordToStore: EncryptedVaultRecord = {
        id: item.id,
        createdAt: item.createdAt || now,
        updatedAt,
        revision,
        encryptedPayload: encrypted.encryptedPayload,
        initializationVector: encrypted.initializationVector,
        authenticationTag: encrypted.authenticationTag,
        encryptionAlgorithm: encrypted.encryptionAlgorithm,
        encryptionVersion: encrypted.encryptionVersion
      };

      await saveEncryptedRecord(recordToStore);

      // 4. Update in-memory state
      setItems((prev) =>
        prev.map((entry) => (entry.id === item.id ? { ...item, revision, updatedAt } : entry))
      );
      resetInactivityTimer();
    },
    [keyState, resetInactivityTimer]
  );

  /**
   * Deletes an item from the vault.
   * Soft-deletes on backend if authenticated.
   */
  const deleteItem = useCallback(
    async (id: string): Promise<void> => {
      if (keyState !== "unlocked") {
        throw new CryptographicError("Vault is locked. Cannot delete item.");
      }

      if (getAccessToken()) {
        await vaultApi.deleteItem(id);
      }

      await deleteEncryptedRecord(id);
      setItems((prev) => prev.filter((item) => item.id !== id));
      resetInactivityTimer();
    },
    [keyState, resetInactivityTimer]
  );

  /**
   * Triggers manual synchronization.
   */
  const syncNow = useCallback(async (): Promise<void> => {
    if (keyState === "unlocked" && activeKeyRef.current) {
      await syncEngine.sync(
        activeKeyRef.current,
        setItems,
        () => activeKeyRef.current !== null,
        () => lockGenerationRef.current
      );
    }
  }, [keyState]);

  /**
   * Generates a secure, encrypted backup file of the user's vault.
   * Exports only encrypted ciphertext and KDF metadata. Never exports plaintext or keys.
   */
  const exportVault = useCallback(async () => {
    const key = activeKeyRef.current;
    if (!key || keyState !== "unlocked") {
      throw new CryptographicError("Vault is locked. Cannot export vault records.");
    }

    const metadata = await getKdfMetadata();
    if (!metadata) {
      throw new CryptographicError("Vault KDF metadata missing. Cannot create export.");
    }

    const records = await listEncryptedRecords();
    const backup = createVaultExport(records, metadata);
    const json = JSON.stringify(backup, null, 2);
    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = `vaultguard-backup-${dateStr}.json`;

    return {
      backup,
      json,
      filename,
      recordCount: records.length
    };
  }, [keyState]);

  /**
   * Restores an encrypted vault backup after strict cryptographic, structural, and compatibility validation.
   * Atomically applies records remotely (if authenticated) and locally.
   */
  const importVault = useCallback(
    async (backupJson: string, strategy: "error" | "skip" = "error") => {
      const key = activeKeyRef.current;
      if (!key || keyState !== "unlocked") {
        throw new CryptographicError("Vault is locked. Cannot import vault records.");
      }

      // 1. Get current active account KDF metadata
      const currentMetadata = await getKdfMetadata();

      // 2. Validate backup structure, cryptographic constraints, and exact KDF metadata compatibility
      const validation = validateVaultBackup(backupJson, currentMetadata);
      if (!validation.success || !validation.data) {
        throw new CryptographicError(validation.error || "Invalid backup file.");
      }

      const backup = validation.data.vaultguardBackup;

      // Safe No-Op: A valid empty backup (records: []) requires no state mutation or backend network call
      if (backup.records.length === 0) {
        resetInactivityTimer();
        return {
          totalProcessed: 0,
          insertedCount: 0,
          skippedCount: 0
        };
      }

      // 3. Pre-commit decryption verification: Verify EVERY record decrypts with active CryptoKey
      // This strictly prevents importing corrupted records or records encrypted under a different password.
      const decryptedRecords: DecryptedVaultItem[] = [];
      for (let i = 0; i < backup.records.length; i++) {
        const rec = backup.records[i];
        try {
          const decryptedPayload = await decryptVaultPayload<Record<string, any>>(rec, key);
          decryptedRecords.push({
            id: rec.id,
            service: decryptedPayload.service || "",
            username: decryptedPayload.username || "",
            password: decryptedPayload.password || "",
            category: decryptedPayload.category || "Personal",
            health: decryptedPayload.health || "Strong",
            favorite: Boolean(decryptedPayload.favorite),
            notes: decryptedPayload.notes || "",
            revision: rec.revision || 1,
            createdAt: rec.createdAt,
            updatedAt: rec.updatedAt
          });
        } catch (decErr: any) {
          throw new DecryptionError(
            `Backup verification failed on record #${i + 1} ('${rec.id}'): Decryption failed. The backup may be corrupted or encrypted with a different master password.`
          );
        }
      }

      // 4. Remote Persistence: If authenticated, call backend batch-import transaction
      let insertedCount = backup.records.length;
      let skippedCount = 0;
      let serverCommitted = false;

      if (getAccessToken()) {
        const serverResult = await vaultApi.batchImport({
          items: backup.records.map((r) => ({
            id: r.id,
            encryptedPayload: r.encryptedPayload,
            initializationVector: r.initializationVector,
            authenticationTag: r.authenticationTag,
            encryptionAlgorithm: r.encryptionAlgorithm,
            encryptionVersion: r.encryptionVersion,
            revision: r.revision || 1,
            createdAt: r.createdAt,
            updatedAt: r.updatedAt
          })),
          strategy
        });

        insertedCount = serverResult.insertedCount;
        skippedCount = serverResult.skippedCount;
        serverCommitted = true;
      }

      // 5. Local Persistence: Save records to IndexedDB and update in-memory state
      try {
        for (const rec of backup.records) {
          await saveEncryptedRecord(rec);
        }
      } catch (idbErr: any) {
        if (serverCommitted) {
          throw new Error(
            `Import partially completed: ${insertedCount} entries were committed to your remote vault, but saving to local browser storage failed (${idbErr?.message || "Storage error"}). Please run "Sync now" or re-open your vault to refresh local storage.`
          );
        }
        throw idbErr;
      }

      // 6. Update in-memory items
      setItems((prev) => {
        const existingIds = new Set(prev.map((i) => i.id));
        const newItems = decryptedRecords.filter((d) => !existingIds.has(d.id));
        const updatedExisting = prev.map((item) => {
          const match = decryptedRecords.find((d) => d.id === item.id);
          return match ? match : item;
        });
        return [...newItems, ...updatedExisting];
      });

      resetInactivityTimer();

      return {
        totalProcessed: backup.records.length,
        insertedCount,
        skippedCount
      };
    },
    [keyState, resetInactivityTimer]
  );

  /**
   * Resets the entire local vault.
   */
  const resetVault = useCallback(async (): Promise<void> => {
    lockVault();
    await resetVaultDatabase();
    setIsInitialized(false);
    setError(null);
  }, [lockVault]);

  const setAutoLockMinutes = useCallback((minutes: number) => {
    setAutoLockMinutesState(minutes);
  }, []);

  const value: VaultContextType = {
    keyState,
    error,
    items,
    isInitialized,
    autoLockMinutes,
    syncStatus,
    lastSyncTime,
    initializeVault,
    unlockVault,
    lockVault,
    addItem,
    updateItem,
    deleteItem,
    setAutoLockMinutes,
    resetVault,
    syncNow,
    exportVault,
    importVault
  };

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export function useVault(): VaultContextType {
  const context = useContext(VaultContext);
  if (!context) {
    throw new Error("useVault must be used within a VaultProvider.");
  }
  return context;
}
