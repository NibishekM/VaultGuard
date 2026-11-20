/**
 * VaultGuard – Incremental Synchronization Engine (Phase 9 & 9.1)
 *
 * Implements client-side synchronization with backend /api/sync/changes:
 * - High-water mark cursor progression
 * - Pagination handling
 * - Safe persistence before cursor advancement
 * - Tombstone processing (isDeleted: true -> deletes from IndexedDB and state)
 * - Idempotent record updates
 * - In-flight mutex guarding against overlapping sync runs
 * - Immediate abort & cancellation via AbortController on lockVault / logout
 * - Lock generation checking to guarantee no stale decrypted data reaches React state
 * - Automatic 30-second interval with visibility-aware pause/resume
 * - Zero plaintext transmission (only ciphertext processed)
 */

import { syncApi } from "../api/sync";
import type { SyncChangesResponseData, VaultChange } from "../api/types";
import { decryptVaultPayload } from "../crypto/aes";
import type { DecryptedVaultItem, EncryptedVaultRecord } from "../crypto/types";
import {
  deleteEncryptedRecord,
  getActiveStorageUser,
  getSyncCursor,
  saveEncryptedRecord,
  saveSyncCursor
} from "../storage/vault-db";

export interface SyncResult {
  appliedCount: number;
  tombstoneCount: number;
  newCursor: number;
  error?: string;
  cancelled?: boolean;
}

export type SyncStatus = "idle" | "syncing" | "error" | "offline";

class SyncEngine {
  private isSyncing = false;
  private intervalTimer: ReturnType<typeof setInterval> | null = null;
  private listeners = new Set<(status: SyncStatus, lastResult?: SyncResult) => void>();
  private currentStatus: SyncStatus = "idle";
  private lastSyncTime: Date | null = null;
  private currentAbortController: AbortController | null = null;

  public getStatus(): { status: SyncStatus; lastSyncTime: Date | null } {
    return { status: this.currentStatus, lastSyncTime: this.lastSyncTime };
  }

  public subscribe(listener: (status: SyncStatus, lastResult?: SyncResult) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private setStatus(status: SyncStatus, result?: SyncResult): void {
    this.currentStatus = status;
    this.listeners.forEach((fn) => {
      try {
        fn(status, result);
      } catch {
        // Ignore listener error
      }
    });
  }

  /**
   * Immediately cancels any active in-flight sync network requests and processing.
   */
  public cancelSync(): void {
    if (this.currentAbortController) {
      try {
        this.currentAbortController.abort();
      } catch {
        // Ignore abort errors
      }
      this.currentAbortController = null;
    }
    this.isSyncing = false;
    this.setStatus("idle", { appliedCount: 0, tombstoneCount: 0, newCursor: 0, cancelled: true });
  }

  /**
   * Performs an incremental synchronization pass.
   *
   * @param keyOrGetKey Active in-memory CryptoKey or getter function returning CryptoKey (null if locked)
   * @param onItemsUpdated Callback to update in-memory decrypted items
   * @param isUnlocked Optional predicate returning whether vault remains unlocked
   * @param getLockGeneration Optional getter returning current lock generation counter
   */
  public async sync(
    keyOrGetKey: CryptoKey | null | (() => CryptoKey | null),
    onItemsUpdated?: (updater: (prev: DecryptedVaultItem[]) => DecryptedVaultItem[]) => void,
    isUnlocked?: () => boolean,
    getLockGeneration?: () => number
  ): Promise<SyncResult> {
    if (this.isSyncing) {
      return { appliedCount: 0, tombstoneCount: 0, newCursor: await getSyncCursor() };
    }

    const operationUserId = getActiveStorageUser();
    const startGeneration = getLockGeneration ? getLockGeneration() : 0;

    // Check if already locked before starting
    if (isUnlocked && !isUnlocked()) {
      return { appliedCount: 0, tombstoneCount: 0, newCursor: await getSyncCursor(operationUserId), cancelled: true };
    }

    this.isSyncing = true;
    this.currentAbortController = new AbortController();
    const signal = this.currentAbortController.signal;
    this.setStatus("syncing");

    let totalApplied = 0;
    let totalTombstones = 0;
    let cursor = await getSyncCursor(operationUserId);

    try {
      let hasMore = true;

      while (hasMore) {
        // Pre-fetch cancellation & user guard
        if (
          signal.aborted ||
          (isUnlocked && !isUnlocked()) ||
          (getLockGeneration && getLockGeneration() !== startGeneration) ||
          getActiveStorageUser() !== operationUserId
        ) {
          return { appliedCount: totalApplied, tombstoneCount: totalTombstones, newCursor: cursor, cancelled: true };
        }

        const response: SyncChangesResponseData = await syncApi.getChanges(cursor, 100, signal);
        const { changes, nextCursor, currentSyncVersion, hasMore: morePages } = response;

        // Post-network cancellation & user guard
        if (
          signal.aborted ||
          (isUnlocked && !isUnlocked()) ||
          (getLockGeneration && getLockGeneration() !== startGeneration) ||
          getActiveStorageUser() !== operationUserId
        ) {
          return { appliedCount: totalApplied, tombstoneCount: totalTombstones, newCursor: cursor, cancelled: true };
        }

        if (!changes || changes.length === 0) {
          if (currentSyncVersion >= cursor && getActiveStorageUser() === operationUserId && !signal.aborted) {
            await saveSyncCursor(currentSyncVersion, operationUserId);
            cursor = currentSyncVersion;
          }
          break;
        }

        const itemsToDecrypt: Array<{ record: EncryptedVaultRecord; revision: number }> = [];
        const tombstonesToDelete: string[] = [];

        // 1. Process batch: categorize into tombstones and active records
        for (const change of changes) {
          if (
            signal.aborted ||
            (isUnlocked && !isUnlocked()) ||
            (getLockGeneration && getLockGeneration() !== startGeneration) ||
            getActiveStorageUser() !== operationUserId
          ) {
            return { appliedCount: totalApplied, tombstoneCount: totalTombstones, newCursor: cursor, cancelled: true };
          }

          if (change.isDeleted) {
            tombstonesToDelete.push(change.id);
            await deleteEncryptedRecord(change.id, operationUserId);
            totalTombstones++;
          } else {
            const record: EncryptedVaultRecord = {
              id: change.id,
              userId: operationUserId || undefined,
              encryptedPayload: change.encryptedPayload,
              initializationVector: change.initializationVector,
              authenticationTag: change.authenticationTag,
              encryptionAlgorithm: change.encryptionAlgorithm as "AES-256-GCM",
              encryptionVersion: change.encryptionVersion as 1,
              revision: change.revision,
              syncVersion: change.syncVersion,
              createdAt: change.createdAt,
              updatedAt: change.updatedAt
            };

            await saveEncryptedRecord(record, operationUserId);
            itemsToDecrypt.push({ record, revision: change.revision });
            totalApplied++;
          }
        }

        // 2. Resolve current key and check lock state before decryption
        const currentKey = typeof keyOrGetKey === "function" ? keyOrGetKey() : keyOrGetKey;
        const canDecrypt =
          Boolean(currentKey) &&
          (!isUnlocked || isUnlocked()) &&
          (!getLockGeneration || getLockGeneration() === startGeneration) &&
          getActiveStorageUser() === operationUserId &&
          !signal.aborted;

        if (canDecrypt && onItemsUpdated && currentKey) {
          const newlyDecrypted: DecryptedVaultItem[] = [];

          for (const { record, revision } of itemsToDecrypt) {
            // Re-check lock state and user before each decryption step
            if (
              signal.aborted ||
              (isUnlocked && !isUnlocked()) ||
              (getLockGeneration && getLockGeneration() !== startGeneration) ||
              getActiveStorageUser() !== operationUserId
            ) {
              break;
            }

            try {
              const payload = await decryptVaultPayload<any>(record, currentKey);
              newlyDecrypted.push({
                id: record.id,
                service: payload.service || "Unnamed Service",
                username: payload.username || "",
                password: payload.password || "",
                category: payload.category || "Personal",
                health: payload.health || "Strong",
                favorite: Boolean(payload.favorite),
                notes: payload.notes || "",
                revision: revision,
                createdAt: record.createdAt,
                updatedAt: record.updatedAt
              });
            } catch {
              // Ignore single item decryption errors during sync pass
            }
          }

          // Strict final check before committing to in-memory React state
          const shouldCommit =
            !signal.aborted &&
            (!isUnlocked || isUnlocked()) &&
            (!getLockGeneration || getLockGeneration() === startGeneration) &&
            getActiveStorageUser() === operationUserId;

          if (shouldCommit) {
            onItemsUpdated((prev) => {
              if (getActiveStorageUser() !== operationUserId) return prev;
              let next = [...prev];

              // Handle tombstones in in-memory state
              if (tombstonesToDelete.length > 0) {
                const delSet = new Set(tombstonesToDelete);
                next = next.filter((item) => !delSet.has(item.id));
              }

              // Handle updated or newly added items
              for (const item of newlyDecrypted) {
                const idx = next.findIndex((existing) => existing.id === item.id);
                if (idx >= 0) {
                  next[idx] = item;
                } else {
                  next.unshift(item);
                }
              }

              return next;
            });
          }
        }

        // 3. Advance local cursor ONLY after batch has been processed and user is unchanged
        if (getActiveStorageUser() === operationUserId && !signal.aborted) {
          cursor = nextCursor;
          await saveSyncCursor(cursor, operationUserId);
        } else {
          return { appliedCount: totalApplied, tombstoneCount: totalTombstones, newCursor: cursor, cancelled: true };
        }

        hasMore = morePages && nextCursor > 0;
      }

      this.lastSyncTime = new Date();
      const result: SyncResult = {
        appliedCount: totalApplied,
        tombstoneCount: totalTombstones,
        newCursor: cursor
      };
      this.setStatus("idle", result);
      return result;
    } catch (err: any) {
      if (err?.name === "AbortError" || signal.aborted) {
        return { appliedCount: totalApplied, tombstoneCount: totalTombstones, newCursor: cursor, cancelled: true };
      }
      const result: SyncResult = {
        appliedCount: totalApplied,
        tombstoneCount: totalTombstones,
        newCursor: cursor,
        error: err?.message || "Sync failed"
      };
      this.setStatus("error", result);
      return result;
    } finally {
      this.currentAbortController = null;
      this.isSyncing = false;
    }
  }

  /**
   * Starts periodic polling sync (runs every 30 seconds when tab is active).
   */
  public startPeriodicSync(
    getKey: () => CryptoKey | null,
    onItemsUpdated: (updater: (prev: DecryptedVaultItem[]) => DecryptedVaultItem[]) => void,
    isUnlocked?: () => boolean,
    getLockGeneration?: () => number,
    intervalMs: number = 30000
  ): () => void {
    this.stopPeriodicSync();

    const run = () => {
      if (typeof document !== "undefined" && document.hidden) {
        return; // Pause during tab inactivity
      }
      if (isUnlocked && !isUnlocked()) {
        return; // Do not sync when locked
      }
      this.sync(getKey, onItemsUpdated, isUnlocked, getLockGeneration).catch(() => {});
    };

    run();

    this.intervalTimer = setInterval(run, intervalMs);

    const onVisibilityChange = () => {
      if (typeof document !== "undefined" && !document.hidden) {
        run();
      }
    };

    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", onVisibilityChange);
    }

    return () => {
      this.stopPeriodicSync();
      if (typeof document !== "undefined") {
        document.removeEventListener("visibilitychange", onVisibilityChange);
      }
    };
  }

  public stopPeriodicSync(): void {
    if (this.intervalTimer) {
      clearInterval(this.intervalTimer);
      this.intervalTimer = null;
    }
    this.cancelSync();
  }
}

export const syncEngine = new SyncEngine();
