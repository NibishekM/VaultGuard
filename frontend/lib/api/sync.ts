/**
 * VaultGuard – Vault Synchronization API Service (Phase 9)
 *
 * Implements incremental synchronization calls against /api/sync/changes.
 */

import { apiClient } from "./client";
import type { ApiResponse, SyncChangesResponseData } from "./types";

export const syncApi = {
  /**
   * Fetches incremental vault changes and tombstones since a specific cursor.
   * Supports optional AbortSignal for immediate cancellation when locking.
   */
  async getChanges(since: number = 0, limit: number = 100, signal?: AbortSignal): Promise<SyncChangesResponseData> {
    const params = new URLSearchParams({
      since: since.toString(),
      limit: limit.toString()
    });

    const res = await apiClient<ApiResponse<SyncChangesResponseData> & SyncChangesResponseData>(
      `/api/sync/changes?${params.toString()}`,
      {
        method: "GET",
        signal
      }
    );

    // Backend responds with { success: true, changes: [...], nextCursor, currentSyncVersion, hasMore }
    return {
      changes: res.changes || res.data?.changes || [],
      nextCursor: res.nextCursor ?? res.data?.nextCursor ?? since,
      currentSyncVersion: res.currentSyncVersion ?? res.data?.currentSyncVersion ?? since,
      hasMore: Boolean(res.hasMore ?? res.data?.hasMore)
    };
  }
};
