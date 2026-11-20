import prisma from "../config/db.js";
import { AppError } from "../utils/errors.js";
import type { SyncChangesQuery } from "../utils/syncValidation.js";

export interface ActiveVaultChange {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: string;
  encryptionVersion: number;
  revision: number;
  syncVersion: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: null;
  isDeleted: false;
}

export interface DeletedVaultChange {
  id: string;
  revision: number;
  syncVersion: number;
  deletedAt: string;
  isDeleted: true;
}

export type VaultChange = ActiveVaultChange | DeletedVaultChange;

export interface SyncChangesResult {
  changes: VaultChange[];
  nextCursor: number;
  currentSyncVersion: number;
  hasMore: boolean;
}

export class SyncService {
  /**
   * Retrieves incremental vault changes for the authenticated user.
   *
   * Synchronization invariants:
   * 1. Captures currentSyncVersion as high-water mark before querying changes to prevent race conditions.
   * 2. Returns records strictly ordered by syncVersion ascending.
   * 3. Scopes strictly to the authenticated user.
   * 4. Includes tombstones for deleted records with isDeleted: true.
   * 5. Uses limit + 1 pagination to prevent skipping records.
   * 6. Advances nextCursor to last delivered syncVersion when more pages exist,
   *    or to currentSyncVersion when all pages are consumed.
   */
  async getChanges(userId: string, query: SyncChangesQuery): Promise<SyncChangesResult> {
    // 1. Capture high-water mark from authenticated user
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { syncVersion: true, accountStatus: true }
    });

    if (!user || user.accountStatus !== "ACTIVE") {
      throw new AppError("User account not found or is inactive.", 404);
    }

    const currentSyncVersion = user.syncVersion;

    // 2. Reject cursor greater than current syncVersion
    if (query.since > currentSyncVersion) {
      throw new AppError(
        `Synchronization cursor 'since' (${query.since}) cannot be greater than the current syncVersion (${currentSyncVersion}).`,
        400
      );
    }

    // Short-circuit if cursor already equals currentSyncVersion
    if (query.since === currentSyncVersion) {
      return {
        changes: [],
        nextCursor: currentSyncVersion,
        currentSyncVersion,
        hasMore: false
      };
    }

    // 3. Fetch changes bounded by since < syncVersion <= currentSyncVersion
    const records = await prisma.vaultItem.findMany({
      where: {
        userId,
        syncVersion: {
          gt: query.since,
          lte: currentSyncVersion
        }
      },
      orderBy: {
        syncVersion: "asc"
      },
      take: query.limit + 1,
      select: {
        id: true,
        encryptedPayload: true,
        initializationVector: true,
        authenticationTag: true,
        encryptionAlgorithm: true,
        encryptionVersion: true,
        revision: true,
        syncVersion: true,
        createdAt: true,
        updatedAt: true,
        deletedAt: true
      }
    });

    // 4. Determine pagination boundaries
    const hasMore = records.length > query.limit;
    const pageRecords = hasMore ? records.slice(0, query.limit) : records;

    let nextCursor = currentSyncVersion;
    if (hasMore && pageRecords.length > 0) {
      nextCursor = pageRecords[pageRecords.length - 1].syncVersion;
    }

    // 5. Format active items and tombstones
    const changes: VaultChange[] = pageRecords.map((item) => {
      if (item.deletedAt !== null) {
        return {
          id: item.id,
          revision: item.revision,
          syncVersion: item.syncVersion,
          deletedAt: item.deletedAt.toISOString(),
          isDeleted: true
        };
      }

      return {
        id: item.id,
        encryptedPayload: Buffer.from(item.encryptedPayload).toString("base64"),
        initializationVector: Buffer.from(item.initializationVector).toString("base64"),
        authenticationTag: Buffer.from(item.authenticationTag).toString("base64"),
        encryptionAlgorithm: item.encryptionAlgorithm,
        encryptionVersion: item.encryptionVersion,
        revision: item.revision,
        syncVersion: item.syncVersion,
        createdAt: item.createdAt.toISOString(),
        updatedAt: item.updatedAt.toISOString(),
        deletedAt: null,
        isDeleted: false
      };
    });

    return {
      changes,
      nextCursor,
      currentSyncVersion,
      hasMore
    };
  }
}

export const syncService = new SyncService();
