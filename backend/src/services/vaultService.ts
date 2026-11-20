import prisma from "../config/db.js";
import { AppError } from "../utils/errors.js";
import type {
  CreateVaultItemInput,
  UpdateVaultItemInput,
  CreateVaultVerificationInput,
  BatchImportVaultInput
} from "../utils/vaultValidation.js";

export interface VaultVerificationResponse {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: string;
  encryptionVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface VaultRecoveryRecord {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: string;
  encryptionVersion: number;
  isDeleted: boolean;
}

export interface GetVerificationResult {
  hasVerification: boolean;
  hasItems: boolean;
  hasActiveItems: boolean;
  verification: VaultVerificationResponse | null;
  recoveryRecord?: VaultRecoveryRecord | null;
}

export interface VaultItemCreated {
  id: string;
  revision: number;
  syncVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface VaultItemUpdated {
  id: string;
  revision: number;
  syncVersion: number;
  updatedAt: string;
}

export interface VaultItemResponse {
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
}

export interface VaultItemDeleted {
  success: boolean;
  message: string;
  data?: {
    id: string;
    syncVersion: number;
  };
}

export class VaultService {
  /**
   * Stores a new encrypted vault item for the authenticated user.
   * Atomically increments the user's syncVersion and assigns it to the created VaultItem.
   * Decodes Base64 payloads into binary buffers for MySQL storage.
   * Never attempts decryption.
   */
  async createItem(userId: string, input: CreateVaultItemInput): Promise<VaultItemCreated> {
    const encryptedPayload = Buffer.from(input.encryptedPayload, "base64");
    const initializationVector = Buffer.from(input.initializationVector, "base64");
    const authenticationTag = Buffer.from(input.authenticationTag, "base64");

    return await prisma.$transaction(async (tx) => {
      // 1. Atomically increment user's syncVersion
      const user = await tx.user.update({
        where: { id: userId },
        data: { syncVersion: { increment: 1 } },
        select: { syncVersion: true }
      });
      const newSyncVersion = user.syncVersion;

      // 2. Create the VaultItem with the newly assigned syncVersion
      const item = await tx.vaultItem.create({
        data: {
          userId,
          encryptedPayload,
          initializationVector,
          authenticationTag,
          encryptionAlgorithm: input.encryptionAlgorithm,
          encryptionVersion: input.encryptionVersion,
          revision: 1,
          syncVersion: newSyncVersion
        },
        select: {
          id: true,
          revision: true,
          syncVersion: true,
          createdAt: true,
          updatedAt: true
        }
      });

      return {
        id: item.id,
        revision: item.revision,
        syncVersion: item.syncVersion,
        createdAt: item.createdAt.toISOString(),
        updatedAt: item.updatedAt.toISOString()
      };
    });
  }

  /**
   * Atomically imports an array of encrypted vault items within a single database transaction.
   * Handles duplicate detection, collision resolution (error vs skip), and atomic syncVersion progression.
   */
  async batchImport(
    userId: string,
    input: BatchImportVaultInput
  ): Promise<{
    insertedCount: number;
    skippedCount: number;
    totalProcessed: number;
    syncVersion: number;
    items: Array<{ id: string; revision: number; syncVersion: number }>;
  }> {
    // 1. Detect duplicates within the import payload itself
    const seenIds = new Set<string>();
    for (const item of input.items) {
      if (item.id) {
        if (seenIds.has(item.id)) {
          throw new AppError(`Duplicate item ID within import payload: ${item.id}`, 409);
        }
        seenIds.add(item.id);
      }
    }

    return await prisma.$transaction(async (tx) => {
      // 2. Fetch existing items for this user matching incoming IDs
      const itemIds = Array.from(seenIds);
      const existingItems =
        itemIds.length > 0
          ? await tx.vaultItem.findMany({
              where: {
                userId,
                id: { in: itemIds }
              }
            })
          : [];

      const existingMap = new Map(existingItems.map((i) => [i.id, i]));

      // 3. Atomically increment user's syncVersion once for the entire batch
      const user = await tx.user.update({
        where: { id: userId },
        data: { syncVersion: { increment: 1 } },
        select: { syncVersion: true }
      });
      const newSyncVersion = user.syncVersion;

      let insertedCount = 0;
      let skippedCount = 0;
      const resultItems: Array<{ id: string; revision: number; syncVersion: number }> = [];

      for (const item of input.items) {
        const id = item.id || crypto.randomUUID();
        const existing = existingMap.get(id);

        if (existing) {
          // Check if payload is identical
          const isIdentical =
            Buffer.from(existing.encryptedPayload).equals(Buffer.from(item.encryptedPayload, "base64")) &&
            Buffer.from(existing.initializationVector).equals(Buffer.from(item.initializationVector, "base64")) &&
            Buffer.from(existing.authenticationTag).equals(Buffer.from(item.authenticationTag, "base64")) &&
            existing.revision === (item.revision || 1);

          if (isIdentical) {
            skippedCount++;
            resultItems.push({ id: existing.id, revision: existing.revision, syncVersion: existing.syncVersion });
            continue;
          }

          if (input.strategy === "skip") {
            skippedCount++;
            resultItems.push({ id: existing.id, revision: existing.revision, syncVersion: existing.syncVersion });
            continue;
          }

          // Default strategy: error on conflict
          throw new AppError(`Conflict: Record with ID ${id} already exists with differing revision or data.`, 409);
        }

        // New record insertion
        const encryptedPayload = Buffer.from(item.encryptedPayload, "base64");
        const initializationVector = Buffer.from(item.initializationVector, "base64");
        const authenticationTag = Buffer.from(item.authenticationTag, "base64");
        const createdAt = item.createdAt ? new Date(item.createdAt) : new Date();
        const updatedAt = item.updatedAt ? new Date(item.updatedAt) : new Date();

        const created = await tx.vaultItem.create({
          data: {
            id,
            userId,
            encryptedPayload,
            initializationVector,
            authenticationTag,
            encryptionAlgorithm: item.encryptionAlgorithm,
            encryptionVersion: item.encryptionVersion,
            revision: item.revision || 1,
            syncVersion: newSyncVersion,
            createdAt,
            updatedAt
          },
          select: {
            id: true,
            revision: true,
            syncVersion: true
          }
        });

        insertedCount++;
        resultItems.push(created);
      }

      return {
        insertedCount,
        skippedCount,
        totalProcessed: input.items.length,
        syncVersion: newSyncVersion,
        items: resultItems
      };
    });
  }

  /**
   * Lists all active (non-deleted) encrypted vault items for the authenticated user.
   * Converts database binary blobs back to canonical Base64 strings.
   * Never decrypts payloads.
   */
  async listItems(userId: string): Promise<VaultItemResponse[]> {
    const items = await prisma.vaultItem.findMany({
      where: {
        userId,
        deletedAt: null
      },
      orderBy: {
        updatedAt: "desc"
      },
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
        updatedAt: true
      }
    });

    return items.map((item) => ({
      id: item.id,
      encryptedPayload: Buffer.from(item.encryptedPayload).toString("base64"),
      initializationVector: Buffer.from(item.initializationVector).toString("base64"),
      authenticationTag: Buffer.from(item.authenticationTag).toString("base64"),
      encryptionAlgorithm: item.encryptionAlgorithm,
      encryptionVersion: item.encryptionVersion,
      revision: item.revision,
      syncVersion: item.syncVersion,
      createdAt: item.createdAt.toISOString(),
      updatedAt: item.updatedAt.toISOString()
    }));
  }

  /**
   * Retrieves a single active encrypted vault item by ID.
   * Strictly verifies ownership via userId.
   * Never discloses whether another user's item exists (returns 404).
   */
  async getItemById(userId: string, id: string): Promise<VaultItemResponse> {
    const item = await prisma.vaultItem.findFirst({
      where: {
        id,
        userId,
        deletedAt: null
      },
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
        updatedAt: true
      }
    });

    if (!item) {
      throw new AppError("Vault item not found.", 404);
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
      updatedAt: item.updatedAt.toISOString()
    };
  }

  /**
   * Atomically updates an encrypted vault item with optimistic concurrency control.
   * Increments revision by exactly one if expectedRevision matches.
   * Increments user syncVersion and assigns it to the item atomically on success.
   * Distinguishes safely between 404 (missing/unowned/deleted) and 409 (revision conflict).
   */
  async updateItem(
    userId: string,
    id: string,
    input: UpdateVaultItemInput
  ): Promise<VaultItemUpdated> {
    const encryptedPayload = Buffer.from(input.encryptedPayload, "base64");
    const initializationVector = Buffer.from(input.initializationVector, "base64");
    const authenticationTag = Buffer.from(input.authenticationTag, "base64");

    const now = new Date();

    return await prisma.$transaction(async (tx) => {
      // 1. Atomically increment user's syncVersion
      const user = await tx.user.update({
        where: { id: userId },
        data: { syncVersion: { increment: 1 } },
        select: { syncVersion: true }
      });
      const newSyncVersion = user.syncVersion;

      // 2. Perform conditional update on item requiring expectedRevision and not deleted
      const updateResult = await tx.vaultItem.updateMany({
        where: {
          id,
          userId,
          revision: input.expectedRevision,
          deletedAt: null
        },
        data: {
          encryptedPayload,
          initializationVector,
          authenticationTag,
          encryptionAlgorithm: input.encryptionAlgorithm,
          encryptionVersion: input.encryptionVersion,
          revision: { increment: 1 },
          syncVersion: newSyncVersion,
          updatedAt: now
        }
      });

      if (updateResult.count === 0) {
        // Safe check within the user's scope to distinguish 404 from 409
        const existing = await tx.vaultItem.findFirst({
          where: {
            id,
            userId,
            deletedAt: null
          },
          select: {
            id: true,
            revision: true
          }
        });

        if (!existing) {
          throw new AppError("Vault item not found.", 404);
        }

        // Conflict: Item exists and is owned by user, but revision did not match
        throw new AppError(
          `Conflict: Vault item has been modified by another request. Current revision is ${existing.revision}, expected ${input.expectedRevision}.`,
          409
        );
      }

      return {
        id,
        revision: input.expectedRevision + 1,
        syncVersion: newSyncVersion,
        updatedAt: now.toISOString()
      };
    });
  }

  /**
   * Soft-deletes a vault item by setting deletedAt to the current timestamp.
   * Increments revision and assigns a new syncVersion for tombstone synchronization.
   * Returns 404 for missing, unowned, or already deleted items.
   */
  async deleteItem(userId: string, id: string): Promise<VaultItemDeleted> {
    const now = new Date();

    return await prisma.$transaction(async (tx) => {
      // 1. Atomically increment user's syncVersion
      const user = await tx.user.update({
        where: { id: userId },
        data: { syncVersion: { increment: 1 } },
        select: { syncVersion: true }
      });
      const newSyncVersion = user.syncVersion;

      // 2. Soft-delete the item
      const result = await tx.vaultItem.updateMany({
        where: {
          id,
          userId,
          deletedAt: null
        },
        data: {
          deletedAt: now,
          revision: { increment: 1 },
          syncVersion: newSyncVersion,
          updatedAt: now
        }
      });

      if (result.count === 0) {
        throw new AppError("Vault item not found.", 404);
      }

      return {
        success: true,
        message: "Vault item deleted successfully.",
        data: {
          id,
          syncVersion: newSyncVersion
        }
      };
    });
  }

  /**
   * Retrieves the server verification status and record for the authenticated user.
   * Also checks whether the user has existing active or tombstone vault items.
   * Phase 9.2.1 (Fix C): Returns accurate hasActiveItems and safe encrypted recoveryRecord if available.
   */
  async getVerification(userId: string): Promise<GetVerificationResult> {
    const [verification, totalItemCount, activeItemCount] = await Promise.all([
      prisma.vaultVerification.findUnique({
        where: { userId }
      }),
      prisma.vaultItem.count({
        where: { userId }
      }),
      prisma.vaultItem.count({
        where: { userId, deletedAt: null }
      })
    ]);

    const hasVerification = verification !== null;
    const hasItems = totalItemCount > 0;
    const hasActiveItems = activeItemCount > 0;

    let verificationData: VaultVerificationResponse | null = null;
    if (verification) {
      verificationData = {
        id: verification.id,
        encryptedPayload: Buffer.from(verification.encryptedPayload).toString("base64"),
        initializationVector: Buffer.from(verification.initializationVector).toString("base64"),
        authenticationTag: Buffer.from(verification.authenticationTag).toString("base64"),
        encryptionAlgorithm: verification.encryptionAlgorithm,
        encryptionVersion: verification.encryptionVersion,
        createdAt: verification.createdAt.toISOString(),
        updatedAt: verification.updatedAt.toISOString()
      };
    }

    // Phase 9.2.1 (Fix C): If no verification canary exists but vault has items (active or soft-deleted),
    // safely provide an encrypted recovery item for local master password verification on authorized devices.
    let recoveryRecord: VaultRecoveryRecord | null = null;
    if (!hasVerification && hasItems) {
      // Prefer an active item first; if all are soft-deleted, use the earliest item
      let item = await prisma.vaultItem.findFirst({
        where: { userId, deletedAt: null },
        orderBy: { createdAt: "asc" }
      });
      if (!item) {
        item = await prisma.vaultItem.findFirst({
          where: { userId },
          orderBy: { createdAt: "asc" }
        });
      }

      if (item && item.encryptedPayload && item.initializationVector && item.authenticationTag) {
        recoveryRecord = {
          id: item.id,
          encryptedPayload: Buffer.from(item.encryptedPayload).toString("base64"),
          initializationVector: Buffer.from(item.initializationVector).toString("base64"),
          authenticationTag: Buffer.from(item.authenticationTag).toString("base64"),
          encryptionAlgorithm: item.encryptionAlgorithm,
          encryptionVersion: item.encryptionVersion,
          isDeleted: item.deletedAt !== null
        };
      }
    }

    return {
      hasVerification,
      hasItems,
      hasActiveItems,
      verification: verificationData,
      recoveryRecord
    };
  }

  /**
   * Creates the encrypted verification record for the user.
   * Enforces create-once semantics:
   * - If a verification record already exists, rejects with 409 Conflict.
   * - If the vault contains existing items:
   *   - If isLegacyMigration is not true, rejects with 409 Conflict.
   *   - If isLegacyMigration is true, independently authorizes that the request originates
   *     from the user's original enrolled legacy device. Rejecting unauthorized devices with 403 Forbidden.
   */
  async createVerification(
    userId: string,
    sessionIdOrInput: string | CreateVaultVerificationInput,
    possibleInput?: CreateVaultVerificationInput
  ): Promise<VaultVerificationResponse> {
    let sessionId: string | undefined;
    let input: CreateVaultVerificationInput;

    if (typeof sessionIdOrInput === "string") {
      sessionId = sessionIdOrInput;
      input = possibleInput!;
    } else {
      input = sessionIdOrInput;
    }

    const encryptedPayload = Buffer.from(input.encryptedPayload, "base64");
    const initializationVector = Buffer.from(input.initializationVector, "base64");
    const authenticationTag = Buffer.from(input.authenticationTag, "base64");

    return await prisma.$transaction(async (tx) => {
      // 1. Check if verification already exists
      const existing = await tx.vaultVerification.findUnique({
        where: { userId }
      });

      if (existing) {
        throw new AppError("Verification record already exists for this user. Cannot overwrite.", 409);
      }

      // 2. Check existing items for legacy protection
      const itemCount = await tx.vaultItem.count({
        where: { userId }
      });

      if (itemCount > 0) {
        if (!input.isLegacyMigration) {
          throw new AppError(
            "Vault contains existing items. New vault initialization not permitted. Legacy migration required.",
            409
          );
        }

        // Phase 9.2.2 (Fix A & Fix B): Server-side legacy migration device & transactional session authorization
        if (!sessionId) {
          throw new AppError("Forbidden: Unauthorized or missing session context for legacy migration.", 403);
        }

        // 1. First look up the session's deviceId
        const sessionMeta = await tx.session.findFirst({
          where: { id: sessionId, userId },
          select: { id: true, deviceId: true }
        });

        if (!sessionMeta) {
          throw new AppError("Forbidden: Unauthorized, expired, or invalid session context.", 403);
        }

        // 2. Phase 9.2.2 (Fix B): Acquire row locks in consistent global hierarchy order (devices -> sessions)
        // Explicitly lock the device record with FOR UPDATE
        const lockedDevices = await tx.$queryRaw<Array<{ id: string; removedAt: Date | string | null; createdAt: Date | string }>>`
          SELECT id, removedAt, createdAt FROM devices WHERE id = ${sessionMeta.deviceId} AND userId = ${userId} FOR UPDATE
        `;
        const lockedDevice = lockedDevices && lockedDevices.length > 0 ? lockedDevices[0] : null;

        if (!lockedDevice || lockedDevice.removedAt !== null) {
          throw new AppError("Forbidden: Session device has been removed.", 403);
        }

        // Explicitly lock the session record with FOR UPDATE
        const lockedSessions = await tx.$queryRaw<Array<{ id: string; userId: string; deviceId: string; expiresAt: Date | string; revokedAt: Date | string | null }>>`
          SELECT id, userId, deviceId, expiresAt, revokedAt FROM sessions WHERE id = ${sessionId} AND userId = ${userId} FOR UPDATE
        `;
        const lockedSession = lockedSessions && lockedSessions.length > 0 ? lockedSessions[0] : null;
        const now = new Date();
        const sessionExpiresAt = lockedSession ? new Date(lockedSession.expiresAt) : null;

        if (
          !lockedSession ||
          lockedSession.revokedAt !== null ||
          !sessionExpiresAt ||
          sessionExpiresAt.getTime() <= now.getTime()
        ) {
          throw new AppError("Forbidden: Unauthorized, expired, or invalid session context.", 403);
        }

        // 3. Phase 9.2.2 (Fix A): Determine durable historical original device identity across ALL devices (including soft-deleted)
        const historicalOriginalDevice = await tx.device.findFirst({
          where: {
            userId
          },
          orderBy: {
            createdAt: "asc"
          }
        });

        const isHistoricalOriginalDevice = historicalOriginalDevice && lockedDevice.id === historicalOriginalDevice.id;

        // Strict enforcement: Only the authentic historical original device is authorized.
        // The isDevicePreItem fallback is removed completely. Soft-deleting the original device does NOT transfer authority.
        if (!isHistoricalOriginalDevice) {
          throw new AppError(
            "Forbidden: Legacy migration can only be authorized from the user's original enrolled device.",
            403
          );
        }

        // Defensive check: The calling device must not be removed
        if (lockedDevice.removedAt !== null) {
          throw new AppError(
            "Forbidden: Cannot perform legacy migration from a removed device.",
            403
          );
        }
      }

      // 3. Create the verification record
      try {
        const created = await tx.vaultVerification.create({
          data: {
            userId,
            encryptedPayload,
            initializationVector,
            authenticationTag,
            encryptionAlgorithm: input.encryptionAlgorithm || "AES-256-GCM",
            encryptionVersion: input.encryptionVersion || 1
          }
        });

        return {
          id: created.id,
          encryptedPayload: input.encryptedPayload,
          initializationVector: input.initializationVector,
          authenticationTag: input.authenticationTag,
          encryptionAlgorithm: created.encryptionAlgorithm,
          encryptionVersion: created.encryptionVersion,
          createdAt: created.createdAt.toISOString(),
          updatedAt: created.updatedAt.toISOString()
        };
      } catch (err: any) {
        if (err?.code === "P2002") {
          throw new AppError("Verification record already exists for this user. Cannot overwrite.", 409);
        }
        throw err;
      }
    });
  }
}

export const vaultService = new VaultService();

