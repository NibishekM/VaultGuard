import crypto from "crypto";
import prisma from "../config/db.js";
import { generateAccessToken } from "../utils/jwt.js";
import { AppError } from "../utils/errors.js";

// Refresh token TTL: 30 days
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
// Access token TTL: 15 minutes (mirror of JWT_EXPIRES_IN)
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // Session matches refresh token lifetime
// Throttle lastUsedAt DB write to once per 60 seconds
const LAST_USED_THROTTLE_MS = 60 * 1000;

// In-flight refresh tracking to safely prevent concurrent refresh races from false-positive replay revocation
const inFlightRefreshes = new Set<string>();

export interface DeviceInput {
  deviceIdentifier?: string;
  deviceName?: string;
}

export interface SessionResult {
  sessionId: string;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
}

/**
 * Generates a cryptographically random refresh token (32 bytes = 256 bits).
 * Returns both the plaintext token (sent to client once) and its SHA-256 hash (stored in DB).
 */
function generateRefreshToken(): { plaintext: string; hash: string } {
  const plaintext = crypto.randomBytes(32).toString("hex"); // 64 hex chars
  const hash = crypto.createHash("sha256").update(plaintext).digest("hex");
  return { plaintext, hash };
}

/**
 * Hashes a plaintext refresh token with SHA-256.
 */
function hashRefreshToken(plaintext: string): string {
  return crypto.createHash("sha256").update(plaintext).digest("hex");
}

/**
 * Upserts a device record and creates a new session + refresh token.
 * Returns session ID, plaintext refresh token (send to client exactly once), and expiry.
 */
export async function createDeviceAndSession(
  userId: string,
  deviceInput: DeviceInput
): Promise<SessionResult> {
  const now = new Date();
  const sessionExpiresAt = new Date(now.getTime() + SESSION_TTL_MS);
  const refreshExpiresAt = new Date(now.getTime() + REFRESH_TOKEN_TTL_MS);

  // Provide a stable default deviceIdentifier for clients that omit it
  const deviceIdentifier = deviceInput.deviceIdentifier || "default";
  const deviceName = deviceInput.deviceName || null;

  // Upsert the device (create or update lastSeenAt)
  const device = await prisma.device.upsert({
    where: {
      userId_deviceIdentifier: { userId, deviceIdentifier }
    },
    create: {
      userId,
      deviceIdentifier,
      deviceName,
      lastSeenAt: now
    },
    update: {
      lastSeenAt: now,
      // Restore a previously removed device if the user logs in again from the same identifier
      removedAt: null
    }
  });

  const { plaintext, hash } = generateRefreshToken();

  // Create session and refresh token in a single transaction
  const session = await prisma.session.create({
    data: {
      userId,
      deviceId: device.id,
      expiresAt: sessionExpiresAt,
      refreshTokens: {
        create: {
          tokenHash: hash,
          expiresAt: refreshExpiresAt
        }
      }
    }
  });

  return {
    sessionId: session.id,
    refreshToken: plaintext,
    refreshTokenExpiresAt: refreshExpiresAt
  };
}

/**
 * Validates an active session by ID and userId.
 * - Session must exist for the given user.
 * - Session must not be revoked.
 * - Session must not be expired.
 * - Associated device must not have been removed (soft-deleted).
 *
 * Performs a throttled lastUsedAt update (at most once per 60 seconds).
 *
 * @throws AppError 401 if session is invalid.
 */
export async function validateSession(sessionId: string, userId: string): Promise<void> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { device: { select: { removedAt: true } } }
  });

  if (!session || session.userId !== userId) {
    throw new AppError("Session not found or access denied.", 401);
  }

  if (session.revokedAt !== null) {
    throw new AppError("Session has been revoked. Please log in again.", 401);
  }

  const now = new Date();
  if (session.expiresAt < now) {
    throw new AppError("Session has expired. Please log in again.", 401);
  }

  if (session.device.removedAt !== null) {
    throw new AppError("This device has been removed. Please log in again.", 401);
  }

  // Throttle lastUsedAt update to avoid a DB write on every request
  const timeSinceLastUsed = now.getTime() - session.lastUsedAt.getTime();
  if (timeSinceLastUsed > LAST_USED_THROTTLE_MS) {
    // Fire-and-forget update — do not await to avoid adding latency to the request
    prisma.session
      .update({ where: { id: sessionId }, data: { lastUsedAt: now } })
      .catch(() => { /* non-critical */ });
  }
}

/**
 * Rotates a refresh token (single-use enforcement with replay detection and concurrency safety).
 *
 * Process:
 * 1. Checks in-memory in-flight set to catch concurrent refresh requests for the same token.
 * 2. Within a database transaction:
 *    - Looks up the token record by SHA-256 hash.
 *    - Replay detection: If token was previously consumed in a completed rotation, revokes entire session.
 *    - Validates token revocation, token expiration, session status, device status, and account status.
 *    - Executes conditional atomic update:
 *        updateMany({ where: { id: existing.id, consumedAt: null, revokedAt: null }, data: { consumedAt: now } })
 *    - Verifies affected row count === 1. If 0, rejects without issuing duplicate tokens.
 *    - Generates new rotating refresh token and creates DB record.
 *    - Updates session lastUsedAt.
 *    - Issues signed access token with sid claim.
 *
 * @returns new access token, new plaintext refresh token, and expiry.
 */
export async function rotateRefreshToken(plaintext: string): Promise<{
  accessToken: string;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
  sessionId: string;
}> {
  const hash = hashRefreshToken(plaintext);

  // Concurrency Guard: Detect simultaneous in-flight refresh requests for the same token
  if (inFlightRefreshes.has(hash)) {
    throw new AppError("Refresh token rotation is already in progress. Please retry.", 409);
  }

  inFlightRefreshes.add(hash);

  try {
    return await prisma.$transaction(async (tx) => {
      const existing = await tx.refreshToken.findUnique({
        where: { tokenHash: hash },
        include: {
          session: {
            include: {
              user: { select: { id: true, email: true, accountStatus: true } },
              device: { select: { removedAt: true } }
            }
          }
        }
      });

      if (!existing) {
        throw new AppError("Invalid refresh token.", 401);
      }

      const now = new Date();

      // Replay attack: token was previously consumed in a completed cycle — revoke entire session
      if (existing.consumedAt !== null) {
        await prisma.session.update({
          where: { id: existing.sessionId },
          data: { revokedAt: now }
        });
        // Also revoke all refresh tokens for this session
        await prisma.refreshToken.updateMany({
          where: { sessionId: existing.sessionId, revokedAt: null },
          data: { revokedAt: now }
        });
        throw new AppError("Refresh token replay detected. Session has been revoked for security.", 401);
      }

      if (existing.revokedAt !== null) {
        throw new AppError("Refresh token has been revoked.", 401);
      }

      if (existing.expiresAt < now) {
        throw new AppError("Refresh token has expired. Please log in again.", 401);
      }

      const session = existing.session;

      if (session.revokedAt !== null) {
        throw new AppError("Session has been revoked. Please log in again.", 401);
      }

      if (session.expiresAt < now) {
        throw new AppError("Session has expired. Please log in again.", 401);
      }

      if (session.device.removedAt !== null) {
        throw new AppError("This device has been removed. Please log in again.", 401);
      }

      if (session.user.accountStatus !== "ACTIVE") {
        throw new AppError("Account is locked or disabled.", 403);
      }

      // Step 5: Conditional database update ensuring exactly one concurrent request can consume the token
      const consumeResult = await tx.refreshToken.updateMany({
        where: {
          id: existing.id,
          consumedAt: null,
          revokedAt: null
        },
        data: {
          consumedAt: now
        }
      });

      // Step 6 & 7: If conditional update affects zero rows, reject without issuing another token
      if (consumeResult.count === 0) {
        throw new AppError("Refresh token was consumed concurrently. Please use your newly issued token.", 409);
      }

      const refreshExpiresAt = new Date(now.getTime() + REFRESH_TOKEN_TTL_MS);
      const { plaintext: newPlaintext, hash: newHash } = generateRefreshToken();

      // Atomically create new token and update session lastUsedAt
      await tx.refreshToken.create({
        data: {
          sessionId: session.id,
          tokenHash: newHash,
          expiresAt: refreshExpiresAt
        }
      });

      await tx.session.update({
        where: { id: session.id },
        data: { lastUsedAt: now }
      });

      const accessToken = generateAccessToken({
        sub: session.user.id,
        email: session.user.email,
        sid: session.id
      });

      return {
        accessToken,
        refreshToken: newPlaintext,
        refreshTokenExpiresAt: refreshExpiresAt,
        sessionId: session.id
      };
    });
  } finally {
    inFlightRefreshes.delete(hash);
  }
}

/**
 * Revokes a single session and all its refresh tokens.
 * Ownership check: session must belong to the given userId.
 */
export async function revokeSession(sessionId: string, userId: string): Promise<void> {
  const session = await prisma.session.findUnique({ where: { id: sessionId } });

  if (!session || session.userId !== userId) {
    throw new AppError("Session not found or access denied.", 404);
  }

  const now = new Date();

  await prisma.$transaction([
    prisma.session.update({
      where: { id: sessionId },
      data: { revokedAt: now }
    }),
    prisma.refreshToken.updateMany({
      where: { sessionId, revokedAt: null, consumedAt: null },
      data: { revokedAt: now }
    })
  ]);
}

/**
 * Removes a device: sets removedAt soft-delete, then revokes all sessions and
 * refresh tokens linked to that device.
 * Ownership check: device must belong to userId.
 * Prevents removing the device hosting the current session.
 */
export async function revokeDeviceSessions(
  deviceId: string,
  userId: string,
  currentSessionId: string
): Promise<void> {
  const device = await prisma.device.findUnique({ where: { id: deviceId } });

  if (!device || device.userId !== userId) {
    throw new AppError("Device not found or access denied.", 404);
  }

  if (device.removedAt !== null) {
    throw new AppError("Device has already been removed.", 409);
  }

  // Prevent removing the device associated with the current active session
  const currentSession = await prisma.session.findUnique({ where: { id: currentSessionId } });
  if (currentSession && currentSession.deviceId === deviceId) {
    throw new AppError(
      "Cannot remove the device you are currently logged in from. Use logout instead.",
      409
    );
  }

  const now = new Date();

  // Find all sessions for this device
  const deviceSessions = await prisma.session.findMany({
    where: { deviceId, userId },
    select: { id: true }
  });
  const sessionIds = deviceSessions.map((s) => s.id);

  await prisma.$transaction([
    prisma.device.update({
      where: { id: deviceId },
      data: { removedAt: now }
    }),
    prisma.session.updateMany({
      where: { id: { in: sessionIds }, revokedAt: null },
      data: { revokedAt: now }
    }),
    prisma.refreshToken.updateMany({
      where: { sessionId: { in: sessionIds }, revokedAt: null, consumedAt: null },
      data: { revokedAt: now }
    })
  ]);
}
