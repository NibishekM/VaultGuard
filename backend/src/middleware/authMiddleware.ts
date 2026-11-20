import type { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "../utils/jwt.js";
import prisma from "../config/db.js";
import { validateSession } from "../services/sessionService.js";

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Express middleware requiring a valid Bearer JWT.
 * Verifies:
 * 1. Bearer token presence and format.
 * 2. Token cryptographic signature and HS256 algorithm.
 * 3. Token expiration.
 * 4. Mandatory, valid session ID (sid) claim (rejects legacy Phase 4 / malformed tokens).
 * 5. User existence in the database via the token subject.
 * 6. Account status (rejects LOCKED and DISABLED users).
 * 7. Session validity: session must exist, not be revoked, not expired,
 *    and device must not have been removed.
 *
 * Attaches the verified { id, email } to req.user and { id } to req.session.
 */
export const requireAuth = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      success: false,
      message: "Authentication required: Missing or malformed Bearer token."
    });
    return;
  }

  const token = authHeader.substring(7).trim();

  if (!token) {
    res.status(401).json({
      success: false,
      message: "Authentication required: Bearer token is empty."
    });
    return;
  }

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch (error: any) {
    if (error.name === "TokenExpiredError") {
      res.status(401).json({
        success: false,
        message: "Authentication token has expired. Please log in again."
      });
      return;
    }

    res.status(401).json({
      success: false,
      message: "Invalid authentication token."
    });
    return;
  }

  // Phase 6.1 (SEC-P6-02): Enforce mandatory, valid session identifier claim
  if (!payload.sid || typeof payload.sid !== "string" || !UUID_REGEX.test(payload.sid.trim())) {
    res.status(401).json({
      success: false,
      message: "Authentication token is missing a valid session identifier. Please log in again."
    });
    return;
  }

  try {
    // Load and verify the user identity from the verified token subject
    const user = await prisma.user.findUnique({
      where: { id: payload.sub },
      select: {
        id: true,
        email: true,
        accountStatus: true
      }
    });

    if (!user) {
      res.status(401).json({
        success: false,
        message: "Authentication failed: User account no longer exists."
      });
      return;
    }

    if (user.accountStatus !== "ACTIVE") {
      res.status(403).json({
        success: false,
        message: "Access denied: Account is locked or disabled."
      });
      return;
    }

    // Phase 6.1 (SEC-P6-02): Unconditionally validate session against the database
    try {
      await validateSession(payload.sid, user.id);
    } catch (sessionError: any) {
      res.status(401).json({
        success: false,
        message: sessionError.message || "Session is no longer valid. Please log in again."
      });
      return;
    }

    // Attach verified session context to request
    req.session = { id: payload.sid };

    // Attach verified user identity to the request (never trust body-supplied userIds)
    req.user = {
      id: user.id,
      email: user.email
    };

    next();
  } catch (dbError) {
    next(dbError);
  }
};
