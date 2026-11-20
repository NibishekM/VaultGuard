import type { Request, Response, NextFunction } from "express";
import { authService } from "../services/authService.js";
import { rotateRefreshToken, revokeSession } from "../services/sessionService.js";
import {
  REFRESH_COOKIE_NAME,
  setRefreshCookie,
  clearRefreshCookie,
  validateCsrfHeaders
} from "../utils/cookies.js";

export class AuthController {
  /**
   * POST /api/auth/register
   * Registers a new account and returns safe user details + client KDF parameters.
   */
  async register(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const user = await authService.register(req.body);

      res.status(201).json({
        success: true,
        message: "Account registered successfully.",
        data: user
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/auth/login
   * Authenticates credentials, returning a signed JWT access token and KDF parameters.
   * Sets an HttpOnly refresh token cookie.
   */
  async login(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const result = await authService.login(req.body);

      // Set HttpOnly refresh token cookie
      setRefreshCookie(res, result.refreshToken, result.refreshTokenExpiresAt);

      res.status(200).json({
        success: true,
        message: "Authentication successful.",
        data: {
          token: result.token,
          sessionId: result.sessionId,
          user: result.user
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/auth/refresh
   * Rotates the refresh token and issues a new access token.
   * Reads refresh token from HttpOnly cookie.
   * Requires CSRF mitigation headers: X-VaultGuard-Request: 1 + matching Origin.
   */
  async refresh(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!validateCsrfHeaders(req)) {
        res.status(403).json({
          success: false,
          message: "Forbidden: Missing or invalid CSRF headers."
        });
        return;
      }

      const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];

      if (!refreshToken || typeof refreshToken !== "string") {
        res.status(401).json({
          success: false,
          message: "Refresh token cookie is missing."
        });
        return;
      }

      const result = await rotateRefreshToken(refreshToken);

      // Set the new rotated refresh token cookie
      setRefreshCookie(res, result.refreshToken, result.refreshTokenExpiresAt);

      res.status(200).json({
        success: true,
        message: "Token refreshed successfully.",
        data: {
          token: result.accessToken,
          sessionId: result.sessionId
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/auth/logout
   * Revokes the current session and clears the refresh token cookie.
   * Requires a valid Bearer access token and CSRF mitigation headers.
   */
  async logout(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      if (!validateCsrfHeaders(req)) {
        res.status(403).json({
          success: false,
          message: "Forbidden: Missing or invalid CSRF headers."
        });
        return;
      }

      const userId = req.user?.id;
      const sessionId = req.session?.id;

      if (!userId || !sessionId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      await revokeSession(sessionId, userId);
      clearRefreshCookie(res);

      res.status(200).json({
        success: true,
        message: "Logged out successfully."
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/auth/me
   * Returns authenticated user profile based on validated JWT subject claim.
   */
  async getMe(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;

      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const profile = await authService.getProfile(userId);

      res.status(200).json({
        success: true,
        data: profile
      });
    } catch (error) {
      next(error);
    }
  }
}

export const authController = new AuthController();

