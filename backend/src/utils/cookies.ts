import type { Request, Response } from "express";

export const REFRESH_COOKIE_NAME = "vg_refresh_token";

/**
 * Sets the HttpOnly refresh token cookie.
 * - HttpOnly: not accessible from JavaScript
 * - Secure: sent over HTTPS only in production
 * - SameSite=Lax: CSRF mitigation for cross-site requests
 * - Path: scoped to /api/auth to minimize cookie surface
 */
export function setRefreshCookie(res: Response, token: string, expiresAt: Date): void {
  const isProduction = process.env.NODE_ENV === "production";

  res.cookie(REFRESH_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    path: "/api/auth",
    expires: expiresAt
  });
}

/**
 * Clears the refresh token cookie with the same attributes used to set it.
 */
export function clearRefreshCookie(res: Response): void {
  const isProduction = process.env.NODE_ENV === "production";

  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    path: "/api/auth"
  });
}

/**
 * Validates CSRF-mitigation headers for cookie-based endpoints (refresh, logout).
 * Requires:
 *   - X-VaultGuard-Request: "1"
 *   - Origin header matching FRONTEND_URL (or localhost in development)
 *
 * Returns true if valid, false if rejected.
 */
export function validateCsrfHeaders(req: Request): boolean {
  const vgHeader = req.headers["x-vaultguard-request"];
  if (vgHeader !== "1") return false;

  const origin = req.headers["origin"];
  if (!origin) return false;

  const frontendUrl = process.env.FRONTEND_URL || "http://localhost:3000";

  // Allow exact match or same-origin in development
  if (origin === frontendUrl) return true;
  if (process.env.NODE_ENV !== "production") {
    // In development, allow localhost origins
    if (origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:")) {
      return true;
    }
  }

  return false;
}
