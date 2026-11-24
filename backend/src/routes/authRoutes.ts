import { Router, type Router as ExpressRouter } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import type { Request } from "express";
import { authController } from "../controllers/authController.js";
import { validateBody } from "../middleware/validationMiddleware.js";
import { requireAuth } from "../middleware/authMiddleware.js";
import { registerSchema, loginWithDeviceSchema } from "../utils/validation.js";

const router: ExpressRouter = Router();

/**
 * Strict Rate Limiter for Authentication Endpoints
 * Mitigates credential brute-forcing, password-spraying, and denial-of-service.
 * Limits to 20 attempts per 15-minute window per IP.
 */
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                  // 20 requests per window
  standardHeaders: true,    // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,     // Disable `X-RateLimit-*` headers
  message: {
    success: false,
    message: "Too many authentication requests from this IP. Please try again after 15 minutes."
  }
});

/**
 * Refresh Token Rate Limiter
 * Prevents refresh token brute-forcing.
 * 10 requests per 15 minutes per IP.
 */
const refreshRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    return ipKeyGenerator(req.ip || req.socket.remoteAddress || "127.0.0.1");
  },
  message: {
    success: false,
    message: "Too many token refresh requests. Please try again after 15 minutes."
  }
});

// Registration Endpoint
router.post(
  "/register",
  authRateLimiter,
  validateBody(registerSchema),
  authController.register.bind(authController)
);

// Login Endpoint (accepts optional device fields)
router.post(
  "/login",
  authRateLimiter,
  validateBody(loginWithDeviceSchema),
  authController.login.bind(authController)
);

// Token Refresh Endpoint (cookie-based, CSRF-protected)
router.post(
  "/refresh",
  refreshRateLimiter,
  authController.refresh.bind(authController)
);

// Logout Endpoint (requires valid Bearer token + CSRF headers)
router.post(
  "/logout",
  authRateLimiter,
  requireAuth,
  authController.logout.bind(authController)
);

// Protected Identity Verification Endpoint
router.get(
  "/me",
  requireAuth,
  authController.getMe.bind(authController)
);

export default router;

