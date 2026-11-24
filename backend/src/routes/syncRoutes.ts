import { Router, type Request, type Router as ExpressRouter } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import { syncController } from "../controllers/syncController.js";
import { requireAuth } from "../middleware/authMiddleware.js";

const router: ExpressRouter = Router();

// Enforce strict Bearer JWT authentication and session validation first
router.use(requireAuth);

/**
 * Synchronization Rate Limiter
 * Constrains synchronization requests to 100 requests per 15-minute window per user/IP.
 */
export const syncRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  standardHeaders: true,
  legacyHeaders: false,
  statusCode: 429,
  keyGenerator: (req: Request): string => {
    const userId = req.user?.id || "unauthenticated";
    const clientIp = ipKeyGenerator(req.ip || req.socket.remoteAddress || "127.0.0.1");
    return `sync:${userId}:${clientIp}`;
  },
  message: {
    success: false,
    message: "Too many synchronization requests. Please try again after 15 minutes."
  }
});

router.use(syncRateLimiter);

// GET /api/sync/changes - Retrieve incremental synchronization changes
router.get("/changes", syncController.getChanges.bind(syncController));

export default router;
