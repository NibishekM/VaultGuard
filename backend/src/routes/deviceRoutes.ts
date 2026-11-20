import { Router, type Request } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import { deviceController } from "../controllers/deviceController.js";
import { requireAuth } from "../middleware/authMiddleware.js";
import { validateParams } from "../middleware/validationMiddleware.js";
import { deviceIdParamSchema } from "../utils/deviceValidation.js";

const router = Router();

/**
 * Device Management Rate Limiter
 * 30 requests per 15 minutes per authenticated user + IP.
 */
const deviceRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request): string => {
    const userId = req.user?.id || "unauthenticated";
    const clientIp = ipKeyGenerator(req.ip || req.socket.remoteAddress || "127.0.0.1");
    return `devices:${userId}:${clientIp}`;
  },
  message: {
    success: false,
    message: "Too many device management requests. Please try again after 15 minutes."
  }
});

// All device routes require authentication
router.use(requireAuth);
router.use(deviceRateLimiter);

// GET /api/devices — list registered devices for authenticated user
router.get("/", deviceController.listDevices.bind(deviceController));

// DELETE /api/devices/:id — remove a device and revoke its sessions
router.delete(
  "/:id",
  validateParams(deviceIdParamSchema),
  deviceController.removeDevice.bind(deviceController)
);

export default router;
