import { Router, type Request, type Router as ExpressRouter } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import { vaultController } from "../controllers/vaultController.js";
import { requireAuth } from "../middleware/authMiddleware.js";
import { validateVaultBody, validateParams } from "../middleware/validationMiddleware.js";
import {
  createVaultItemSchema,
  updateVaultItemSchema,
  vaultItemIdParamSchema,
  createVaultVerificationSchema,
  batchImportVaultSchema
} from "../utils/vaultValidation.js";

const router: ExpressRouter = Router();

// Enforce strict Bearer JWT authentication on all vault operations first
router.use(requireAuth);

/**
 * Vault Operations Rate Limiter
 * Applied AFTER requireAuth so unauthenticated requests are rejected with 401 first.
 * Limits authenticated clients to 100 requests per 15-minute window.
 * Keys by verified authenticated user ID combined with client IP address.
 */
export const vaultRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100,               // 100 requests per window
  standardHeaders: true,    // Standard `RateLimit-*` headers
  legacyHeaders: false,     // Disable `X-RateLimit-*` headers
  statusCode: 429,
  keyGenerator: (req: Request): string => {
    const userId = req.user?.id || "unauthenticated";
    const clientIp = ipKeyGenerator(req.ip || req.socket.remoteAddress || "127.0.0.1");
    return `vault:${userId}:${clientIp}`;
  },
  message: {
    success: false,
    message: "Too many vault requests. Please try again after 15 minutes."
  }
});

// Enforce rate limiting on all authenticated vault operations
router.use(vaultRateLimiter);

// POST /api/vault - Create encrypted item
router.post(
  "/",
  validateVaultBody(createVaultItemSchema),
  vaultController.createItem.bind(vaultController)
);

// GET /api/vault - List all active items for authenticated user
router.get(
  "/",
  vaultController.listItems.bind(vaultController)
);

// GET /api/vault/verification - Retrieve master-password verification status and canary
router.get(
  "/verification",
  vaultController.getVerification.bind(vaultController)
);

// POST /api/vault/verification - Store initial/migrated master-password verification canary (create-once)
router.post(
  "/verification",
  validateVaultBody(createVaultVerificationSchema),
  vaultController.createVerification.bind(vaultController)
);

// POST /api/vault/batch-import - Atomic batch import of encrypted items
router.post(
  "/batch-import",
  validateVaultBody(batchImportVaultSchema),
  vaultController.batchImport.bind(vaultController)
);

// GET /api/vault/:id - Retrieve specific encrypted item by ID
router.get(
  "/:id",
  validateParams(vaultItemIdParamSchema),
  vaultController.getItemById.bind(vaultController)
);

// PUT /api/vault/:id - Concurrency-safe atomic update
router.put(
  "/:id",
  validateParams(vaultItemIdParamSchema),
  validateVaultBody(updateVaultItemSchema),
  vaultController.updateItem.bind(vaultController)
);

// DELETE /api/vault/:id - Soft-delete item
router.delete(
  "/:id",
  validateParams(vaultItemIdParamSchema),
  vaultController.deleteItem.bind(vaultController)
);

export default router;

