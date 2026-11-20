import type { Request, Response, NextFunction } from "express";
import { vaultService } from "../services/vaultService.js";

export class VaultController {
  /**
   * POST /api/vault
   * Stores a new zero-knowledge encrypted vault item scoped to the authenticated user.
   */
  async createItem(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const item = await vaultService.createItem(userId, req.body);

      res.status(201).json({
        success: true,
        message: "Encrypted vault item stored successfully.",
        data: item
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/vault/batch-import
   * Atomically imports an array of encrypted vault items within a single database transaction.
   */
  async batchImport(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const result = await vaultService.batchImport(userId, req.body);

      res.status(200).json({
        success: true,
        message: `Successfully processed ${result.totalProcessed} items (${result.insertedCount} imported, ${result.skippedCount} skipped).`,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/vault
   * Lists all active (non-deleted) encrypted vault items for the authenticated user.
   */
  async listItems(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const items = await vaultService.listItems(userId);

      res.status(200).json({
        success: true,
        data: items
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/vault/:id
   * Retrieves a single active encrypted vault item by ID with strict ownership verification.
   */
  async getItemById(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const item = await vaultService.getItemById(userId, req.params.id as string);

      res.status(200).json({
        success: true,
        data: item
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * PUT /api/vault/:id
   * Atomically updates an encrypted vault item with optimistic concurrency control.
   */
  async updateItem(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const updated = await vaultService.updateItem(userId, req.params.id as string, req.body);

      res.status(200).json({
        success: true,
        message: "Encrypted vault item updated successfully.",
        data: updated
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * DELETE /api/vault/:id
   * Soft-deletes a vault item, setting deletedAt and incrementing revision for synchronization.
   */
  async deleteItem(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const result = await vaultService.deleteItem(userId, req.params.id as string);

      res.status(200).json(result);
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/vault/verification
   * Returns verification canary status and data (if present) for the authenticated user.
   */
  async getVerification(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const result = await vaultService.getVerification(userId);

      res.status(200).json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/vault/verification
   * Stores the encrypted verification canary record for the user (create-once).
   * Enforces backend-authorized legacy migration bound to the session context.
   */
  async createVerification(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      const sessionId = req.session?.id;
      if (!userId || !sessionId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      const result = await vaultService.createVerification(userId, sessionId, req.body);

      res.status(201).json({
        success: true,
        message: "Encrypted verification canary created successfully.",
        data: result
      });
    } catch (error) {
      next(error);
    }
  }
}

export const vaultController = new VaultController();