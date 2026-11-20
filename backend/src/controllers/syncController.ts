import type { Request, Response, NextFunction } from "express";
import { syncService } from "../services/syncService.js";
import { syncChangesQuerySchema } from "../utils/syncValidation.js";

export class SyncController {
  /**
   * GET /api/sync/changes
   * Retrieves incremental vault record changes and tombstones for the authenticated user.
   */
  async getChanges(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        res.status(401).json({
          success: false,
          message: "Unauthorized: Missing authenticated session context."
        });
        return;
      }

      // Validate query parameters
      const parsed = syncChangesQuerySchema.safeParse(req.query);
      if (!parsed.success) {
        const formattedErrors = parsed.error.issues.map((issue) => ({
          field: issue.path.join("."),
          message: issue.message
        }));

        res.status(400).json({
          success: false,
          message: "Invalid synchronization query parameters",
          errors: formattedErrors
        });
        return;
      }

      const result = await syncService.getChanges(userId, parsed.data);

      res.status(200).json({
        success: true,
        changes: result.changes,
        nextCursor: result.nextCursor,
        currentSyncVersion: result.currentSyncVersion,
        hasMore: result.hasMore,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }
}

export const syncController = new SyncController();
