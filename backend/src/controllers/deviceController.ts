import type { Request, Response, NextFunction } from "express";
import { listUserDevices, removeDevice } from "../services/deviceService.js";

export class DeviceController {
  /**
   * GET /api/devices
   * Returns all registered (non-removed) devices for the authenticated user.
   * Annotates the current device with isCurrent: true.
   */
  async listDevices(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;
      const sessionId = req.session?.id ?? "";

      const devices = await listUserDevices(userId, sessionId);

      res.status(200).json({
        success: true,
        data: devices
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * DELETE /api/devices/:id
   * Removes a registered device: sets removedAt, revokes all sessions and refresh tokens.
   * Cannot remove the device hosting the current active session.
   */
  async removeDevice(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const userId = req.user!.id;
      const sessionId = req.session?.id ?? "";
      const deviceId = req.params["id"] as string;

      await removeDevice(userId, deviceId, sessionId);

      res.status(200).json({
        success: true,
        message: "Device removed and all associated sessions revoked."
      });
    } catch (error) {
      next(error);
    }
  }
}

export const deviceController = new DeviceController();
