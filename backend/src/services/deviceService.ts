import prisma from "../config/db.js";
import { AppError } from "../utils/errors.js";
import { revokeDeviceSessions } from "./sessionService.js";

export interface SafeDevice {
  id: string;
  deviceIdentifier: string;
  deviceName: string | null;
  lastSeenAt: Date | null;
  createdAt: Date;
  isCurrent: boolean;
}

/**
 * Returns all non-removed devices for a user, annotated with isCurrent flag.
 */
export async function listUserDevices(
  userId: string,
  currentSessionId: string
): Promise<SafeDevice[]> {
  // Find the device associated with the current session
  const currentSession = await prisma.session.findUnique({
    where: { id: currentSessionId },
    select: { deviceId: true }
  });

  const currentDeviceId = currentSession?.deviceId ?? null;

  const devices = await prisma.device.findMany({
    where: { userId, removedAt: null },
    orderBy: { lastSeenAt: "desc" },
    select: {
      id: true,
      deviceIdentifier: true,
      deviceName: true,
      lastSeenAt: true,
      createdAt: true
    }
  });

  return devices.map((d) => ({
    ...d,
    isCurrent: d.id === currentDeviceId
  }));
}

/**
 * Removes a device from a user's account.
 * - Prevents removing the device hosting the current session.
 * - Revokes all sessions and refresh tokens linked to the device.
 * - Sets removedAt soft-delete on the device.
 */
export async function removeDevice(
  userId: string,
  deviceId: string,
  currentSessionId: string
): Promise<void> {
  const device = await prisma.device.findUnique({ where: { id: deviceId } });

  if (!device || device.userId !== userId) {
    throw new AppError("Device not found or access denied.", 404);
  }

  // revokeDeviceSessions also performs ownership, current session, and already-removed checks
  await revokeDeviceSessions(deviceId, userId, currentSessionId);
}
