/**
 * VaultGuard – Device Management API Service (Phase 9)
 *
 * Implements client-side calls for device listing and remote session revocation.
 */

import { apiClient } from "./client";
import type { ApiResponse, DeviceResponse } from "./types";

export const deviceApi = {
  /**
   * Retrieves all registered devices for the authenticated user.
   */
  async listDevices(): Promise<DeviceResponse[]> {
    const res = await apiClient<ApiResponse<DeviceResponse[]>>("/api/devices", {
      method: "GET"
    });
    return res.data || [];
  },

  /**
   * Removes a device and revokes its associated server sessions.
   * Note: Server rejects removing the current active session device (409 Conflict).
   */
  async removeDevice(deviceId: string): Promise<void> {
    await apiClient<ApiResponse<{ success: boolean }>>(
      `/api/devices/${encodeURIComponent(deviceId)}`,
      {
        method: "DELETE"
      }
    );
  }
};
