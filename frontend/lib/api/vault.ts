/**
 * VaultGuard – Encrypted Vault CRUD API Service (Phase 9)
 *
 * Implements client-side calls for Zero-Knowledge Vault CRUD:
 * - Create encrypted item
 * - List encrypted items
 * - Get encrypted item by ID
 * - Update encrypted item with expectedRevision
 * - Soft-delete encrypted item
 *
 * Security invariant: Only ciphertext and non-secret metadata are transmitted.
 * Plaintext is NEVER sent to the backend.
 */

import { apiClient } from "./client";
import type {
  ApiResponse,
  CreateVaultItemRequest,
  CreateVaultItemResponseData,
  UpdateVaultItemRequest,
  UpdateVaultItemResponseData,
  VaultItemResponse,
  GetVerificationResponseData,
  CreateVerificationRequest,
  VaultVerificationData,
  BatchImportRequest,
  BatchImportResponseData
} from "./types";

export const vaultApi = {
  /**
   * Atomically imports an array of encrypted vault items.
   */
  async batchImport(data: BatchImportRequest): Promise<BatchImportResponseData> {
    const res = await apiClient<ApiResponse<BatchImportResponseData>>("/api/vault/batch-import", {
      method: "POST",
      body: data
    });
    if (!res.data) {
      throw new Error("Failed to import vault items: No confirmation returned.");
    }
    return res.data;
  },

  /**
   * Stores a new AES-256-GCM encrypted vault item on the backend.
   */
  async createItem(data: CreateVaultItemRequest): Promise<CreateVaultItemResponseData> {
    const res = await apiClient<ApiResponse<CreateVaultItemResponseData>>("/api/vault", {
      method: "POST",
      body: data
    });
    if (!res.data) {
      throw new Error("Failed to create vault item: No item data returned.");
    }
    return res.data;
  },

  /**
   * Lists all active encrypted vault items for the authenticated user.
   */
  async listItems(): Promise<VaultItemResponse[]> {
    const res = await apiClient<ApiResponse<VaultItemResponse[]>>("/api/vault", {
      method: "GET"
    });
    return res.data || [];
  },

  /**
   * Retrieves a single encrypted vault item by ID.
   */
  async getItem(id: string): Promise<VaultItemResponse> {
    const res = await apiClient<ApiResponse<VaultItemResponse>>(`/api/vault/${encodeURIComponent(id)}`, {
      method: "GET"
    });
    if (!res.data) {
      throw new Error("Vault item not found.");
    }
    return res.data;
  },

  /**
   * Updates an existing encrypted item with optimistic concurrency control.
   */
  async updateItem(id: string, data: UpdateVaultItemRequest): Promise<UpdateVaultItemResponseData> {
    const res = await apiClient<ApiResponse<UpdateVaultItemResponseData>>(
      `/api/vault/${encodeURIComponent(id)}`,
      {
        method: "PUT",
        body: data
      }
    );
    if (!res.data) {
      throw new Error("Failed to update vault item: No confirmation returned.");
    }
    return res.data;
  },

  /**
   * Soft-deletes a vault item on the backend.
   */
  async deleteItem(id: string): Promise<{ id: string; syncVersion: number }> {
    const res = await apiClient<ApiResponse<{ id: string; syncVersion: number }>>(
      `/api/vault/${encodeURIComponent(id)}`,
      {
        method: "DELETE"
      }
    );
    return res.data || { id, syncVersion: 0 };
  },

  /**
   * Retrieves the server verification status and canary record.
   */
  async getVerification(): Promise<GetVerificationResponseData> {
    const res = await apiClient<ApiResponse<GetVerificationResponseData>>("/api/vault/verification", {
      method: "GET"
    });
    if (!res.data) {
      throw new Error("Failed to retrieve verification status from server.");
    }
    return res.data;
  },

  /**
   * Creates or migrates the master-password verification record (create-once).
   */
  async createVerification(data: CreateVerificationRequest): Promise<VaultVerificationData> {
    const res = await apiClient<ApiResponse<VaultVerificationData>>("/api/vault/verification", {
      method: "POST",
      body: data
    });
    if (!res.data) {
      throw new Error("Failed to create verification record: No data returned.");
    }
    return res.data;
  }
};
