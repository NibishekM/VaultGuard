/**
 * VaultGuard – API Client Types (Phase 9)
 *
 * Defines contracts matching the VaultGuard backend Express API.
 * Ensures strict type safety across all endpoints.
 */

export interface ApiResponse<T = unknown> {
  success: boolean;
  message?: string;
  data?: T;
  errors?: Array<{ field: string; message: string }>;
}

export interface SafeUser {
  id: string;
  email: string;
  accountStatus: "ACTIVE" | "LOCKED" | "DISABLED";
  vaultKdfAlgorithm: "PBKDF2-HMAC-SHA256" | string;
  vaultKdfSalt: string;
  vaultKdfParameters: {
    iterations: number;
    keyLength: number;
    digest: "SHA-256" | string;
    [key: string]: unknown;
  };
  createdAt: string;
  updatedAt?: string;
}

export interface RegisterRequest {
  email: string;
  password: string; // Account password (Argon2id hashed on server)
  vaultKdfSalt?: string; // Client-generated 16-byte random salt (Base64)
  vaultKdfAlgorithm?: "PBKDF2-HMAC-SHA256";
  vaultKdfParameters?: {
    iterations: number;
    keyLength: number;
    digest: "SHA-256";
  };
}

export interface LoginRequest {
  email: string;
  password: string;
  deviceIdentifier?: string;
  deviceName?: string;
}

export interface LoginResponseData {
  token: string;
  sessionId: string;
  user: SafeUser;
}

export interface RefreshResponseData {
  token: string;
  sessionId: string;
}

export interface CreateVaultItemRequest {
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
}

export interface CreateVaultItemResponseData {
  id: string;
  revision: number;
  syncVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface UpdateVaultItemRequest {
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
  expectedRevision: number;
}

export interface UpdateVaultItemResponseData {
  id: string;
  revision: number;
  syncVersion: number;
  updatedAt: string;
}

export interface VaultItemResponse {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
  revision: number;
  syncVersion: number;
  createdAt: string;
  updatedAt: string;
}

export interface ActiveVaultChange {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: string;
  encryptionVersion: number;
  revision: number;
  syncVersion: number;
  createdAt: string;
  updatedAt: string;
  deletedAt: null;
  isDeleted: false;
}

export interface DeletedVaultChange {
  id: string;
  revision: number;
  syncVersion: number;
  deletedAt: string;
  isDeleted: true;
}

export type VaultChange = ActiveVaultChange | DeletedVaultChange;

export interface SyncChangesResponseData {
  changes: VaultChange[];
  nextCursor: number;
  currentSyncVersion: number;
  hasMore: boolean;
}

export interface DeviceResponse {
  id: string;
  deviceIdentifier: string;
  deviceName: string | null;
  lastSeenAt: string | null;
  createdAt: string;
  isCurrent: boolean;
}

export interface VaultVerificationData {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
  createdAt: string;
  updatedAt: string;
}

export interface VaultRecoveryRecord {
  id: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: string;
  encryptionVersion: number;
  isDeleted: boolean;
}

export interface GetVerificationResponseData {
  hasVerification: boolean;
  hasItems: boolean;
  hasActiveItems?: boolean;
  verification: VaultVerificationData | null;
  recoveryRecord?: VaultRecoveryRecord | null;
}

export interface CreateVerificationRequest {
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm?: "AES-256-GCM";
  encryptionVersion?: 1;
  isLegacyMigration?: boolean;
}

export interface BatchImportItem {
  id?: string;
  encryptedPayload: string;
  initializationVector: string;
  authenticationTag: string;
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
  revision?: number;
  createdAt?: string;
  updatedAt?: string;
}

export interface BatchImportRequest {
  items: BatchImportItem[];
  strategy?: "error" | "skip";
}

export interface BatchImportResponseData {
  insertedCount: number;
  skippedCount: number;
  totalProcessed: number;
  syncVersion: number;
  items: Array<{ id: string; revision: number; syncVersion: number }>;
}

