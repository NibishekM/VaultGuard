/**
 * VaultGuard – Frontend Cryptographic Architecture Types (Phase 8)
 *
 * Defines cryptographic payloads, metadata, key states, and decrypted vault models.
 * Compatible with the VaultGuard backend AES-256-GCM zero-knowledge contract.
 */

export interface VaultKdfParameters {
  iterations: number; // Exactly 600,000 iterations
  keyLength: number; // 32 bytes (256 bits)
  digest: "SHA-256";
}

export interface VaultKdfMetadata {
  vaultKdfSalt: string; // Base64-encoded 16-byte random salt
  vaultKdfAlgorithm: "PBKDF2-HMAC-SHA256";
  vaultKdfParameters: VaultKdfParameters;
}

/**
 * Encrypted payload representation matching the VaultGuard backend contract.
 *
 * Web Crypto AES-GCM produces [ciphertext || 16-byte tag].
 * This interface splits that output into encryptedPayload and authenticationTag.
 */
export interface EncryptedVaultPayload {
  encryptedPayload: string; // Canonical Base64-encoded ciphertext (excluding tag)
  initializationVector: string; // Canonical Base64-encoded 12-byte IV
  authenticationTag: string; // Canonical Base64-encoded 16-byte authentication tag
  encryptionAlgorithm: "AES-256-GCM";
  encryptionVersion: 1;
}

/**
 * Encrypted vault record stored in IndexedDB.
 * Only ciphertext and non-secret metadata are persisted.
 */
export interface EncryptedVaultRecord extends EncryptedVaultPayload {
  id: string;
  userId?: string;
  revision?: number;
  syncVersion?: number;
  createdAt: string;
  updatedAt: string;
}

export type VaultCategory = "Personal" | "Work" | "Finance" | "Social";
export type VaultHealth = "Strong" | "Moderate" | "Weak";

/**
 * In-memory decrypted vault item.
 * Decrypted strictly inside browser memory when vault is unlocked.
 * Cleared immediately upon vault lock.
 */
export interface DecryptedVaultItem {
  id: string;
  service: string;
  username: string;
  password?: string;
  category: VaultCategory;
  health: VaultHealth;
  favorite: boolean;
  notes: string;
  revision?: number;
  createdAt: string;
  updatedAt: string;
}

export type VaultKeyState = "locked" | "unlocking" | "unlocked" | "locking" | "error";

export class CryptographicError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptographicError";
  }
}

export class DecryptionError extends CryptographicError {
  constructor(message = "Authentication tag verification failed or incorrect master password.") {
    super(message);
    this.name = "DecryptionError";
  }
}
