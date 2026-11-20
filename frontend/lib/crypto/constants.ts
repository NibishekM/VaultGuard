/**
 * VaultGuard – Cryptographic Constants (Phase 8)
 *
 * Defines invariant constants for PBKDF2 derivation and AES-256-GCM encryption.
 * Synchronized with the VaultGuard backend specification.
 */

export const VAULT_CRYPTO_CONSTANTS = {
  // Key Derivation Function (PBKDF2-HMAC-SHA256)
  KDF_ALGORITHM: "PBKDF2-HMAC-SHA256" as const,
  KDF_ITERATIONS: 600000,
  KDF_KEY_LENGTH_BYTES: 32, // 256-bit key
  KDF_KEY_LENGTH_BITS: 256,
  KDF_DIGEST: "SHA-256" as const,
  KDF_SALT_BYTES: 16, // 16 bytes (128 bits) cryptographically random salt

  // Authenticated Encryption (AES-256-GCM)
  ENCRYPTION_ALGORITHM: "AES-256-GCM" as const,
  ENCRYPTION_VERSION: 1 as const,
  AES_KEY_LENGTH_BITS: 256,
  IV_BYTES: 12, // 96-bit initialization vector
  AUTH_TAG_BYTES: 16, // 128-bit authentication tag
  AUTH_TAG_LENGTH_BITS: 128,

  // Storage
  INDEXEDDB_NAME: "vaultguard_local_db",
  INDEXEDDB_VERSION: 1,
  STORE_ENCRYPTED_ITEMS: "encrypted_items",
  STORE_METADATA: "vault_metadata",

  // Lifecycle Defaults
  DEFAULT_AUTO_LOCK_MINUTES: 5
} as const;
