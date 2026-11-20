/**
 * VaultGuard – Key Derivation Function Module (Phase 8)
 *
 * Implements PBKDF2-HMAC-SHA256 derivation for client-side zero-knowledge vault keys.
 * Derives non-extractable AES-256-GCM CryptoKey objects using exactly 600,000 iterations.
 */

import { VAULT_CRYPTO_CONSTANTS } from "./constants";
import { stringToUtf8Bytes, uint8ArrayToBase64, base64ToUint8Array } from "./encoding";
import { CryptographicError, type VaultKdfMetadata } from "./types";

/**
 * Generates a fresh, cryptographically secure 16-byte random salt for PBKDF2.
 */
export function generateKdfSalt(): Uint8Array {
  const salt = new Uint8Array(VAULT_CRYPTO_CONSTANTS.KDF_SALT_BYTES);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Creates default VaultKdfMetadata with a freshly generated random 16-byte salt.
 */
export function createDefaultKdfMetadata(salt?: Uint8Array): VaultKdfMetadata {
  const effectiveSalt = salt || generateKdfSalt();
  return {
    vaultKdfSalt: uint8ArrayToBase64(effectiveSalt),
    vaultKdfAlgorithm: VAULT_CRYPTO_CONSTANTS.KDF_ALGORITHM,
    vaultKdfParameters: {
      iterations: VAULT_CRYPTO_CONSTANTS.KDF_ITERATIONS,
      keyLength: VAULT_CRYPTO_CONSTANTS.KDF_KEY_LENGTH_BYTES,
      digest: VAULT_CRYPTO_CONSTANTS.KDF_DIGEST
    }
  };
}

/**
 * Validates KDF metadata against VaultGuard requirements.
 */
export function validateKdfMetadata(metadata: unknown): asserts metadata is VaultKdfMetadata {
  if (!metadata || typeof metadata !== "object") {
    throw new CryptographicError("KDF metadata must be an object.");
  }

  const m = metadata as Partial<VaultKdfMetadata>;

  if (m.vaultKdfAlgorithm !== VAULT_CRYPTO_CONSTANTS.KDF_ALGORITHM) {
    throw new CryptographicError(
      `Unsupported KDF algorithm: ${m.vaultKdfAlgorithm}. Expected ${VAULT_CRYPTO_CONSTANTS.KDF_ALGORITHM}.`
    );
  }

  if (typeof m.vaultKdfSalt !== "string" || m.vaultKdfSalt.length === 0) {
    throw new CryptographicError("Missing or invalid vaultKdfSalt in KDF metadata.");
  }

  const saltBytes = base64ToUint8Array(m.vaultKdfSalt);
  if (saltBytes.length !== VAULT_CRYPTO_CONSTANTS.KDF_SALT_BYTES) {
    throw new CryptographicError(
      `Invalid KDF salt length: ${saltBytes.length} bytes. Expected exactly ${VAULT_CRYPTO_CONSTANTS.KDF_SALT_BYTES} bytes.`
    );
  }

  const params = m.vaultKdfParameters;
  if (!params || typeof params !== "object") {
    throw new CryptographicError("Missing vaultKdfParameters in KDF metadata.");
  }

  if (params.iterations < VAULT_CRYPTO_CONSTANTS.KDF_ITERATIONS) {
    throw new CryptographicError(
      `Insufficient KDF iterations: ${params.iterations}. Must be at least ${VAULT_CRYPTO_CONSTANTS.KDF_ITERATIONS}.`
    );
  }

  if (params.keyLength !== VAULT_CRYPTO_CONSTANTS.KDF_KEY_LENGTH_BYTES) {
    throw new CryptographicError(
      `Invalid key length: ${params.keyLength} bytes. Expected ${VAULT_CRYPTO_CONSTANTS.KDF_KEY_LENGTH_BYTES} bytes.`
    );
  }

  if (params.digest !== VAULT_CRYPTO_CONSTANTS.KDF_DIGEST) {
    throw new CryptographicError(
      `Unsupported digest: ${params.digest}. Expected ${VAULT_CRYPTO_CONSTANTS.KDF_DIGEST}.`
    );
  }
}

/**
 * Derives a non-extractable 256-bit AES-GCM CryptoKey from the master password and salt.
 *
 * Security properties:
 * - Master password is imported with extractable: false.
 * - Key derivation uses PBKDF2 with HMAC-SHA-256 and 600,000 iterations.
 * - Output AES-GCM CryptoKey is non-extractable (extractable: false).
 * - Master password string is not retained inside this module.
 */
export async function deriveVaultKey(
  masterPassword: string,
  salt: Uint8Array | string,
  iterations: number = VAULT_CRYPTO_CONSTANTS.KDF_ITERATIONS
): Promise<CryptoKey> {
  if (typeof masterPassword !== "string" || masterPassword.length === 0) {
    throw new CryptographicError("Master password cannot be empty.");
  }

  const saltBytes = typeof salt === "string" ? base64ToUint8Array(salt) : salt;
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length !== VAULT_CRYPTO_CONSTANTS.KDF_SALT_BYTES) {
    throw new CryptographicError(
      `Invalid salt length: ${saltBytes.length} bytes. Expected ${VAULT_CRYPTO_CONSTANTS.KDF_SALT_BYTES} bytes.`
    );
  }

  if (iterations < VAULT_CRYPTO_CONSTANTS.KDF_ITERATIONS) {
    throw new CryptographicError(
      `Iterations must be at least ${VAULT_CRYPTO_CONSTANTS.KDF_ITERATIONS}.`
    );
  }

  // 1. Import master password as raw key material for PBKDF2
  const passwordBytes = stringToUtf8Bytes(masterPassword);
  let baseKey: CryptoKey;
  try {
    baseKey = await crypto.subtle.importKey(
      "raw",
      passwordBytes,
      { name: "PBKDF2" },
      false, // non-extractable
      ["deriveKey"]
    );
  } finally {
    // Clear the temporary byte buffer from memory
    passwordBytes.fill(0);
  }

  // 2. Derive the AES-256-GCM encryption key
  const vaultKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations,
      hash: "SHA-256"
    },
    baseKey,
    {
      name: "AES-GCM",
      length: VAULT_CRYPTO_CONSTANTS.AES_KEY_LENGTH_BITS
    },
    false, // strictly non-extractable!
    ["encrypt", "decrypt"]
  );

  return vaultKey;
}
