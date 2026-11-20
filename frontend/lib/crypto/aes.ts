/**
 * VaultGuard – Authenticated Encryption Module (AES-256-GCM) (Phase 8)
 *
 * Implements client-side AES-256-GCM authenticated encryption and decryption.
 * Produces and consumes the exact payload format expected by the VaultGuard backend:
 * - encryptedPayload: Canonical Base64 ciphertext (without tag)
 * - initializationVector: Canonical Base64 12-byte IV
 * - authenticationTag: Canonical Base64 16-byte auth tag
 * - encryptionAlgorithm: "AES-256-GCM"
 * - encryptionVersion: 1
 */

import { VAULT_CRYPTO_CONSTANTS } from "./constants";
import {
  base64ToUint8Array,
  concatUint8Arrays,
  stringToUtf8Bytes,
  uint8ArrayToBase64,
  utf8BytesToString
} from "./encoding";
import {
  CryptographicError,
  DecryptionError,
  type EncryptedVaultPayload
} from "./types";

/**
 * Generates a fresh, unique 12-byte (96-bit) Initialization Vector (IV).
 * Must be generated anew for EVERY encryption operation to prevent IV reuse.
 */
export function generateInitializationVector(): Uint8Array {
  const iv = new Uint8Array(VAULT_CRYPTO_CONSTANTS.IV_BYTES);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Encrypts data using AES-256-GCM with a unique 12-byte IV.
 *
 * Web Crypto AES-GCM appends the 16-byte tag to the ciphertext:
 * [ ...ciphertext (N bytes) | authentication tag (16 bytes) ]
 *
 * This function extracts the final 16 bytes as authenticationTag and returns
 * the preceding bytes as encryptedPayload, matching backend expectations.
 */
export async function encryptVaultPayload(
  data: unknown,
  key: CryptoKey
): Promise<EncryptedVaultPayload> {
  if (!key || !(key instanceof CryptoKey)) {
    throw new CryptographicError("A valid CryptoKey is required for encryption.");
  }

  // 1. Serialize data to UTF-8 bytes
  const serialized = typeof data === "string" ? data : JSON.stringify(data);
  const plaintextBytes = stringToUtf8Bytes(serialized);

  // 2. Generate unique 12-byte IV
  const iv = generateInitializationVector();

  try {
    // 3. Encrypt via Web Crypto AES-GCM
    const cipherResultBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: VAULT_CRYPTO_CONSTANTS.AUTH_TAG_LENGTH_BITS
      },
      key,
      plaintextBytes
    );

    const combinedBytes = new Uint8Array(cipherResultBuffer);

    // 4. Validate output length contains at least 16 bytes for auth tag
    if (combinedBytes.length < VAULT_CRYPTO_CONSTANTS.AUTH_TAG_BYTES) {
      throw new CryptographicError("AES-GCM output is shorter than the authentication tag.");
    }

    // 5. Split [ciphertext ... 16-byte tag]
    const splitIndex = combinedBytes.length - VAULT_CRYPTO_CONSTANTS.AUTH_TAG_BYTES;
    const ciphertextBytes = combinedBytes.subarray(0, splitIndex);
    const authTagBytes = combinedBytes.subarray(splitIndex);

    // 6. Encode canonical Base64 representations
    return {
      encryptedPayload: uint8ArrayToBase64(ciphertextBytes),
      initializationVector: uint8ArrayToBase64(iv),
      authenticationTag: uint8ArrayToBase64(authTagBytes),
      encryptionAlgorithm: VAULT_CRYPTO_CONSTANTS.ENCRYPTION_ALGORITHM,
      encryptionVersion: VAULT_CRYPTO_CONSTANTS.ENCRYPTION_VERSION
    };
  } catch (err: any) {
    if (err instanceof CryptographicError) throw err;
    throw new CryptographicError(`Encryption failed: ${err?.message || "Unknown error"}`);
  }
}

/**
 * Decrypts an AES-256-GCM encrypted payload using the provided CryptoKey.
 *
 * Recombines [encryptedPayload || authenticationTag] before invoking
 * Web Crypto AES-GCM decryption.
 *
 * Throws DecryptionError if the authentication tag fails verification
 * (e.g., incorrect key, tampered ciphertext, tampered IV, or tampered tag).
 */
export async function decryptVaultPayload<T = unknown>(
  payload: EncryptedVaultPayload,
  key: CryptoKey
): Promise<T> {
  if (!key || !(key instanceof CryptoKey)) {
    throw new CryptographicError("A valid CryptoKey is required for decryption.");
  }

  // 1. Validate cryptographic metadata
  if (!payload || typeof payload !== "object") {
    throw new CryptographicError("Invalid payload: payload must be an object.");
  }

  if (payload.encryptionAlgorithm !== VAULT_CRYPTO_CONSTANTS.ENCRYPTION_ALGORITHM) {
    throw new CryptographicError(
      `Unsupported encryption algorithm: ${payload.encryptionAlgorithm}. Expected ${VAULT_CRYPTO_CONSTANTS.ENCRYPTION_ALGORITHM}.`
    );
  }

  if (payload.encryptionVersion !== VAULT_CRYPTO_CONSTANTS.ENCRYPTION_VERSION) {
    throw new CryptographicError(
      `Unsupported encryption version: ${payload.encryptionVersion}. Expected ${VAULT_CRYPTO_CONSTANTS.ENCRYPTION_VERSION}.`
    );
  }

  // 2. Decode Base64 components
  const ciphertextBytes = base64ToUint8Array(payload.encryptedPayload);
  const ivBytes = base64ToUint8Array(payload.initializationVector);
  const authTagBytes = base64ToUint8Array(payload.authenticationTag);

  // 3. Validate component lengths
  if (ivBytes.length !== VAULT_CRYPTO_CONSTANTS.IV_BYTES) {
    throw new CryptographicError(
      `Invalid IV length: ${ivBytes.length} bytes. Expected exactly ${VAULT_CRYPTO_CONSTANTS.IV_BYTES} bytes.`
    );
  }

  if (authTagBytes.length !== VAULT_CRYPTO_CONSTANTS.AUTH_TAG_BYTES) {
    throw new CryptographicError(
      `Invalid authentication tag length: ${authTagBytes.length} bytes. Expected exactly ${VAULT_CRYPTO_CONSTANTS.AUTH_TAG_BYTES} bytes.`
    );
  }

  // 4. Recombine ciphertext and authentication tag for Web Crypto
  const combinedBytes = concatUint8Arrays(ciphertextBytes, authTagBytes);

  try {
    // 5. Decrypt and authenticate
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivBytes,
        tagLength: VAULT_CRYPTO_CONSTANTS.AUTH_TAG_LENGTH_BITS
      },
      key,
      combinedBytes
    );

    // 6. Decode UTF-8 plaintext
    const plaintext = utf8BytesToString(new Uint8Array(decryptedBuffer));

    // 7. Parse JSON if structured, otherwise return plaintext string
    try {
      return JSON.parse(plaintext) as T;
    } catch {
      return plaintext as unknown as T;
    }
  } catch (err: any) {
    // In Web Crypto, tag verification failure or wrong key manifests as OperationError
    if (err?.name === "OperationError") {
      throw new DecryptionError("Decryption failed: authentication tag verification failed.");
    }
    throw new CryptographicError(`Decryption error: ${err?.message || "Unknown error"}`);
  }
}
