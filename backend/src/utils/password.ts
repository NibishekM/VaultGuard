import argon2 from "argon2";
import crypto from "crypto";

/**
 * OWASP-aligned Argon2id parameters for user account password hashing.
 * Argon2id offers hybrid resistance against side-channel and GPU-based attacks.
 *
 * Parameters:
 * - type: argon2id (hybrid mode, value 2)
 * - memoryCost: 65536 KiB (64 MiB memory hardness)
 * - timeCost: 3 iterations
 * - parallelism: 1 thread
 * - hashLength: 32 bytes output length
 */
export const ARGON2ID_OPTIONS: argon2.HashOptions & { raw?: false } = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  hashLength: 32,
  raw: false
};

/**
 * Hashes an account password using Argon2id.
 * Plaintext passwords are never logged, stored, or exposed.
 */
export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, ARGON2ID_OPTIONS);
}

/**
 * Verifies a candidate password against an Argon2id hash.
 * Returns false on mismatch or malformed hash format, never throwing internal errors.
 */
export async function verifyPassword(hash: string, candidate: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, candidate);
  } catch {
    return false;
  }
}

/**
 * Generates a cryptographically secure random salt for client-side vault key derivation (KDF).
 * Stored as a base64-encoded string on the backend and retrieved by the client to derive the AES key.
 */
export function generateVaultKdfSalt(bytes = 16): string {
  return crypto.randomBytes(bytes).toString("base64");
}
