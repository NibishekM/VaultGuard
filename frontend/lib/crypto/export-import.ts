/**
 * VaultGuard – Secure Encrypted Vault Export & Import (Phase 10.4)
 *
 * Implements client-side encrypted backup generation and rigorous restoration validation:
 * - Exports ONLY encrypted vault records and KDF metadata (zero plaintext).
 * - Enforces versioned backup schema: "vaultguardBackup", formatVersion 1.
 * - Validates file size (max 5 MB) before parsing to prevent memory exhaustion / DoS.
 * - Enforces canonical Base64, 12-byte IVs, 16-byte authentication tags, and AES-256-GCM.
 * - Enforces PBKDF2-HMAC-SHA256 with >= 600,000 iterations and 16-byte KDF salt.
 * - Detects and rejects duplicate record IDs within the import payload.
 * - Validates KDF salt compatibility with the active account before restoration.
 * - Never logs or transmits master passwords, derived keys, or plaintext secrets.
 */

import { base64ToUint8Array } from "./encoding";
import type { EncryptedVaultRecord, VaultKdfMetadata } from "./types";

export const BACKUP_FORMAT_VERSION = 1 as const;
export const BACKUP_FORMAT_NAME = "vaultguard-encrypted-backup" as const;
export const MAX_BACKUP_FILE_BYTES = 5 * 1024 * 1024; // 5 MiB maximum

export interface VaultBackupMetadata {
  formatVersion: typeof BACKUP_FORMAT_VERSION;
  formatName: typeof BACKUP_FORMAT_NAME;
  createdAt: string;
  appVersion: string;
  kdfMetadata: VaultKdfMetadata;
  recordCount: number;
}

export interface VaultBackupFile {
  vaultguardBackup: VaultBackupMetadata & {
    records: EncryptedVaultRecord[];
  };
}

export interface BackupValidationResult {
  success: boolean;
  data?: VaultBackupFile;
  error?: string;
}

/**
 * Creates a clean, versioned encrypted backup object from encrypted records and KDF metadata.
 * Strips any internal unneeded fields while preserving required cryptographic and sync data.
 */
export function createVaultExport(
  records: EncryptedVaultRecord[],
  kdfMetadata: VaultKdfMetadata,
  appVersion = "1.0.0"
): VaultBackupFile {
  const sanitizedRecords: EncryptedVaultRecord[] = records.map((rec) => ({
    id: rec.id,
    encryptedPayload: rec.encryptedPayload,
    initializationVector: rec.initializationVector,
    authenticationTag: rec.authenticationTag,
    encryptionAlgorithm: rec.encryptionAlgorithm || "AES-256-GCM",
    encryptionVersion: rec.encryptionVersion || 1,
    revision: rec.revision || 1,
    createdAt: rec.createdAt,
    updatedAt: rec.updatedAt
  }));

  return {
    vaultguardBackup: {
      formatVersion: BACKUP_FORMAT_VERSION,
      formatName: BACKUP_FORMAT_NAME,
      createdAt: new Date().toISOString(),
      appVersion,
      kdfMetadata: {
        vaultKdfSalt: kdfMetadata.vaultKdfSalt,
        vaultKdfAlgorithm: kdfMetadata.vaultKdfAlgorithm,
        vaultKdfParameters: {
          iterations: kdfMetadata.vaultKdfParameters.iterations,
          keyLength: kdfMetadata.vaultKdfParameters.keyLength,
          digest: kdfMetadata.vaultKdfParameters.digest
        }
      },
      recordCount: sanitizedRecords.length,
      records: sanitizedRecords
    }
  };
}

/**
 * Validates a raw backup file string against strict cryptographic, structural, and schema rules.
 *
 * @param jsonString The raw file content
 * @param activeKdfMetadata Optional active account KDF metadata or salt for compatibility validation
 */
export function validateVaultBackup(
  jsonString: string,
  activeKdfMetadata?: VaultKdfMetadata | string | null
): BackupValidationResult {
  // 1. File size check before parsing
  if (typeof jsonString !== "string") {
    return { success: false, error: "Invalid backup input: Expected string content." };
  }

  // UTF-8 byte estimate: string length in characters (safe upper bound)
  if (jsonString.length > MAX_BACKUP_FILE_BYTES) {
    return {
      success: false,
      error: `Backup file exceeds maximum allowed size of 5 MB (size: ${Math.round(jsonString.length / 1024)} KB).`
    };
  }

  // 2. Parse JSON
  let parsed: any;
  try {
    parsed = JSON.parse(jsonString);
  } catch (err: any) {
    return { success: false, error: `Malformed JSON: ${err?.message || "Syntax error"}` };
  }

  // 3. Root structure check
  if (!parsed || typeof parsed !== "object" || !parsed.vaultguardBackup || typeof parsed.vaultguardBackup !== "object") {
    return { success: false, error: "Invalid backup file: Missing root 'vaultguardBackup' container." };
  }

  const root = parsed.vaultguardBackup;

  // 4. Format & Version check
  if (root.formatName !== BACKUP_FORMAT_NAME) {
    return {
      success: false,
      error: `Unsupported backup format: '${root.formatName}'. Expected '${BACKUP_FORMAT_NAME}'.`
    };
  }

  if (root.formatVersion !== BACKUP_FORMAT_VERSION) {
    return {
      success: false,
      error: `Unsupported backup format version: ${root.formatVersion}. Expected version ${BACKUP_FORMAT_VERSION}.`
    };
  }

  // 5. Creation timestamp check
  if (typeof root.createdAt !== "string" || isNaN(Date.parse(root.createdAt))) {
    return { success: false, error: "Invalid or missing 'createdAt' timestamp in backup metadata." };
  }

  // 6. KDF metadata validation
  const kdf = root.kdfMetadata;
  if (!kdf || typeof kdf !== "object") {
    return { success: false, error: "Missing 'kdfMetadata' in backup header." };
  }

  if (kdf.vaultKdfAlgorithm !== "PBKDF2-HMAC-SHA256") {
    return {
      success: false,
      error: `Unsupported KDF algorithm '${kdf.vaultKdfAlgorithm}'. Only 'PBKDF2-HMAC-SHA256' is supported.`
    };
  }

  const kdfParams = kdf.vaultKdfParameters;
  if (!kdfParams || typeof kdfParams !== "object") {
    return { success: false, error: "Missing 'vaultKdfParameters' in KDF metadata." };
  }

  if (typeof kdfParams.iterations !== "number" || kdfParams.iterations < 600000) {
    return {
      success: false,
      error: `Insecure or invalid KDF iterations (${kdfParams.iterations}). Must be at least 600,000.`
    };
  }

  if (kdfParams.keyLength !== 32 || kdfParams.digest !== "SHA-256") {
    return {
      success: false,
      error: "Invalid KDF parameters. Expected keyLength 32 and digest SHA-256."
    };
  }

  // Validate KDF salt (must decode to exactly 16 bytes)
  try {
    const saltBytes = base64ToUint8Array(kdf.vaultKdfSalt);
    if (saltBytes.length !== 16) {
      return { success: false, error: "KDF salt must be exactly 16 bytes when decoded." };
    }
  } catch (err: any) {
    return { success: false, error: `Invalid KDF salt: ${err?.message || "Invalid Base64"}` };
  }

  // 7. Account KDF Compatibility Check
  if (activeKdfMetadata !== undefined && activeKdfMetadata !== null) {
    if (typeof activeKdfMetadata === "string") {
      if (kdf.vaultKdfSalt !== activeKdfMetadata) {
        return {
          success: false,
          error:
            "Incompatible vault backup: The backup's KDF salt does not match the active account's KDF configuration. Cross-account imports without re-encryption are not supported to preserve zero-knowledge isolation."
        };
      }
    } else {
      const activeMeta = activeKdfMetadata as VaultKdfMetadata;
      if (kdf.vaultKdfSalt !== activeMeta.vaultKdfSalt) {
        return {
          success: false,
          error:
            "Incompatible vault backup: The backup's KDF salt does not match the active account's KDF salt. Cross-account imports without re-encryption are not supported."
        };
      }
      if (kdf.vaultKdfAlgorithm !== activeMeta.vaultKdfAlgorithm) {
        return {
          success: false,
          error: `Incompatible vault backup: The backup's KDF algorithm '${kdf.vaultKdfAlgorithm}' does not match the active account's KDF algorithm '${activeMeta.vaultKdfAlgorithm}'.`
        };
      }
      if (kdfParams.iterations !== activeMeta.vaultKdfParameters.iterations) {
        return {
          success: false,
          error: `Incompatible vault backup: The backup's PBKDF2 iterations (${kdfParams.iterations}) do not match the active account's iterations (${activeMeta.vaultKdfParameters.iterations}).`
        };
      }
      if (kdfParams.keyLength !== activeMeta.vaultKdfParameters.keyLength) {
        return {
          success: false,
          error: `Incompatible vault backup: The backup's key length (${kdfParams.keyLength}) does not match the active account's key length (${activeMeta.vaultKdfParameters.keyLength}).`
        };
      }
      if (kdfParams.digest !== activeMeta.vaultKdfParameters.digest) {
        return {
          success: false,
          error: `Incompatible vault backup: The backup's digest algorithm '${kdfParams.digest}' does not match the active account's digest algorithm '${activeMeta.vaultKdfParameters.digest}'.`
        };
      }
    }
  }

  // 8. Records array validation
  if (!Array.isArray(root.records)) {
    return { success: false, error: "'records' must be an array." };
  }

  if (typeof root.recordCount !== "number" || root.recordCount !== root.records.length) {
    return {
      success: false,
      error: `Record count mismatch: Header indicates ${root.recordCount} records, but array contains ${root.records.length}.`
    };
  }

  // 9. Inspect every record
  const seenIds = new Set<string>();

  for (let i = 0; i < root.records.length; i++) {
    const rec = root.records[i];
    const prefix = `Record #${i + 1}`;

    if (!rec || typeof rec !== "object") {
      return { success: false, error: `${prefix} is not a valid object.` };
    }

    // ID validation
    if (typeof rec.id !== "string" || rec.id.trim().length === 0) {
      return { success: false, error: `${prefix} missing valid 'id' identifier.` };
    }

    if (seenIds.has(rec.id)) {
      return { success: false, error: `Duplicate record identifier '${rec.id}' detected in backup.` };
    }
    seenIds.add(rec.id);

    // Encryption algorithm & version
    if (rec.encryptionAlgorithm !== "AES-256-GCM") {
      return {
        success: false,
        error: `${prefix} has unsupported encryption algorithm '${rec.encryptionAlgorithm}'. Only 'AES-256-GCM' is supported.`
      };
    }

    if (rec.encryptionVersion !== 1) {
      return {
        success: false,
        error: `${prefix} has unsupported encryption version '${rec.encryptionVersion}'. Expected version 1.`
      };
    }

    // Encrypted payload Base64 validation
    if (typeof rec.encryptedPayload !== "string" || rec.encryptedPayload.length === 0) {
      return { success: false, error: `${prefix} missing 'encryptedPayload'.` };
    }
    try {
      const payloadBytes = base64ToUint8Array(rec.encryptedPayload);
      if (payloadBytes.length === 0) {
        return { success: false, error: `${prefix} 'encryptedPayload' is empty.` };
      }
    } catch (err: any) {
      return { success: false, error: `${prefix} 'encryptedPayload' invalid Base64: ${err?.message}` };
    }

    // Initialization vector (IV) validation (must be exactly 12 bytes)
    if (typeof rec.initializationVector !== "string") {
      return { success: false, error: `${prefix} missing 'initializationVector'.` };
    }
    try {
      const ivBytes = base64ToUint8Array(rec.initializationVector);
      if (ivBytes.length !== 12) {
        return {
          success: false,
          error: `${prefix} IV length is ${ivBytes.length} bytes. Expected exactly 12 bytes (96 bits).`
        };
      }
    } catch (err: any) {
      return { success: false, error: `${prefix} 'initializationVector' invalid Base64: ${err?.message}` };
    }

    // Authentication tag validation (must be exactly 16 bytes)
    if (typeof rec.authenticationTag !== "string") {
      return { success: false, error: `${prefix} missing 'authenticationTag'.` };
    }
    try {
      const tagBytes = base64ToUint8Array(rec.authenticationTag);
      if (tagBytes.length !== 16) {
        return {
          success: false,
          error: `${prefix} tag length is ${tagBytes.length} bytes. Expected exactly 16 bytes (128 bits).`
        };
      }
    } catch (err: any) {
      return { success: false, error: `${prefix} 'authenticationTag' invalid Base64: ${err?.message}` };
    }

    // Revision check
    if (rec.revision !== undefined && (typeof rec.revision !== "number" || rec.revision < 1)) {
      return { success: false, error: `${prefix} revision must be a positive integer.` };
    }
  }

  return {
    success: true,
    data: parsed as VaultBackupFile
  };
}

/**
 * Initiates a browser download of the exported JSON backup file.
 */
export function triggerBackupDownload(backup: VaultBackupFile, filename?: string): void {
  const json = JSON.stringify(backup, null, 2);
  const now = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const finalFilename = filename || `vaultguard-backup-${now}.json`;

  if (typeof window === "undefined" || typeof document === "undefined") {
    // Non-browser / Node testing environment
    return;
  }

  const blob = new Blob([json], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = finalFilename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
