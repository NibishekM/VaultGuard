import { z } from "zod";

/**
 * Validates that a string is syntactically valid and canonically-encoded Base64.
 * Enforces standard Base64 character sets, multiple of 4 length, correct padding,
 * and byte round-trip equality to prevent ambiguous or trailing bit injection.
 */
export function isValidCanonicalBase64(val: string): boolean {
  if (typeof val !== "string" || val.length === 0 || val.length % 4 !== 0) {
    return false;
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(val)) {
    return false;
  }
  try {
    const buf = Buffer.from(val, "base64");
    return buf.toString("base64") === val;
  } catch {
    return false;
  }
}

/**
 * Forbidden plaintext keys that must NEVER be accepted by the backend.
 * Zero-Knowledge architecture mandates client-side encryption of all metadata.
 */
export const FORBIDDEN_PLAINTEXT_KEYS = [
  "service",
  "name",
  "title",
  "username",
  "password",
  "website",
  "url",
  "category",
  "notes",
  "favorite",
  "masterPassword",
  "encryptionKey",
  "secret",
  "demoSecret"
] as const;

const FORBIDDEN_LOWER_KEYS = new Set(
  FORBIDDEN_PLAINTEXT_KEYS.map((k) => k.toLowerCase())
);

/**
 * Recursively inspects object keys for forbidden plaintext or client-side secret field names (case-insensitive).
 * Inspects only property keys, never property values (ensuring binary/Base64 ciphertext values are never falsely flagged).
 */
export function findForbiddenPlaintextKey(data: unknown, depth = 0): string | null {
  if (!data || typeof data !== "object" || depth > 10) {
    return null;
  }

  if (Array.isArray(data)) {
    for (const item of data) {
      const violation = findForbiddenPlaintextKey(item, depth + 1);
      if (violation) return violation;
    }
    return null;
  }

  for (const key of Object.keys(data)) {
    if (FORBIDDEN_LOWER_KEYS.has(key.toLowerCase())) {
      return key;
    }
    const val = (data as Record<string, unknown>)[key];
    if (val && typeof val === "object") {
      const violation = findForbiddenPlaintextKey(val, depth + 1);
      if (violation) return violation;
    }
  }

  return null;
}

/**
 * Zod Schema for POST /api/vault
 * Rejects unexpected properties, enforces 12-byte IV, 16-byte tag, non-empty payload <= 1 MiB.
 */
export const createVaultItemSchema = z
  .object({
    encryptedPayload: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "encryptedPayload must be a valid, canonically-encoded Base64 string"
      })
      .refine(
        (val) => {
          const len = Buffer.from(val, "base64").length;
          return len > 0 && len <= 1024 * 1024;
        },
        {
          message: "encryptedPayload must be non-empty and at most 1 MiB (1,048,576 bytes) when decoded"
        }
      ),
    initializationVector: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "initializationVector must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 12, {
        message: "initializationVector must be exactly 12 bytes (96 bits) when decoded"
      }),
    authenticationTag: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "authenticationTag must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 16, {
        message: "authenticationTag must be exactly 16 bytes (128 bits) when decoded"
      }),
    encryptionAlgorithm: z
      .enum(["AES-256-GCM"])
      .default("AES-256-GCM"),
    encryptionVersion: z
      .number()
      .int("encryptionVersion must be an integer")
      .positive("encryptionVersion must be a positive integer")
      .default(1)
  })
  .strict();

export type CreateVaultItemInput = z.infer<typeof createVaultItemSchema>;

/**
 * Zod Schema for PUT /api/vault/:id
 * Requires expectedRevision for optimistic concurrency conflict detection.
 */
export const updateVaultItemSchema = z
  .object({
    encryptedPayload: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "encryptedPayload must be a valid, canonically-encoded Base64 string"
      })
      .refine(
        (val) => {
          const len = Buffer.from(val, "base64").length;
          return len > 0 && len <= 1024 * 1024;
        },
        {
          message: "encryptedPayload must be non-empty and at most 1 MiB (1,048,576 bytes) when decoded"
        }
      ),
    initializationVector: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "initializationVector must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 12, {
        message: "initializationVector must be exactly 12 bytes (96 bits) when decoded"
      }),
    authenticationTag: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "authenticationTag must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 16, {
        message: "authenticationTag must be exactly 16 bytes (128 bits) when decoded"
      }),
    encryptionAlgorithm: z
      .enum(["AES-256-GCM"])
      .default("AES-256-GCM"),
    encryptionVersion: z
      .number()
      .int("encryptionVersion must be an integer")
      .positive("encryptionVersion must be a positive integer")
      .default(1),
    expectedRevision: z
      .number()
      .int("expectedRevision must be an integer")
      .positive("expectedRevision must be a positive integer")
  })
  .strict();

export type UpdateVaultItemInput = z.infer<typeof updateVaultItemSchema>;

/**
 * Zod Schema for URL parameter :id
 */
export const vaultItemIdParamSchema = z
  .object({
    id: z.string().uuid("Invalid vault item ID format (must be a valid UUID)")
  })
  .strict();

/**
 * Zod Schema for POST /api/vault/verification
 * Enforces AES-256-GCM verification canary payload structure:
 * 12-byte IV, 16-byte tag, non-empty payload <= 64 KiB.
 * Optional isLegacyMigration flag for migrating legacy accounts.
 */
export const createVaultVerificationSchema = z
  .object({
    encryptedPayload: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "encryptedPayload must be a valid, canonically-encoded Base64 string"
      })
      .refine(
        (val) => {
          const len = Buffer.from(val, "base64").length;
          return len > 0 && len <= 65536;
        },
        {
          message: "encryptedPayload must be non-empty and at most 64 KiB when decoded"
        }
      ),
    initializationVector: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "initializationVector must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 12, {
        message: "initializationVector must be exactly 12 bytes (96 bits) when decoded"
      }),
    authenticationTag: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "authenticationTag must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 16, {
        message: "authenticationTag must be exactly 16 bytes (128 bits) when decoded"
      }),
    encryptionAlgorithm: z
      .enum(["AES-256-GCM"])
      .default("AES-256-GCM"),
    encryptionVersion: z
      .number()
      .int("encryptionVersion must be an integer")
      .positive("encryptionVersion must be a positive integer")
      .default(1),
    isLegacyMigration: z
      .boolean()
      .optional()
      .default(false)
  })
  .strict();

export type CreateVaultVerificationInput = z.infer<typeof createVaultVerificationSchema>;

/**
 * Zod Schema for an individual item in POST /api/vault/batch-import
 */
export const batchImportItemSchema = z
  .object({
    id: z.string().uuid("Item id must be a valid UUID").optional(),
    encryptedPayload: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "encryptedPayload must be a valid, canonically-encoded Base64 string"
      })
      .refine(
        (val) => {
          const len = Buffer.from(val, "base64").length;
          return len > 0 && len <= 1024 * 1024;
        },
        {
          message: "encryptedPayload must be non-empty and at most 1 MiB (1,048,576 bytes) when decoded"
        }
      ),
    initializationVector: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "initializationVector must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 12, {
        message: "initializationVector must be exactly 12 bytes (96 bits) when decoded"
      }),
    authenticationTag: z
      .string()
      .refine(isValidCanonicalBase64, {
        message: "authenticationTag must be a valid, canonically-encoded Base64 string"
      })
      .refine((val) => Buffer.from(val, "base64").length === 16, {
        message: "authenticationTag must be exactly 16 bytes (128 bits) when decoded"
      }),
    encryptionAlgorithm: z
      .enum(["AES-256-GCM"])
      .default("AES-256-GCM"),
    encryptionVersion: z
      .number()
      .int("encryptionVersion must be an integer")
      .positive("encryptionVersion must be a positive integer")
      .default(1),
    revision: z
      .number()
      .int("revision must be an integer")
      .positive("revision must be a positive integer")
      .optional()
      .default(1),
    createdAt: z
      .string()
      .refine((val) => !isNaN(Date.parse(val)), { message: "Invalid date format for createdAt" })
      .optional(),
    updatedAt: z
      .string()
      .refine((val) => !isNaN(Date.parse(val)), { message: "Invalid date format for updatedAt" })
      .optional()
  })
  .strict();

export type BatchImportItemInput = z.infer<typeof batchImportItemSchema>;

/**
 * Zod Schema for POST /api/vault/batch-import
 */
export const batchImportVaultSchema = z
  .object({
    items: z
      .array(batchImportItemSchema)
      .min(1, "Import payload must contain at least 1 item")
      .max(1000, "Import payload cannot exceed 1,000 items per batch"),
    strategy: z
      .enum(["error", "skip"])
      .optional()
      .default("error")
  })
  .strict();

export type BatchImportVaultInput = z.infer<typeof batchImportVaultSchema>;
