import { z } from "zod";

/**
 * Registration Validation Schema
 *
 * Rules:
 * - Email: valid email format, max 255 chars
 * - Password: min 12 chars for strong entropy, max 128 chars to mitigate CPU denial-of-service
 * - Plaintext passwords are NEVER trimmed or modified by the backend
 * - Strict rejection of forbidden master password / encryption key fields
 */
export const registerSchema = z
  .object({
    email: z
      .string()
      .email("Invalid email address format")
      .max(255, "Email address must not exceed 255 characters"),
    password: z
      .string()
      .min(12, "Password must be at least 12 characters long")
      .max(128, "Password must not exceed 128 characters"),
    vaultKdfSalt: z.string().max(255).optional(),
    vaultKdfAlgorithm: z.string().max(50).optional(),
    vaultKdfParameters: z.record(z.string(), z.any()).optional()
  })
  .strict();

export type RegisterInput = z.infer<typeof registerSchema>;

/**
 * Login Validation Schema (strict — no extra fields allowed)
 */
export const loginSchema = z
  .object({
    email: z
      .string()
      .email("Invalid email address format")
      .max(255, "Email address must not exceed 255 characters"),
    password: z
      .string()
      .min(1, "Password is required")
      .max(128, "Password must not exceed 128 characters")
  })
  .strict();

export type LoginInput = z.infer<typeof loginSchema>;

/**
 * Login with optional device registration schema.
 * Extends loginSchema with optional device fingerprint fields.
 * Not strict — additional future fields are ignored.
 */
export const loginWithDeviceSchema = z.object({
  email: z
    .string()
    .email("Invalid email address format")
    .max(255, "Email address must not exceed 255 characters"),
  password: z
    .string()
    .min(1, "Password is required")
    .max(128, "Password must not exceed 128 characters"),
  deviceIdentifier: z.string().min(1).max(255).optional(),
  deviceName: z.string().min(1).max(255).optional()
});

export type LoginWithDeviceInput = z.infer<typeof loginWithDeviceSchema>;

/**
 * Refresh token request body (cookie-only — no body needed; schema is a placeholder for future fields)
 */
export const refreshSchema = z.object({}).passthrough();
