import type { Request, Response, NextFunction } from "express";
import { type ZodType } from "zod";
import { findForbiddenPlaintextKey } from "../utils/vaultValidation.js";

/**
 * Middleware factory that validates request body against a Zod schema.
 * Rejects with a structured 400 response without leaking internal details or password values.
 * Can optionally enforce Zero-Knowledge guards against transmission of client-side encryption secrets and plaintext fields.
 */
export const validateBody = (
  schema: ZodType,
  options: { checkZeroKnowledge?: boolean } = {}
) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    // Explicit Zero-Knowledge architecture guard against plaintext fields and client secrets on vault endpoints
    if (options.checkZeroKnowledge && req.body && typeof req.body === "object") {
      const violation = findForbiddenPlaintextKey(req.body);

      if (violation) {
        res.status(400).json({
          success: false,
          message: `Zero-Knowledge Violation: '${violation}' must never be transmitted to the backend. Vault encryption is strictly client-side.`
        });
        return;
      }
    }

    const result = schema.safeParse(req.body);

    if (!result.success) {
      const formattedErrors = result.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message
      }));

      res.status(400).json({
        success: false,
        message: "Invalid request payload",
        errors: formattedErrors
      });
      return;
    }

    req.body = result.data;
    next();
  };
};

/**
 * Convenience middleware for vault endpoints enforcing Zero-Knowledge checks
 */
export const validateVaultBody = (schema: ZodType) => {
  return validateBody(schema, { checkZeroKnowledge: true });
};

/**
 * Middleware factory that validates URL parameters against a Zod schema (e.g. UUID formatting).
 */
export const validateParams = (schema: ZodType) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.params);

    if (!result.success) {
      const formattedErrors = result.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message
      }));

      res.status(400).json({
        success: false,
        message: "Invalid URL parameters",
        errors: formattedErrors
      });
      return;
    }

    req.params = result.data as any;
    next();
  };
};
