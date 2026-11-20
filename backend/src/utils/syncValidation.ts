import { z } from "zod";

/**
 * Validation schema for GET /api/sync/changes query parameters.
 * - since: non-negative integer cursor, defaults to 0
 * - limit: positive integer between 1 and 500, defaults to 100
 * Strictly rejects negative values, non-integers, floats, non-numeric strings, and limits > 500.
 * Rejects unexpected query parameters like userId.
 */
export const syncChangesQuerySchema = z
  .object({
    since: z
      .string()
      .optional()
      .default("0")
      .refine((val) => /^\d+$/.test(val), {
        message: "Query parameter 'since' must be a non-negative integer"
      })
      .transform((val) => parseInt(val, 10)),
    limit: z
      .string()
      .optional()
      .default("100")
      .refine((val) => /^[1-9]\d*$/.test(val), {
        message: "Query parameter 'limit' must be a positive integer"
      })
      .transform((val) => parseInt(val, 10))
      .refine((val) => val >= 1 && val <= 500, {
        message: "Query parameter 'limit' must be between 1 and 500"
      })
  })
  .strict();

export type SyncChangesQuery = z.infer<typeof syncChangesQuerySchema>;
