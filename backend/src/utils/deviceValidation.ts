import { z } from "zod";

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates the :id URL parameter as a UUID v4.
 */
export const deviceIdParamSchema = z.object({
  id: z
    .string()
    .regex(UUID_REGEX, "Device ID must be a valid UUID")
});

export type DeviceIdParam = z.infer<typeof deviceIdParamSchema>;
