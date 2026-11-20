import type { Request, Response, NextFunction } from "express";

export interface ApiError extends Error {
  statusCode?: number;
  status?: number;
}

/**
 * 404 Not Found Middleware
 * Handles requests to undefined endpoints with a structured JSON response.
 */
export const notFoundHandler = (
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  res.status(404).json({
    success: false,
    message: "Resource not found"
  });
};

/**
 * Centralized Error Handling Middleware
 * Ensures safe and structured error responses.
 * Stack traces and internal error details are suppressed in production.
 */
export const errorHandler = (
  err: ApiError,
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  let statusCode =
    typeof err.statusCode === "number"
      ? err.statusCode
      : typeof err.status === "number"
        ? err.status
        : 500;

  let message = err.message || "An unexpected error occurred";

  // Phase 9.2 (Fix E): Map Prisma unique constraint P2002 to HTTP 409 Conflict
  const errCode = (err as any)?.code;
  if (errCode === "P2002" || (err.name === "PrismaClientKnownRequestError" && errCode === "P2002")) {
    statusCode = 409;
    message = "Resource conflict: A record with this unique identifier already exists.";
  }

  const isProduction = process.env.NODE_ENV === "production";

  // Prevent leaking internal errors or stack traces in production
  const finalMessage =
    isProduction && statusCode === 500
      ? "Internal Server Error"
      : message;

  res.status(statusCode).json({
    success: false,
    message: finalMessage,
    ...(isProduction ? {} : { stack: err.stack })
  });
};

