import jwt from "jsonwebtoken";

export interface TokenPayload {
  sub: string;
  email: string;
  sid: string;
  iat?: number;
  exp?: number;
}

const MIN_SECRET_LENGTH = 32;

/**
 * Retrieves and validates the JWT secret from environment configuration.
 * Throws an explicit error if missing or insufficiently long, refusing to use fallback keys.
 */
function getJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.trim().length < MIN_SECRET_LENGTH) {
    throw new Error(
      `[VaultGuard] Security Configuration Error: JWT_SECRET environment variable is missing or shorter than ${MIN_SECRET_LENGTH} characters.`
    );
  }
  return secret;
}

/**
 * Startup validation function to ensure cryptographic JWT configuration is valid before accepting traffic.
 */
export function validateJwtConfiguration(): void {
  getJwtSecret();
}

/**
 * Generates a signed JWT access token for an authenticated user.
 */
export function generateAccessToken(payload: { sub: string; email: string; sid: string }): string {
  const secret = getJwtSecret();
  const expiresIn = (process.env.JWT_EXPIRES_IN || "15m") as jwt.SignOptions["expiresIn"];

  return jwt.sign(payload, secret, {
    algorithm: "HS256",
    expiresIn
  });
}

/**
 * Verifies and decodes a JWT access token.
 * Enforces algorithm restriction to HS256 to prevent algorithm confusion attacks.
 */
export function verifyAccessToken(token: string): TokenPayload {
  const secret = getJwtSecret();

  const decoded = jwt.verify(token, secret, {
    algorithms: ["HS256"]
  });

  return decoded as TokenPayload;
}
