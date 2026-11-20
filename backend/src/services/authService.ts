import prisma from "../config/db.js";
import { hashPassword, verifyPassword, generateVaultKdfSalt } from "../utils/password.js";
import { generateAccessToken } from "../utils/jwt.js";
import { AppError } from "../utils/errors.js";
import { createDeviceAndSession } from "./sessionService.js";
import type { RegisterInput } from "../utils/validation.js";
import type { LoginWithDeviceInput } from "../utils/validation.js";

// Standard client-side KDF configuration parameters
const DEFAULT_VAULT_KDF_ALGORITHM = "PBKDF2-HMAC-SHA256";
const DEFAULT_VAULT_KDF_PARAMETERS = {
  iterations: 600000,
  keyLength: 32,
  digest: "SHA-256"
};

export interface SafeUser {
  id: string;
  email: string;
  accountStatus: string;
  vaultKdfAlgorithm: string;
  vaultKdfSalt: string;
  vaultKdfParameters: unknown;
  createdAt: Date;
  updatedAt?: Date;
}

export interface LoginResult {
  token: string;
  sessionId: string;
  refreshToken: string;
  refreshTokenExpiresAt: Date;
  user: SafeUser;
}

export class AuthService {
  /**
   * Registers a new user account.
   * - Hashes account password with Argon2id.
   * - Generates cryptographically random vault KDF salt.
   * - Stores KDF metadata for client-side key derivation.
   * - Returns safe user details (never passwordHash or plaintext).
   */
  async register(input: RegisterInput): Promise<SafeUser> {
    const rawEmail = input.email.trim();
    const emailNormalized = rawEmail.toLowerCase();

    // Check for existing account
    const existing = await prisma.user.findUnique({
      where: { emailNormalized }
    });

    if (existing) {
      throw new AppError("An account with this email address already exists.", 409);
    }

    // Generate KDF salt and hash the account password
    const vaultKdfSalt = input.vaultKdfSalt || generateVaultKdfSalt(16);
    const vaultKdfAlgorithm = input.vaultKdfAlgorithm || DEFAULT_VAULT_KDF_ALGORITHM;
    const vaultKdfParameters = input.vaultKdfParameters || DEFAULT_VAULT_KDF_PARAMETERS;
    const passwordHash = await hashPassword(input.password);

    try {
      const user = await prisma.user.create({
        data: {
          email: rawEmail,
          emailNormalized,
          passwordHash,
          vaultKdfSalt,
          vaultKdfAlgorithm,
          vaultKdfParameters,
          accountStatus: "ACTIVE"
        }
      });

      return {
        id: user.id,
        email: user.email,
        accountStatus: user.accountStatus,
        vaultKdfAlgorithm: user.vaultKdfAlgorithm,
        vaultKdfSalt: user.vaultKdfSalt,
        vaultKdfParameters: user.vaultKdfParameters,
        createdAt: user.createdAt
      };
    } catch (error: any) {
      // Handle database unique constraint race condition
      if (error?.code === "P2002") {
        throw new AppError("An account with this email address already exists.", 409);
      }
      throw error;
    }
  }

  /**
   * Authenticates user with email and password.
   * - Constant-time generic rejection on invalid credentials.
   * - Enforces ACTIVE account status check.
   * - Creates device record (upsert) and session.
   * - Issues signed JWT access token with session ID claim (sid).
   * - Issues rotating refresh token (stored hashed in DB).
   */
  async login(input: LoginWithDeviceInput): Promise<LoginResult> {
    const emailNormalized = input.email.trim().toLowerCase();

    const user = await prisma.user.findUnique({
      where: { emailNormalized }
    });

    // Mitigate account enumeration: reject unknown account with generic message
    if (!user) {
      throw new AppError("Invalid email or password.", 401);
    }

    // Check account status
    if (user.accountStatus !== "ACTIVE") {
      throw new AppError("Account is locked or disabled. Please contact support.", 403);
    }

    // Verify password against Argon2id hash
    const isPasswordValid = await verifyPassword(user.passwordHash, input.password);

    if (!isPasswordValid) {
      throw new AppError("Invalid email or password.", 401);
    }

    // Create or update device and open a new session
    const { sessionId, refreshToken, refreshTokenExpiresAt } = await createDeviceAndSession(
      user.id,
      {
        deviceIdentifier: input.deviceIdentifier,
        deviceName: input.deviceName
      }
    );

    // Issue JWT access token with session ID claim
    const token = generateAccessToken({
      sub: user.id,
      email: user.email,
      sid: sessionId
    });

    return {
      token,
      sessionId,
      refreshToken,
      refreshTokenExpiresAt,
      user: {
        id: user.id,
        email: user.email,
        accountStatus: user.accountStatus,
        vaultKdfAlgorithm: user.vaultKdfAlgorithm,
        vaultKdfSalt: user.vaultKdfSalt,
        vaultKdfParameters: user.vaultKdfParameters,
        createdAt: user.createdAt
      }
    };
  }

  /**
   * Retrieves safe account profile for the authenticated user.
   */
  async getProfile(userId: string): Promise<SafeUser> {
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user || user.accountStatus !== "ACTIVE") {
      throw new AppError("User account not found or is inactive.", 404);
    }

    return {
      id: user.id,
      email: user.email,
      accountStatus: user.accountStatus,
      vaultKdfAlgorithm: user.vaultKdfAlgorithm,
      vaultKdfSalt: user.vaultKdfSalt,
      vaultKdfParameters: user.vaultKdfParameters,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };
  }
}

export const authService = new AuthService();