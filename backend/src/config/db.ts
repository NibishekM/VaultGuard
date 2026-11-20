/**
 * VaultGuard – Prisma Database Client (Phase 2)
 *
 * Uses Prisma 7's mandatory driver adapter pattern.
 * The MariaDB adapter is compatible with MySQL 8 self-hosted servers.
 *
 * PrismaClient is created lazily on first access via getPrisma().
 * This avoids env-var validation running at module load time (before dotenv
 * has had a chance to run), which is a common issue with CommonJS hoisting.
 *
 * In development, a global guard prevents creating multiple PrismaClient
 * instances during tsx watch hot-reloads.
 *
 * Database credentials are read exclusively from environment variables.
 * No credentials are logged or exposed in error messages.
 */

import { PrismaClient } from "../generated/prisma/client.js";
import { PrismaMariaDb } from "@prisma/adapter-mariadb";

declare global {
  // eslint-disable-next-line no-var
  var __prismaClient: PrismaClient | undefined;
}

function createPrismaClient(): PrismaClient {
  // Validate required database environment variables.
  // Fail fast with a clear message rather than a cryptic connection error later.
  const requiredEnvVars = [
    "DATABASE_HOST",
    "DATABASE_PORT",
    "DATABASE_USER",
    "DATABASE_PASSWORD",
    "DATABASE_NAME",
  ] as const;

  for (const key of requiredEnvVars) {
    if (!process.env[key]) {
      throw new Error(
        `[VaultGuard] Missing required environment variable: ${key}. ` +
        "Check your .env file against .env.example."
      );
    }
  }

  // Pass PoolConfig directly to the adapter constructor.
  // PrismaMariaDb accepts mariadb.Pool | mariadb.PoolConfig | string.
  // Using PoolConfig avoids importing the mariadb package directly and prevents
  // TypeScript type conflicts between different mariadb package versions.
  const adapter = new PrismaMariaDb({
    host: process.env.DATABASE_HOST!,
    port: Number(process.env.DATABASE_PORT),
    user: process.env.DATABASE_USER!,
    password: process.env.DATABASE_PASSWORD!,
    database: process.env.DATABASE_NAME!,
    connectionLimit: 5,
    connectTimeout: 10000,
  });

  return new PrismaClient({
    adapter,
    log:
      process.env.NODE_ENV === "development"
        ? ["warn", "error"]
        : ["error"],
  });
}

/**
 * Returns the shared PrismaClient instance.
 * Creates it on first call; subsequent calls return the cached instance.
 * Uses a global guard in development to survive tsx hot-reloads.
 */
function getPrisma(): PrismaClient {
  if (!global.__prismaClient) {
    global.__prismaClient = createPrismaClient();
  }
  return global.__prismaClient;
}

export default getPrisma();

