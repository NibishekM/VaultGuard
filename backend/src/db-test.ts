/**
 * VaultGuard – Database Connectivity Test Script (Phase 2)
 *
 * Run with: npm run db:test
 *
 * tsx --env-file=.env loads the .env file before any module executes,
 * so database env vars are available when db.ts initialises.
 *
 * This script does NOT:
 * - Create, modify, or drop any tables
 * - Insert or read application data
 * - Access or modify any database other than DATABASE_NAME
 *
 * Exit codes:
 *   0 – connection and query succeeded
 *   1 – connection failed (see error message)
 */

import prisma from "./config/db.js";

async function testDatabaseConnection(): Promise<void> {
  console.log("[VaultGuard] Starting database connectivity test...");
  console.log(`[VaultGuard] Target database : ${process.env.DATABASE_NAME}`);
  console.log(`[VaultGuard] Host            : ${process.env.DATABASE_HOST}:${process.env.DATABASE_PORT}`);

  try {
    // Execute a minimal query to confirm the connection and query pipeline work.
    // $queryRaw is the standard Prisma approach for raw SQL verification.
    const result = await prisma.$queryRaw<[{ "1": number }]>`SELECT 1`;

    if (result && Array.isArray(result) && result.length > 0) {
      console.log("[VaultGuard] ✓ Database connection established successfully.");
      console.log("[VaultGuard] ✓ SELECT 1 executed and returned a result.");
      console.log("[VaultGuard] ✓ MySQL 8 is reachable and responding.");
    } else {
      console.error("[VaultGuard] ✗ SELECT 1 returned an unexpected empty result.");
      process.exit(1);
    }
  } catch (error: unknown) {
    if (error instanceof Error) {
      const safeMessage = error.message
        .replace(/password=[^\s&]*/gi, "password=***")
        .replace(/:[^:@]+@/g, ":***@");

      console.error("[VaultGuard] ✗ Database connection failed.");
      console.error(`[VaultGuard]   Error: ${safeMessage}`);

      if (safeMessage.includes("ECONNREFUSED")) {
        console.error("[VaultGuard]   → MySQL server is not running or the host/port is incorrect.");
      } else if (safeMessage.includes("ER_ACCESS_DENIED")) {
        console.error("[VaultGuard]   → MySQL credentials are incorrect.");
      } else if (safeMessage.includes("ER_BAD_DB_ERROR")) {
        console.error(
          `[VaultGuard]   → Database '${process.env.DATABASE_NAME}' does not exist. Create it first.`
        );
      }
    } else {
      console.error("[VaultGuard] ✗ An unexpected non-Error was thrown.");
    }
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

testDatabaseConnection();
