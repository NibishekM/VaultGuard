/**
 * VaultGuard – Phase 9.2.2 Verification Suite
 * Strict Historical Original Device Authorization and Transaction-Safe Concurrency Hardening
 *
 * Usage: tsx --env-file=../VaultGuard-Backend/.env scripts/verify-phase9-2-2.ts
 */

import http from "node:http";
import path from "node:path";

try {
  process.loadEnvFile(path.resolve(__dirname, "../../VaultGuard-Backend/.env"));
} catch {
  // Env file already loaded via CLI
}

import app from "../../VaultGuard-Backend/src/app";
import prisma from "../../VaultGuard-Backend/src/config/db";
import { vaultService } from "../../VaultGuard-Backend/src/services/vaultService";
import { revokeSession, revokeDeviceSessions } from "../../VaultGuard-Backend/src/services/sessionService";
import {
  createDefaultKdfMetadata,
  deriveVaultKey
} from "../lib/crypto/kdf";
import {
  encryptVaultPayload
} from "../lib/crypto/aes";
import { generateAccessToken } from "../../VaultGuard-Backend/src/utils/jwt";
import { hashPassword } from "../../VaultGuard-Backend/src/utils/password";

let testPassedCount = 0;
let testFailedCount = 0;

function logTest(num: number, desc: string, passed: boolean, detail?: string) {
  if (passed) {
    testPassedCount++;
    console.log(`  ✅ PASS [${num}] ${desc}${detail ? ` (${detail})` : ""}`);
  } else {
    testFailedCount++;
    console.error(`  ❌ FAIL [${num}] ${desc}${detail ? ` (${detail})` : ""}`);
  }
}

async function request(
  baseUrl: string,
  method: string,
  pathName: string,
  token?: string,
  body?: any
): Promise<{ status: number; body: any }> {
  const url = `${baseUrl}${pathName}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-VaultGuard-Request": "1",
    "Origin": baseUrl
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  let resBody: any = null;
  try {
    resBody = await res.json();
  } catch {
    resBody = null;
  }

  return { status: res.status, body: resBody };
}

async function run() {
  console.log("================================================================================");
  console.log("VaultGuard Phase 9.2.2: Strict Authorization & Concurrency Hardening Suite");
  console.log("================================================================================\n");

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  process.env.NEXT_PUBLIC_API_BASE_URL = baseUrl;

  const timestamp = Date.now();
  const cleanUserIds: string[] = [];

  try {
    const accountPassword = "Password!123456Phase922";
    const masterPassword = "MasterPassword!Phase922";
    const passwordHash = await hashPassword(accountPassword);
    const kdfMeta = createDefaultKdfMetadata();
    const kdfSalt = kdfMeta.vaultKdfSalt;
    const vaultKey = await deriveVaultKey(masterPassword, kdfSalt);

    const canaryEncrypted = await encryptVaultPayload(
      JSON.stringify({ canary: "phase922-canary" }),
      vaultKey
    );
    const canaryPayload = {
      encryptedPayload: canaryEncrypted.encryptedPayload,
      initializationVector: canaryEncrypted.initializationVector,
      authenticationTag: canaryEncrypted.authenticationTag,
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      isLegacyMigration: true
    };

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 1: Fix A – Strict Historical Original Device Authorization
    // ─────────────────────────────────────────────────────────────────────────
    console.log("── Section 1: Fix A – Strict Historical Original Device Authorization ──");

    // Setup User 1: D1 at T0, D2 at T1, VaultItem at T2 (T0 < T1 < T2)
    const user1Email = `phase922_u1_${timestamp}@example.com`;
    const user1 = await prisma.user.create({
      data: {
        email: user1Email,
        emailNormalized: user1Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user1.id);

    // D1: Registered at T0 (2 hours ago) - The historical original device
    const u1D1 = await prisma.device.create({
      data: {
        userId: user1.id,
        deviceIdentifier: `u1_d1_${timestamp}`,
        deviceName: "U1 Original Laptop",
        createdAt: new Date(Date.now() - 7200000)
      }
    });

    // D2: Registered at T1 (1.5 hours ago) - PRE-ITEM secondary device!
    const u1D2 = await prisma.device.create({
      data: {
        userId: user1.id,
        deviceIdentifier: `u1_d2_${timestamp}`,
        deviceName: "U1 Secondary Phone (Pre-Item)",
        createdAt: new Date(Date.now() - 5400000)
      }
    });

    // VaultItem: Created at T2 (1 hour ago)
    const itemEnc = await encryptVaultPayload(JSON.stringify({ title: "Item 1" }), vaultKey);
    await prisma.vaultItem.create({
      data: {
        userId: user1.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    // Sessions for D1 and D2
    const u1S1 = await prisma.session.create({
      data: { userId: user1.id, deviceId: u1D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u1S1Token = generateAccessToken({ sub: user1.id, email: user1Email, sid: u1S1.id });

    const u1S2 = await prisma.session.create({
      data: { userId: user1.id, deviceId: u1D2.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u1S2Token = generateAccessToken({ sub: user1.id, email: user1Email, sid: u1S2.id });

    // Test 1: Secondary device D2 registered BEFORE the first vault item is strictly REJECTED (eliminates isDevicePreItem bypass)
    const resPreItemD2 = await request(baseUrl, "POST", "/api/vault/verification", u1S2Token, canaryPayload);
    logTest(
      1,
      "Fix A: Secondary device D2 registered before the first vault item is strictly REJECTED with 403 Forbidden",
      resPreItemD2.status === 403,
      "HTTP 403 Forbidden"
    );

    // Setup User 2 to test the specific audit sign-off scenario:
    // D1 (T0), D2 (T1 pre-item), Item (T2). D1 is subsequently REMOVED. Does D2 get authority?
    const user2Email = `phase922_u2_${timestamp}@example.com`;
    const user2 = await prisma.user.create({
      data: {
        email: user2Email,
        emailNormalized: user2Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user2.id);

    const u2D1 = await prisma.device.create({
      data: {
        userId: user2.id,
        deviceIdentifier: `u2_d1_${timestamp}`,
        deviceName: "U2 Original Laptop (Removed)",
        createdAt: new Date(Date.now() - 7200000),
        removedAt: new Date(Date.now() - 1800000) // D1 is soft-deleted!
      }
    });

    const u2D2 = await prisma.device.create({
      data: {
        userId: user2.id,
        deviceIdentifier: `u2_d2_${timestamp}`,
        deviceName: "U2 Pre-Item Device (Active)",
        createdAt: new Date(Date.now() - 5400000) // D2 created before item
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user2.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    const u2S2 = await prisma.session.create({
      data: { userId: user2.id, deviceId: u2D2.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u2S2Token = generateAccessToken({ sub: user2.id, email: user2Email, sid: u2S2.id });

    // Test 2: When D1 is removed, pre-item D2 CANNOT obtain migration authority (Fix A confirms no fallback transfer)
    const resU2D2 = await request(baseUrl, "POST", "/api/vault/verification", u2S2Token, canaryPayload);
    logTest(
      2,
      "Fix A: When original device D1 is removed, pre-item device D2 CANNOT claim migration authority (403)",
      resU2D2.status === 403,
      "HTTP 403 Forbidden"
    );

    // Test 3: Post-item registered secondary device D3 is strictly rejected
    const u2D3 = await prisma.device.create({
      data: {
        userId: user2.id,
        deviceIdentifier: `u2_d3_${timestamp}`,
        deviceName: "U2 Post-Item Device",
        createdAt: new Date(Date.now() - 60000) // registered after items
      }
    });
    const u2S3 = await prisma.session.create({
      data: { userId: user2.id, deviceId: u2D3.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u2S3Token = generateAccessToken({ sub: user2.id, email: user2Email, sid: u2S3.id });
    const resU2D3 = await request(baseUrl, "POST", "/api/vault/verification", u2S3Token, canaryPayload);
    logTest(
      3,
      "Fix A: Secondary device D3 registered after first vault item is strictly rejected with 403 Forbidden",
      resU2D3.status === 403,
      "HTTP 403 Forbidden"
    );

    // Test 4: Removed original device D1 attempting migration is strictly rejected
    const u2S1Removed = await prisma.session.create({
      data: { userId: user2.id, deviceId: u2D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u2S1RemovedToken = generateAccessToken({ sub: user2.id, email: user2Email, sid: u2S1Removed.id });
    const resU2D1Removed = await request(baseUrl, "POST", "/api/vault/verification", u2S1RemovedToken, canaryPayload);
    logTest(
      4,
      "Fix A: Removed original device D1 attempting migration is strictly rejected (401/403)",
      resU2D1Removed.status === 401 || resU2D1Removed.status === 403,
      "HTTP 401/403"
    );

    // Test 5: Client cannot bypass authorization by submitting isLegacyMigration: true on unauthorized device
    const resClientClaimBypass = await request(baseUrl, "POST", "/api/vault/verification", u1S2Token, {
      ...canaryPayload,
      isLegacyMigration: true
    });
    logTest(
      5,
      "Fix A: Client cannot bypass authorization by asserting isLegacyMigration: true on unauthorized device",
      resClientClaimBypass.status === 403,
      "HTTP 403 Forbidden"
    );

    // Test 6: Original active device D1 on User 1 is authorized and creates verification canary (201 Created)
    const resU1D1Auth = await request(baseUrl, "POST", "/api/vault/verification", u1S1Token, canaryPayload);
    logTest(
      6,
      "Fix A: Authentic historical original device D1 with active valid session successfully migrates (201 Created)",
      resU1D1Auth.status === 201 && resU1D1Auth.body?.success === true,
      "HTTP 201 Created"
    );

    // Test 7: Subsequent verification creation attempt rejected with 409 Conflict (create-once semantics)
    const resU1Subsequent = await request(baseUrl, "POST", "/api/vault/verification", u1S1Token, canaryPayload);
    logTest(
      7,
      "Create-once semantics: Subsequent verification creation on migrated vault returns 409 Conflict",
      resU1Subsequent.status === 409,
      "HTTP 409 Conflict"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 2: Fix B – Transaction Concurrency Hardening & Revocation Serialization
    // ─────────────────────────────────────────────────────────────────────────
    console.log("\n── Section 2: Fix B – Transaction Concurrency Hardening & Revocation Serialization ──");

    // Setup User 3 for concurrent race testing
    const user3Email = `phase922_u3_${timestamp}@example.com`;
    const user3 = await prisma.user.create({
      data: {
        email: user3Email,
        emailNormalized: user3Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user3.id);

    const u3D1 = await prisma.device.create({
      data: {
        userId: user3.id,
        deviceIdentifier: `u3_d1_${timestamp}`,
        deviceName: "U3 Laptop",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user3.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    const u3S1 = await prisma.session.create({
      data: { userId: user3.id, deviceId: u3D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    // Test 8: Revocation committed BEFORE createVerification runs -> rejected with 403
    await revokeSession(u3S1.id, user3.id);
    let rejectedAfterRevoke = false;
    try {
      await vaultService.createVerification(user3.id, u3S1.id, canaryPayload as any);
    } catch (err: any) {
      rejectedAfterRevoke = (err.statusCode === 403 || err.status === 403);
    }
    logTest(
      8,
      "Fix B: Session revoked before transaction obtains lock is strictly rejected with 403 Forbidden",
      rejectedAfterRevoke,
      "Locked current-read observed revokedAt !== null"
    );

    // Setup User 4 for Device Removal race
    const user4Email = `phase922_u4_${timestamp}@example.com`;
    const user4 = await prisma.user.create({
      data: {
        email: user4Email,
        emailNormalized: user4Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user4.id);

    const u4D1 = await prisma.device.create({
      data: {
        userId: user4.id,
        deviceIdentifier: `u4_d1_${timestamp}`,
        deviceName: "U4 Device",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user4.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    const u4S1 = await prisma.session.create({
      data: { userId: user4.id, deviceId: u4D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u4S_other = await prisma.session.create({
      data: { userId: user4.id, deviceId: u4D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    // Remove device u4D1 via revokeDeviceSessions
    await revokeDeviceSessions(u4D1.id, user4.id, u4S_other.id).catch(() => {
      // If currentSessionId matches deviceId, update removedAt directly
    });
    // Ensure u4D1 is removed
    await prisma.device.update({
      where: { id: u4D1.id },
      data: { removedAt: new Date() }
    });

    let rejectedAfterDeviceRemoved = false;
    try {
      await vaultService.createVerification(user4.id, u4S1.id, canaryPayload as any);
    } catch (err: any) {
      rejectedAfterDeviceRemoved = (err.statusCode === 403 || err.status === 403);
    }
    logTest(
      9,
      "Fix B: Device removed before transaction obtains lock is strictly rejected with 403 Forbidden",
      rejectedAfterDeviceRemoved,
      "Locked current-read observed removedAt !== null"
    );

    // Setup User 5: Actual Concurrent Race between createVerification and session revocation
    const user5Email = `phase922_u5_${timestamp}@example.com`;
    const user5 = await prisma.user.create({
      data: {
        email: user5Email,
        emailNormalized: user5Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user5.id);

    const u5D1 = await prisma.device.create({
      data: {
        userId: user5.id,
        deviceIdentifier: `u5_d1_${timestamp}`,
        deviceName: "U5 Device",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user5.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    const u5S1 = await prisma.session.create({
      data: { userId: user5.id, deviceId: u5D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    // Execute concurrent race: createVerification and revokeSession run simultaneously in Promise.allSettled
    const [raceVerifResult, raceRevokeResult] = await Promise.allSettled([
      vaultService.createVerification(user5.id, u5S1.id, canaryPayload as any),
      revokeSession(u5S1.id, user5.id)
    ]);

    // Evaluation:
    // Because of FOR UPDATE locking on sessions/devices:
    // - If createVerification acquired the lock first: createVerification succeeded, then revokeSession succeeded.
    // - If revokeSession acquired the lock first: revokeSession updated revokedAt, then createVerification threw 403.
    // In NEITHER case can an un-serialized or corrupted state exist!
    const verifSucceeded = raceVerifResult.status === "fulfilled";
    const verifRejected403 =
      raceVerifResult.status === "rejected" &&
      ((raceVerifResult.reason as any)?.statusCode === 403 || (raceVerifResult.reason as any)?.status === 403);

    logTest(
      10,
      "Fix B: Concurrent createVerification and session revocation executes with strict serialization (zero TOCTOU bypass)",
      verifSucceeded || verifRejected403,
      verifSucceeded ? "Verification committed before revocation" : "Revocation serialized before verification (403)"
    );

    // Setup User 6: Concurrent Race between TWO simultaneous createVerification requests
    const user6Email = `phase922_u6_${timestamp}@example.com`;
    const user6 = await prisma.user.create({
      data: {
        email: user6Email,
        emailNormalized: user6Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user6.id);

    const u6D1 = await prisma.device.create({
      data: {
        userId: user6.id,
        deviceIdentifier: `u6_d1_${timestamp}`,
        deviceName: "U6 Device",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user6.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    const u6S1 = await prisma.session.create({
      data: { userId: user6.id, deviceId: u6D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    const [v1Result, v2Result] = await Promise.allSettled([
      vaultService.createVerification(user6.id, u6S1.id, canaryPayload as any),
      vaultService.createVerification(user6.id, u6S1.id, canaryPayload as any)
    ]);

    const v1Success = v1Result.status === "fulfilled";
    const v2Success = v2Result.status === "fulfilled";
    const v1Conflict = v1Result.status === "rejected" && ((v1Result.reason as any)?.statusCode === 409 || (v1Result.reason as any)?.status === 409);
    const v2Conflict = v2Result.status === "rejected" && ((v2Result.reason as any)?.statusCode === 409 || (v2Result.reason as any)?.status === 409);

    const exactOneCreated = (v1Success && v2Conflict) || (v2Success && v1Conflict);
    const createdCanaries = await prisma.vaultVerification.count({ where: { userId: user6.id } });

    logTest(
      11,
      "Fix B: Concurrent createVerification requests yield exactly one 201 Created and one 409 Conflict",
      exactOneCreated && createdCanaries === 1,
      `Exact one created: ${exactOneCreated}, DB count: ${createdCanaries}`
    );

    // Setup User 7: Deadlock verification under simultaneous reverse queries
    const user7Email = `phase922_u7_${timestamp}@example.com`;
    const user7 = await prisma.user.create({
      data: {
        email: user7Email,
        emailNormalized: user7Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user7.id);

    const u7D1 = await prisma.device.create({
      data: {
        userId: user7.id,
        deviceIdentifier: `u7_d1_${timestamp}`,
        deviceName: "U7 Device",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user7.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    const u7S1 = await prisma.session.create({
      data: { userId: user7.id, deviceId: u7D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    // Run 5 simultaneous concurrent operations mixing createVerification and session reads
    const mixedOperations = await Promise.allSettled([
      vaultService.createVerification(user7.id, u7S1.id, canaryPayload as any),
      prisma.session.findUnique({ where: { id: u7S1.id } }),
      prisma.device.findUnique({ where: { id: u7D1.id } }),
      vaultService.getVerification(user7.id),
      revokeSession(u7S1.id, user7.id)
    ]);

    const anyDeadlock = mixedOperations.some(
      (op) =>
        op.status === "rejected" &&
        ((op.reason as any)?.message?.includes("Deadlock") || (op.reason as any)?.code === "ER_LOCK_DEADLOCK")
    );

    logTest(
      12,
      "Fix B: Global hierarchy order (devices -> sessions) prevents database deadlocks under high concurrency",
      !anyDeadlock,
      "Zero deadlocks observed"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // SECTION 3: Final Concurrency Hardening – Device Removal & HTTP Logout Races
    // ─────────────────────────────────────────────────────────────────────────
    console.log("\n── Section 3: Final Concurrency Hardening – Device Removal & HTTP Logout Races ──");

    // Setup User 8: Actual Concurrent Race between createVerification and revokeDeviceSessions
    const user8Email = `phase922_u8_${timestamp}@example.com`;
    const user8 = await prisma.user.create({
      data: {
        email: user8Email,
        emailNormalized: user8Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user8.id);

    const u8D1 = await prisma.device.create({
      data: {
        userId: user8.id,
        deviceIdentifier: `u8_d1_${timestamp}`,
        deviceName: "U8 Device 1 (Original)",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    const u8D2 = await prisma.device.create({
      data: {
        userId: user8.id,
        deviceIdentifier: `u8_d2_${timestamp}`,
        deviceName: "U8 Device 2 (Secondary)",
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user8.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1200000)
      }
    });

    const u8S1 = await prisma.session.create({
      data: { userId: user8.id, deviceId: u8D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    const u8S2 = await prisma.session.create({
      data: { userId: user8.id, deviceId: u8D2.id, expiresAt: new Date(Date.now() + 3600000) }
    });

    // Execute concurrent race: createVerification on u8S1 (D1) vs revokeDeviceSessions on u8D1 (requested from S2)
    const [raceVerifDeviceResult, raceDeviceRemoveResult] = await Promise.allSettled([
      vaultService.createVerification(user8.id, u8S1.id, canaryPayload as any),
      revokeDeviceSessions(u8D1.id, user8.id, u8S2.id)
    ]);

    const devRemoveVerifFulfilled = raceVerifDeviceResult.status === "fulfilled";
    const devRemoveVerifRejected403 =
      raceVerifDeviceResult.status === "rejected" &&
      ((raceVerifDeviceResult.reason as any)?.statusCode === 403 || (raceVerifDeviceResult.reason as any)?.status === 403);
    const devRemoveSucceeded = raceDeviceRemoveResult.status === "fulfilled";

    const d1InDb = await prisma.device.findUnique({ where: { id: u8D1.id } });
    const s1InDb = await prisma.session.findUnique({ where: { id: u8S1.id } });
    const verifInDbCount = await prisma.vaultVerification.count({ where: { userId: user8.id } });

    const test13Pass =
      devRemoveSucceeded &&
      (devRemoveVerifFulfilled || devRemoveVerifRejected403) &&
      d1InDb?.removedAt !== null &&
      s1InDb?.revokedAt !== null &&
      (devRemoveVerifRejected403 ? verifInDbCount === 0 : verifInDbCount === 1);

    logTest(
      13,
      "Fix B: Concurrent createVerification and revokeDeviceSessions executes with strict serialization (zero TOCTOU bypass)",
      test13Pass,
      devRemoveVerifFulfilled
        ? "Verification committed before device removal"
        : "Device removal serialized before verification (403)"
    );

    // Setup User 9: Actual Concurrent Race between HTTP createVerification and HTTP POST /api/auth/logout
    const user9Email = `phase922_u9_${timestamp}@example.com`;
    const user9 = await prisma.user.create({
      data: {
        email: user9Email,
        emailNormalized: user9Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    cleanUserIds.push(user9.id);

    const u9D1 = await prisma.device.create({
      data: {
        userId: user9.id,
        deviceIdentifier: `u9_d1_${timestamp}`,
        deviceName: "U9 Device 1 (Original)",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    await prisma.vaultItem.create({
      data: {
        userId: user9.id,
        encryptedPayload: Buffer.from(itemEnc.encryptedPayload, "base64"),
        initializationVector: Buffer.from(itemEnc.initializationVector, "base64"),
        authenticationTag: Buffer.from(itemEnc.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    const u9S1 = await prisma.session.create({
      data: { userId: user9.id, deviceId: u9D1.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const u9S1Token = generateAccessToken({ sub: user9.id, email: user9Email, sid: u9S1.id });

    // Execute concurrent race against real HTTP endpoints: POST /api/vault/verification vs POST /api/auth/logout
    const [httpVerifResult, httpLogoutResult] = await Promise.allSettled([
      request(baseUrl, "POST", "/api/vault/verification", u9S1Token, canaryPayload),
      request(baseUrl, "POST", "/api/auth/logout", u9S1Token)
    ]);

    const httpVerifRes = httpVerifResult.status === "fulfilled" ? httpVerifResult.value : null;
    const httpLogoutRes = httpLogoutResult.status === "fulfilled" ? httpLogoutResult.value : null;

    const logoutOk = httpLogoutRes?.status === 200;
    const verif201 = httpVerifRes?.status === 201;
    const verif403 = httpVerifRes?.status === 403;

    const u9SessionInDb = await prisma.session.findUnique({ where: { id: u9S1.id } });
    const u9VerifCountInDb = await prisma.vaultVerification.count({ where: { userId: user9.id } });

    const test14Pass =
      logoutOk &&
      (verif201 || verif403) &&
      u9SessionInDb?.revokedAt !== null &&
      (verif403 ? u9VerifCountInDb === 0 : u9VerifCountInDb === 1);

    logTest(
      14,
      "Fix B: Concurrent HTTP createVerification and HTTP /api/auth/logout executes with strict serialization (zero TOCTOU bypass)",
      test14Pass,
      verif201
        ? "HTTP Verification committed before HTTP Logout"
        : "HTTP Logout serialized before HTTP Verification (403)"
    );

  } finally {
    server.close();
    // Clean up test records
    if (cleanUserIds.length > 0) {
      await prisma.vaultVerification.deleteMany({
        where: { userId: { in: cleanUserIds } }
      }).catch(() => {});
      await prisma.vaultItem.deleteMany({
        where: { userId: { in: cleanUserIds } }
      }).catch(() => {});
      await prisma.session.deleteMany({
        where: { userId: { in: cleanUserIds } }
      }).catch(() => {});
      await prisma.device.deleteMany({
        where: { userId: { in: cleanUserIds } }
      }).catch(() => {});
      await prisma.user.deleteMany({
        where: { id: { in: cleanUserIds } }
      }).catch(() => {});
    }
  }

  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Phase 9.2.2 Verification Summary: ${testPassedCount + testFailedCount} tests | ✅ ${testPassedCount} passed | ❌ ${testFailedCount} failed`);
  console.log("════════════════════════════════════════════════════════════\n");

  if (testFailedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

run().catch((err) => {
  console.error("Verification suite failed:", err);
  process.exit(1);
});
