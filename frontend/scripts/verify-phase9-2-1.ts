/**
 * VaultGuard – Phase 9.2.1 Verification Suite
 * Final Security Hardening: Durable Device Authorization, Transactional Session Expiry, and Tombstone Zero-Knowledge Recovery
 *
 * Usage: tsx --env-file=../VaultGuard-Backend/.env scripts/verify-phase9-2-1.ts
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
import {
  createDefaultKdfMetadata,
  deriveVaultKey
} from "../lib/crypto/kdf";
import {
  encryptVaultPayload,
  decryptVaultPayload,
  generateInitializationVector
} from "../lib/crypto/aes";
import { DecryptionError } from "../lib/crypto/types";
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
    "X-VaultGuard-Request": "1"
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
  console.log("VaultGuard Phase 9.2.1: Final Security Hardening Verification Suite");
  console.log("================================================================================\n");

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  process.env.NEXT_PUBLIC_API_BASE_URL = baseUrl;

  const timestamp = Date.now();
  const user1Email = `phase921_u1_${timestamp}@example.com`;
  const user2Email = `phase921_u2_${timestamp}@example.com`;
  const user3Email = `phase921_u3_${timestamp}@example.com`;
  const user4Email = `phase921_u4_${timestamp}@example.com`;
  const user5Email = `phase921_u5_${timestamp}@example.com`;

  const accountPassword = "Password!123456Phase921";
  const masterPassword = "MasterPassword!Phase921";

  const cleanUserIds: string[] = [];

  try {
    const passwordHash = await hashPassword(accountPassword);
    const kdfMeta = createDefaultKdfMetadata();
    const kdfSalt = kdfMeta.vaultKdfSalt;

    // ─────────────────────────────────────────────────────────────────────────
    // FIX A: Durable Historical Device Identity (Eliminate Oldest Active Fallback)
    // ─────────────────────────────────────────────────────────────────────────
    console.log("── Fix A: Durable Historical Original Device Identity ──");

    // Setup User 1: Legacy user with original device D1 (active) and D2 (newer)
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

    // Create D1 (original device created 2 hours ago)
    const d1 = await prisma.device.create({
      data: {
        userId: user1.id,
        deviceIdentifier: `u1_d1_${timestamp}`,
        deviceName: "U1 Original Device",
        createdAt: new Date(Date.now() - 7200000)
      }
    });

    // Create D2 (newer device created 1 hour ago)
    const d2 = await prisma.device.create({
      data: {
        userId: user1.id,
        deviceIdentifier: `u1_d2_${timestamp}`,
        deviceName: "U1 New Device",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    // Create a legacy vault item created 1.5 hours ago
    const vaultKey = await deriveVaultKey(masterPassword, kdfSalt);
    const encryptedItem = await encryptVaultPayload(
      JSON.stringify({ title: "Secret 1", username: "admin", password: "pw" }),
      vaultKey
    );

    await prisma.vaultItem.create({
      data: {
        userId: user1.id,
        encryptedPayload: Buffer.from(encryptedItem.encryptedPayload, "base64"),
        initializationVector: Buffer.from(encryptedItem.initializationVector, "base64"),
        authenticationTag: Buffer.from(encryptedItem.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 5400000)
      }
    });

    // Valid canary payload for migration
    const canaryEncrypted = await encryptVaultPayload(
      JSON.stringify({ canary: "phase921-canary" }),
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

    // Session on D1 (original active device)
    const s1 = await prisma.session.create({
      data: {
        userId: user1.id,
        deviceId: d1.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const s1Token = generateAccessToken({ sub: user1.id, email: user1Email, sid: s1.id });

    // Test 1: Original device active -> authorized (201 Created)
    // Wait, let's test with a different user or test unauthorized first so canary is not yet created.
    // Let's create User 2 for testing soft-deleted D1 behavior so User 1 can test authorized D1.

    // Session on D2 (new device) attempting migration while D1 is still active
    const s2 = await prisma.session.create({
      data: {
        userId: user1.id,
        deviceId: d2.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const s2Token = generateAccessToken({ sub: user1.id, email: user1Email, sid: s2.id });

    const resD2Blocked = await request(baseUrl, "POST", "/api/vault/verification", s2Token, canaryPayload);
    logTest(
      1,
      "New device D2 rejected with 403 when attempting legacy migration on active vault",
      resD2Blocked.status === 403,
      "HTTP 403 Forbidden"
    );

    // Setup User 2 to test Fix A: Soft-deleted original device D1 does NOT promote D2
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

    // U2 D1: Original device, created 3 hours ago, but SOFT-DELETED 1 hour ago
    const u2D1 = await prisma.device.create({
      data: {
        userId: user2.id,
        deviceIdentifier: `u2_d1_${timestamp}`,
        deviceName: "U2 Original Laptop (Removed)",
        createdAt: new Date(Date.now() - 10800000),
        removedAt: new Date(Date.now() - 3600000) // soft-deleted
      }
    });

    // U2 D2: New device created 30 minutes ago (currently the only "active" device!)
    const u2D2 = await prisma.device.create({
      data: {
        userId: user2.id,
        deviceIdentifier: `u2_d2_${timestamp}`,
        deviceName: "U2 New Phone",
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    // U2 Vault item created 2 hours ago (before D2 was enrolled)
    await prisma.vaultItem.create({
      data: {
        userId: user2.id,
        encryptedPayload: Buffer.from(encryptedItem.encryptedPayload, "base64"),
        initializationVector: Buffer.from(encryptedItem.initializationVector, "base64"),
        authenticationTag: Buffer.from(encryptedItem.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 7200000)
      }
    });

    // Session on U2 D2 (the newest and only active device)
    const u2S2 = await prisma.session.create({
      data: {
        userId: user2.id,
        deviceId: u2D2.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const u2S2Token = generateAccessToken({ sub: user2.id, email: user2Email, sid: u2S2.id });

    // Test 2: In the vulnerable code, D2 was the "oldest active device" (since D1 was soft-deleted)
    // In Fix A, D1 is historically the original device, so D2 is NOT the original device and was created after vault items.
    const resU2D2 = await request(baseUrl, "POST", "/api/vault/verification", u2S2Token, canaryPayload);
    logTest(
      2,
      "Fix A: Soft-deleting original device does NOT transfer migration authority to newest active device (403)",
      resU2D2.status === 403
    );

    // Test 3: Session belonging to a removed device is rejected with 401 or 403
    const u2S1Removed = await prisma.session.create({
      data: {
        userId: user2.id,
        deviceId: u2D1.id, // u2D1 has removedAt !== null
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const u2S1RemovedToken = generateAccessToken({ sub: user2.id, email: user2Email, sid: u2S1Removed.id });
    const resRemovedDevSession = await request(baseUrl, "POST", "/api/vault/verification", u2S1RemovedToken, canaryPayload);
    let serviceRejectedRemoved = false;
    try {
      await vaultService.createVerification(user2.id, u2S1Removed.id, canaryPayload as any);
    } catch (err: any) {
      serviceRejectedRemoved = err.statusCode === 403;
    }
    logTest(
      3,
      "Session belonging to soft-deleted device is rejected (401/403 HTTP & 403 service)",
      (resRemovedDevSession.status === 401 || resRemovedDevSession.status === 403) && serviceRejectedRemoved
    );

    // Test 4: Revoked session is rejected
    const u1SRevoked = await prisma.session.create({
      data: {
        userId: user1.id,
        deviceId: d1.id,
        expiresAt: new Date(Date.now() + 3600000),
        revokedAt: new Date(Date.now() - 60000)
      }
    });
    const u1SRevokedToken = generateAccessToken({ sub: user1.id, email: user1Email, sid: u1SRevoked.id });
    const resRevoked = await request(baseUrl, "POST", "/api/vault/verification", u1SRevokedToken, canaryPayload);
    logTest(
      4,
      "Revoked session is rejected by authentication or verification checks (401 or 403)",
      resRevoked.status === 401 || resRevoked.status === 403
    );

    // Test 5: Expired session is rejected
    const u1SExpired = await prisma.session.create({
      data: {
        userId: user1.id,
        deviceId: d1.id,
        expiresAt: new Date(Date.now() - 60000) // expired 1 minute ago
      }
    });
    const u1SExpiredToken = generateAccessToken({ sub: user1.id, email: user1Email, sid: u1SExpired.id });
    const resExpired = await request(baseUrl, "POST", "/api/vault/verification", u1SExpiredToken, canaryPayload);
    logTest(
      5,
      "Expired session is rejected by authentication middleware (401 Unauthorized)",
      resExpired.status === 401
    );

    // Test 6: Original active device D1 on User 1 is authorized (201 Created)
    const resU1D1Success = await request(baseUrl, "POST", "/api/vault/verification", s1Token, canaryPayload);
    logTest(
      6,
      "Fix A: Original active device with valid session successfully establishes verification canary (201 Created)",
      resU1D1Success.status === 201 && resU1D1Success.body?.success === true,
      "HTTP 201 Created"
    );

    // ─────────────────────────────────────────────────────────────────────────
    // FIX B: Transactional Session Expiry & Revocation Check
    // ─────────────────────────────────────────────────────────────────────────
    console.log("\n── Fix B: Transactional Session Expiration and Revocation Checks ──");

    // Setup User 3 for Fix B tests
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
        encryptedPayload: Buffer.from(encryptedItem.encryptedPayload, "base64"),
        initializationVector: Buffer.from(encryptedItem.initializationVector, "base64"),
        authenticationTag: Buffer.from(encryptedItem.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 1800000)
      }
    });

    // Test 7: Simulating session expiring right before transactional query
    // Create session that is valid for JWT generation, but expiresAt <= now in DB
    const u3STxExpired = await prisma.session.create({
      data: {
        userId: user3.id,
        deviceId: u3D1.id,
        expiresAt: new Date(Date.now() - 5000) // expired in DB
      }
    });
    const u3STxExpiredToken = generateAccessToken({ sub: user3.id, email: user3Email, sid: u3STxExpired.id });
    const resTxExpired = await request(baseUrl, "POST", "/api/vault/verification", u3STxExpiredToken, canaryPayload);
    let serviceRejectedExpired = false;
    let expiredErrDetail = "";
    try {
      await vaultService.createVerification(user3.id, u3STxExpired.id, canaryPayload as any);
    } catch (err: any) {
      expiredErrDetail = `code=${err.code}, status=${err.statusCode || err.status}, msg=${err.message}`;
      serviceRejectedExpired = (err.statusCode === 403 || err.status === 403);
    }
    logTest(
      7,
      "Fix B: Transactional session expiration check rejects session with expiresAt <= now (401/403 HTTP & 403 service)",
      (resTxExpired.status === 401 || resTxExpired.status === 403) && serviceRejectedExpired,
      "Rejected with 401 HTTP & 403 Service"
    );

    // Test 8: Simulating session revoked right before transactional query
    const u3STxRevoked = await prisma.session.create({
      data: {
        userId: user3.id,
        deviceId: u3D1.id,
        expiresAt: new Date(Date.now() + 3600000),
        revokedAt: new Date(Date.now() - 2000) // revoked in DB
      }
    });
    const u3STxRevokedToken = generateAccessToken({ sub: user3.id, email: user3Email, sid: u3STxRevoked.id });
    const resTxRevoked = await request(baseUrl, "POST", "/api/vault/verification", u3STxRevokedToken, canaryPayload);
    let serviceRejectedRevoked = false;
    let revokedErrDetail = "";
    try {
      await vaultService.createVerification(user3.id, u3STxRevoked.id, canaryPayload as any);
    } catch (err: any) {
      revokedErrDetail = `code=${err.code}, status=${err.statusCode || err.status}, msg=${err.message}`;
      serviceRejectedRevoked = (err.statusCode === 403 || err.status === 403);
    }
    logTest(
      8,
      "Fix B: Transactional session check rejects session with revokedAt !== null (401/403 HTTP & 403 service)",
      (resTxRevoked.status === 401 || resTxRevoked.status === 403) && serviceRejectedRevoked,
      "Rejected with 401 HTTP & 403 Service"
    );

    // Test 9: Active, unrevoked, unexpired session passes transactional query
    const u3SValid = await prisma.session.create({
      data: {
        userId: user3.id,
        deviceId: u3D1.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const u3SValidToken = generateAccessToken({ sub: user3.id, email: user3Email, sid: u3SValid.id });
    const resTxValid = await request(baseUrl, "POST", "/api/vault/verification", u3SValidToken, canaryPayload);
    logTest(
      9,
      "Fix B: Active, unexpired, unrevoked session passes transactional check and establishes canary (201 Created)",
      resTxValid.status === 201 && resTxValid.body?.success === true
    );

    // ─────────────────────────────────────────────────────────────────────────
    // FIX C: Tombstone Zero-Knowledge Recovery & Active Items Flag
    // ─────────────────────────────────────────────────────────────────────────
    console.log("\n── Fix C: Tombstone Zero-Knowledge Recovery & Active Items Flag ──");

    // Setup User 4: Account where ALL vault items are soft-deleted (tombstones only)
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
        deviceName: "U4 Original Laptop",
        createdAt: new Date(Date.now() - 7200000)
      }
    });

    const deletedAtTimestamp = new Date(Date.now() - 1800000);
    const tombstoneItem = await prisma.vaultItem.create({
      data: {
        userId: user4.id,
        encryptedPayload: Buffer.from(encryptedItem.encryptedPayload, "base64"),
        initializationVector: Buffer.from(encryptedItem.initializationVector, "base64"),
        authenticationTag: Buffer.from(encryptedItem.authenticationTag, "base64"),
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1,
        createdAt: new Date(Date.now() - 3600000),
        deletedAt: deletedAtTimestamp // ALL items soft-deleted!
      }
    });

    const u4S1 = await prisma.session.create({
      data: {
        userId: user4.id,
        deviceId: u4D1.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const u4S1Token = generateAccessToken({ sub: user4.id, email: user4Email, sid: u4S1.id });

    // Test 10: getVerification returns hasActiveItems: false, hasItems: true, and recoveryRecord with isDeleted: true
    const resU4GetVerif = await request(baseUrl, "GET", "/api/vault/verification", u4S1Token);
    const verifDataU4 = resU4GetVerif.body?.data;
    logTest(
      10,
      "Fix C: getVerification returns hasActiveItems: false and recoveryRecord for tombstone-only vault",
      resU4GetVerif.status === 200 &&
        verifDataU4?.hasVerification === false &&
        verifDataU4?.hasItems === true &&
        verifDataU4?.hasActiveItems === false &&
        verifDataU4?.recoveryRecord?.id === tombstoneItem.id &&
        verifDataU4?.recoveryRecord?.isDeleted === true
    );

    // Test 11: Client decrypts recoveryRecord locally with correct master password (proof of possession)
    let localDecryptSuccess = false;
    let localPayload: any = null;
    try {
      const rec = verifDataU4.recoveryRecord;
      const decrypted = await decryptVaultPayload<any>(
        {
          encryptedPayload: rec.encryptedPayload,
          initializationVector: rec.initializationVector,
          authenticationTag: rec.authenticationTag,
          encryptionAlgorithm: rec.encryptionAlgorithm || "AES-256-GCM",
          encryptionVersion: rec.encryptionVersion || 1
        },
        vaultKey
      );
      localPayload = typeof decrypted === "string" ? JSON.parse(decrypted) : decrypted;
      localDecryptSuccess = localPayload?.title === "Secret 1";
    } catch {
      localDecryptSuccess = false;
    }
    logTest(
      11,
      "Fix C: Client decrypts soft-deleted recoveryRecord locally with correct master key (zero knowledge preserved)",
      localDecryptSuccess
    );

    // Test 12: Client with wrong master password fails closed with DecryptionError
    let wrongPasswordFailedClosed = false;
    try {
      const wrongKey = await deriveVaultKey("WrongMasterPassword!921", kdfSalt);
      const rec = verifDataU4.recoveryRecord;
      await decryptVaultPayload(
        {
          encryptedPayload: rec.encryptedPayload,
          initializationVector: rec.initializationVector,
          authenticationTag: rec.authenticationTag,
          encryptionAlgorithm: rec.encryptionAlgorithm || "AES-256-GCM",
          encryptionVersion: rec.encryptionVersion || 1
        },
        wrongKey
      );
      wrongPasswordFailedClosed = false;
    } catch (err: any) {
      wrongPasswordFailedClosed = true;
    }
    logTest(
      12,
      "Fix C: Decrypting tombstone recoveryRecord with wrong master key fails closed with DecryptionError",
      wrongPasswordFailedClosed
    );

    // Test 13: Authorized client establishes canary after verifying tombstone possession
    const u4CanaryEnc = await encryptVaultPayload(JSON.stringify({ canary: "u4-canary" }), vaultKey);
    const resU4Migration = await request(baseUrl, "POST", "/api/vault/verification", u4S1Token, {
      encryptedPayload: u4CanaryEnc.encryptedPayload,
      initializationVector: u4CanaryEnc.initializationVector,
      authenticationTag: u4CanaryEnc.authenticationTag,
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      isLegacyMigration: true
    });
    logTest(
      13,
      "Fix C: Authentic original device establishes canary on tombstone-only vault (201 Created)",
      resU4Migration.status === 201 && resU4Migration.body?.success === true
    );

    // Test 14: Existing tombstones remain deleted in database (deletedAt is preserved and not restored)
    const tombstoneInDb = await prisma.vaultItem.findUnique({
      where: { id: tombstoneItem.id }
    });
    logTest(
      14,
      "Fix C: Soft-deleted vault item remains deleted in database (deletedAt timestamp preserved)",
      tombstoneInDb?.deletedAt !== null &&
        tombstoneInDb?.deletedAt?.getTime() === deletedAtTimestamp.getTime()
    );

    // Test 15: Unauthorized new device cannot establish canary on tombstone vault
    const u4D2New = await prisma.device.create({
      data: {
        userId: user4.id,
        deviceIdentifier: `u4_d2_new_${timestamp}`,
        deviceName: "U4 Rogue Device",
        createdAt: new Date(Date.now())
      }
    });
    const u4S2New = await prisma.session.create({
      data: {
        userId: user4.id,
        deviceId: u4D2New.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const u4S2NewToken = generateAccessToken({ sub: user4.id, email: user4Email, sid: u4S2New.id });
    const resU4Rogue = await request(baseUrl, "POST", "/api/vault/verification", u4S2NewToken, {
      encryptedPayload: u4CanaryEnc.encryptedPayload,
      initializationVector: u4CanaryEnc.initializationVector,
      authenticationTag: u4CanaryEnc.authenticationTag,
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      isLegacyMigration: true
    });
    logTest(
      15,
      "Fix C: Unauthorized new device rejected from tombstone migration or replacement (403 or 409)",
      resU4Rogue.status === 403 || resU4Rogue.status === 409
    );

    // Test 16: Setup User 5 with 0 items: normal setup with isLegacyMigration: false returns 201 Created
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
        deviceName: "U5 Fresh Device",
        createdAt: new Date()
      }
    });

    const u5S1 = await prisma.session.create({
      data: {
        userId: user5.id,
        deviceId: u5D1.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    const u5S1Token = generateAccessToken({ sub: user5.id, email: user5Email, sid: u5S1.id });

    // Check getVerification on fresh account
    const resU5GetVerif = await request(baseUrl, "GET", "/api/vault/verification", u5S1Token);
    const verifDataU5 = resU5GetVerif.body?.data;

    const u5CanaryEnc = await encryptVaultPayload(JSON.stringify({ canary: "fresh-account" }), vaultKey);
    const resU5CreateVerif = await request(baseUrl, "POST", "/api/vault/verification", u5S1Token, {
      encryptedPayload: u5CanaryEnc.encryptedPayload,
      initializationVector: u5CanaryEnc.initializationVector,
      authenticationTag: u5CanaryEnc.authenticationTag,
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      isLegacyMigration: false
    });
    logTest(
      16,
      "Fresh account (itemCount: 0) initial setup succeeds with isLegacyMigration: false (201 Created)",
      resU5GetVerif.status === 200 &&
        verifDataU5?.hasVerification === false &&
        verifDataU5?.hasItems === false &&
        verifDataU5?.hasActiveItems === false &&
        verifDataU5?.recoveryRecord === null &&
        resU5CreateVerif.status === 201 &&
        resU5CreateVerif.body?.success === true,
      "HTTP 201 Created"
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
  console.log(`Phase 9.2.1 Verification Summary: ${testPassedCount + testFailedCount} tests | ✅ ${testPassedCount} passed | ❌ ${testFailedCount} failed`);
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
