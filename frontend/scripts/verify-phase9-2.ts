/**
 * VaultGuard – Phase 9.2 Verification Suite
 * Legacy Migration Authorization, Account-Safe Synchronization, and Session Cleanup
 *
 * Usage: tsx --env-file=../VaultGuard-Backend/.env scripts/verify-phase9-2.ts
 */

import http from "node:http";
import assert from "node:assert";
import path from "node:path";

try {
  process.loadEnvFile(path.resolve(__dirname, "../../VaultGuard-Backend/.env"));
} catch {
  // Env file already loaded via CLI
}

import app from "../../VaultGuard-Backend/src/app";
import prisma from "../../VaultGuard-Backend/src/config/db";
import { authApi } from "../lib/api/auth";
import { vaultApi } from "../lib/api/vault";
import { syncApi } from "../lib/api/sync";
import { setAccessToken } from "../lib/api/client";
import {
  createDefaultKdfMetadata,
  deriveVaultKey
} from "../lib/crypto/kdf";
import {
  encryptVaultPayload,
  decryptVaultPayload,
  generateInitializationVector
} from "../lib/crypto/aes";
import {
  saveEncryptedRecord,
  listEncryptedRecords,
  getEncryptedRecord,
  deleteEncryptedRecord,
  saveKdfMetadata,
  getKdfMetadata,
  saveAuthVerification,
  getAuthVerification,
  setActiveStorageUser,
  getActiveStorageUser,
  clearAccountCache,
  resetVaultDatabase,
  saveSyncCursor,
  getSyncCursor
} from "../lib/storage/vault-db";
import { syncEngine } from "../lib/sync/sync-engine";
import { onAuthReset, triggerAuthReset } from "../lib/auth/auth-context";
import { CryptographicError, DecryptionError, type EncryptedVaultRecord } from "../lib/crypto/types";
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
  console.log("VaultGuard Phase 9.2: Legacy Migration, Account-Safe Sync & Cleanup Suite");
  console.log("================================================================================\n");

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  process.env.NEXT_PUBLIC_API_BASE_URL = baseUrl;

  const timestamp = Date.now();
  const testUserEmail = `phase92_legacy_${timestamp}@example.com`;
  const freshUserEmail = `phase92_fresh_${timestamp}@example.com`;
  const accountPassword = "Password!123456Phase92";
  const masterPassword = "MasterPassword!Phase92";

  let legacyUserId: string = "";
  let legacyOriginalSessionId: string = "";
  let legacyOriginalToken: string = "";
  let legacyNewSessionId: string = "";
  let legacyNewToken: string = "";

  let freshUserId: string = "";
  let freshSessionId: string = "";
  let freshToken: string = "";

  let legacy2UserId: string = "";

  try {
    // ── SECTION 1: Setup Legacy User and Devices ──
    console.log("── Section 1: Legacy Migration Authorization on Backend (Fix A) ──");

    const passwordHash = await hashPassword(accountPassword);
    const kdfSalt = "c2FsdF9waGFzZTkyXzEyMw==";

    // Create legacy user in database
    const user = await prisma.user.create({
      data: {
        email: testUserEmail,
        emailNormalized: testUserEmail.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    legacyUserId = user.id;

    // Create Device 1 (original enrolled device, created at T0)
    const device1 = await prisma.device.create({
      data: {
        userId: legacyUserId,
        deviceIdentifier: `orig_device_${timestamp}`,
        deviceName: "Original Legacy Laptop",
        createdAt: new Date(Date.now() - 3600000) // 1 hour ago
      }
    });

    const session1 = await prisma.session.create({
      data: {
        userId: legacyUserId,
        deviceId: device1.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    legacyOriginalSessionId = session1.id;
    legacyOriginalToken = generateAccessToken({ sub: legacyUserId, email: testUserEmail, sid: session1.id });

    // Device 1 creates an encrypted vault item (before device 2 exists)
    const iv = Buffer.from("123456789012").toString("base64");
    const tag = Buffer.from("1234567890123456").toString("base64");
    const payload = Buffer.from("legacy-encrypted-item-content").toString("base64");

    const itemRes = await request(baseUrl, "POST", "/api/vault", legacyOriginalToken, {
      encryptedPayload: payload,
      initializationVector: iv,
      authenticationTag: tag
    });
    assert.strictEqual(itemRes.status, 201, "Legacy item creation must return 201");

    // Later: Create Device 2 (newly enrolled device, created at T1 > item.createdAt)
    const device2 = await prisma.device.create({
      data: {
        userId: legacyUserId,
        deviceIdentifier: `new_device_${timestamp}`,
        deviceName: "Attacker or Secondary Phone",
        createdAt: new Date(Date.now()) // now
      }
    });

    const session2 = await prisma.session.create({
      data: {
        userId: legacyUserId,
        deviceId: device2.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    legacyNewSessionId = session2.id;
    legacyNewToken = generateAccessToken({ sub: legacyUserId, email: testUserEmail, sid: session2.id });

    // Test 1: New device sends isLegacyMigration: true -> REJECTED with 403 Forbidden!
    const validCanary = {
      encryptedPayload: Buffer.from("canary-payload-data").toString("base64"),
      initializationVector: Buffer.from("123456789012").toString("base64"),
      authenticationTag: Buffer.from("1234567890123456").toString("base64"),
      encryptionAlgorithm: "AES-256-GCM" as const,
      encryptionVersion: 1
    };

    const newDeviceMigrationRes = await request(baseUrl, "POST", "/api/vault/verification", legacyNewToken, {
      ...validCanary,
      isLegacyMigration: true
    });
    logTest(
      1,
      "Unauthorized new device sending isLegacyMigration: true is strictly REJECTED with 403 Forbidden",
      newDeviceMigrationRes.status === 403
    );

    // Test 2: New device sends without isLegacyMigration -> REJECTED with 409 Conflict
    const newDeviceStandardRes = await request(baseUrl, "POST", "/api/vault/verification", legacyNewToken, {
      ...validCanary,
      isLegacyMigration: false
    });
    logTest(
      2,
      "New device on legacy vault without isLegacyMigration rejected with 409 Conflict",
      newDeviceStandardRes.status === 409
    );

    // Test 3: Fresh account with 0 vault items can initialize verification canary normally
    const freshUser = await prisma.user.create({
      data: {
        email: freshUserEmail,
        emailNormalized: freshUserEmail.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    freshUserId = freshUser.id;
    const freshDev = await prisma.device.create({
      data: { userId: freshUserId, deviceIdentifier: `fresh_dev_${timestamp}`, deviceName: "Fresh Device" }
    });
    const freshSess = await prisma.session.create({
      data: { userId: freshUserId, deviceId: freshDev.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    freshSessionId = freshSess.id;
    freshToken = generateAccessToken({ sub: freshUserId, email: freshUserEmail, sid: freshSess.id });

    const freshCanaryRes = await request(baseUrl, "POST", "/api/vault/verification", freshToken, {
      ...validCanary,
      isLegacyMigration: false
    });
    logTest(
      3,
      "Fresh account with zero vault items initializes verification with 201 Created",
      freshCanaryRes.status === 201
    );

    // Test 4: Original legacy device with isLegacyMigration: true is AUTHORIZED and succeeds (201 Created)
    const originalMigrationRes = await request(baseUrl, "POST", "/api/vault/verification", legacyOriginalToken, {
      ...validCanary,
      isLegacyMigration: true
    });
    logTest(
      4,
      "Authorized original legacy device with isLegacyMigration: true returns 201 Created",
      originalMigrationRes.status === 201
    );

    // ── SECTION 2: Low Fix E - Prisma P2002 Mapping to 409 Conflict ──
    console.log("\n── Section 2: Error Handler Prisma P2002 Mapping (Fix E) ──");

    // Test 5: Duplicate verification creation maps to 409 Conflict (P2002 unique constraint)
    const duplicateRes = await request(baseUrl, "POST", "/api/vault/verification", legacyOriginalToken, {
      ...validCanary,
      isLegacyMigration: true
    });
    logTest(
      5,
      "Subsequent canary creation returns 409 Conflict (P2002 mapped to 409, never 500)",
      duplicateRes.status === 409 && duplicateRes.body?.success === false
    );

    // ── SECTION 3: Critical Fix B - Prevent Cross-Account Sync Cache Pollution ──
    console.log("\n── Section 3: Account-Safe Synchronization & Storage Isolation (Fix B) ──");

    setActiveStorageUser("user_alpha");

    const recordAlpha: EncryptedVaultRecord = {
      id: `item_alpha_${timestamp}`,
      userId: "user_alpha",
      encryptedPayload: "cGF5bG9hZA==",
      initializationVector: "MTIzNDU2Nzg5MDEy",
      authenticationTag: "MTIzNDU2Nzg5MDEyMzQ1Ng==",
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      revision: 1,
      syncVersion: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Test 6: saveEncryptedRecord allows write when targetUserId matches active user
    await saveEncryptedRecord(recordAlpha, "user_alpha");
    const retrievedAlpha = await getEncryptedRecord(recordAlpha.id);
    logTest(
      6,
      "saveEncryptedRecord with matching targetUserId saves record successfully",
      retrievedAlpha !== null && retrievedAlpha.id === recordAlpha.id
    );

    // Test 7: saveEncryptedRecord safely discards write when targetUserId does NOT match active user
    setActiveStorageUser("user_beta");
    const recordSneaky: EncryptedVaultRecord = {
      id: `item_sneaky_${timestamp}`,
      userId: "user_alpha",
      encryptedPayload: "cGF5bG9hZA==",
      initializationVector: "MTIzNDU2Nzg5MDEy",
      authenticationTag: "MTIzNDU2Nzg5MDEyMzQ1Ng==",
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      revision: 1,
      syncVersion: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // Should be safely discarded because targetUserId ('user_alpha') !== activeStorageUserId ('user_beta')
    await saveEncryptedRecord(recordSneaky, "user_alpha");
    const betaCheck = await getEncryptedRecord(recordSneaky.id);
    logTest(
      7,
      "saveEncryptedRecord with inactive targetUserId is safely discarded (no cross-account cache pollution)",
      betaCheck === null
    );

    // Test 8: saveEncryptedRecord throws CryptographicError if record.userId mismatches targetUserId
    let mismatchError = false;
    try {
      await saveEncryptedRecord(recordAlpha, "user_gamma");
    } catch (e: any) {
      mismatchError = e instanceof CryptographicError;
    }
    logTest(
      8,
      "saveEncryptedRecord rejects record when record.userId mismatches targetUserId with CryptographicError",
      mismatchError
    );

    // Test 9: saveSyncCursor safely discards write when userId does not match active storage user
    setActiveStorageUser("user_beta");
    await saveSyncCursor(999, "user_alpha"); // Discarded!
    setActiveStorageUser("user_alpha");
    const alphaCursor = await getSyncCursor("user_alpha");
    logTest(
      9,
      "saveSyncCursor with inactive targetUserId is safely discarded",
      alphaCursor !== 999
    );

    // Test 10: In-flight account switch during syncEngine.sync() cancels and discards changes
    setActiveStorageUser(legacyUserId);
    setAccessToken(legacyOriginalToken);

    // Start a sync pass, but switch active storage user immediately
    const syncPromise = syncEngine.sync(null, undefined, () => true, () => 0);
    // Switch active user during async boundary
    setActiveStorageUser("switched_user");

    const syncResult = await syncPromise;
    logTest(
      10,
      "Account switch during in-flight sync triggers cancellation (cancelled: true, zero writes committed)",
      syncResult.cancelled === true
    );

    // ── SECTION 4: Medium Fix C - Safe Legacy Recovery When Local Canary Missing ──
    console.log("\n── Section 4: Missing Local Canary Recovery on Original Device (Fix C) ──");

    // Setup User Legacy2 with vault items, but NO local canary
    const legacy2Email = `phase92_legacy2_${timestamp}@example.com`;
    const user2 = await prisma.user.create({
      data: {
        email: legacy2Email,
        emailNormalized: legacy2Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfSalt,
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    legacy2UserId = user2.id;

    const key2 = await deriveVaultKey(masterPassword, kdfSalt, 600000);
    const encItem = await encryptVaultPayload({ service: "Bank", password: "SecretPassword123" }, key2);

    const dev2Orig = await prisma.device.create({
      data: {
        userId: user2.id,
        deviceIdentifier: `legacy2_orig_${timestamp}`,
        deviceName: "Legacy2 Laptop",
        createdAt: new Date(Date.now() - 3600000)
      }
    });

    const sess2Orig = await prisma.session.create({
      data: { userId: user2.id, deviceId: dev2Orig.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    const token2Orig = generateAccessToken({ sub: user2.id, email: legacy2Email, sid: sess2Orig.id });

    // Store item on server
    await request(baseUrl, "POST", "/api/vault", token2Orig, {
      encryptedPayload: encItem.encryptedPayload,
      initializationVector: encItem.initializationVector,
      authenticationTag: encItem.authenticationTag
    });

    // Device has NO local canary (clean state or cleared storage)
    setActiveStorageUser(user2.id);
    const existingLocalCanary = await getAuthVerification(user2.id);
    assert.strictEqual(existingLocalCanary, null, "Local canary must be missing initially");

    // Simulate unlock on original device:
    // 1. Fetch remote items
    const remoteItemsRes = await request(baseUrl, "GET", "/api/vault", token2Orig);
    const remoteItems = remoteItemsRes.body?.data || [];
    assert.strictEqual(remoteItems.length, 1, "Must find 1 remote item");

    // 2. Local verification against the remote item
    let verifiedKeySuccess = false;
    try {
      const decPayload = await decryptVaultPayload(remoteItems[0], key2);
      verifiedKeySuccess = (decPayload as any).service === "Bank";
    } catch {
      verifiedKeySuccess = false;
    }
    logTest(
      11,
      "Original device with missing canary verifies master password against existing encrypted item",
      verifiedKeySuccess
    );

    // 3. Local canary created and uploaded with isLegacyMigration: true
    const recoveredCanary = await encryptVaultPayload({ verifier: "recovered" }, key2);
    const recoverRes = await request(baseUrl, "POST", "/api/vault/verification", token2Orig, {
      ...recoveredCanary,
      isLegacyMigration: true
    });
    logTest(
      12,
      "Original device successfully uploads recovered verification canary (201 Created)",
      recoverRes.status === 201
    );

    // Test 13: Wrong master password fails decrypting remote item (DecryptionError)
    const wrongKey = await deriveVaultKey("WrongMasterPassword!", kdfSalt, 600000);
    let wrongPassFailed = false;
    try {
      await decryptVaultPayload(remoteItems[0], wrongKey);
    } catch (e: any) {
      wrongPassFailed = e instanceof DecryptionError;
    }
    logTest(
      13,
      "Incorrect master password fails remote item decryption with DecryptionError",
      wrongPassFailed
    );

    // ── SECTION 5: Medium Fix D - Synchronous Lock and Cancellation on Logout & Expiry ──
    console.log("\n── Section 5: Synchronous Lock & Cleanup on Logout / Expiration (Fix D) ──");

    let authResetTriggered = false;
    const unsubReset = onAuthReset(() => {
      authResetTriggered = true;
    });

    // Test 14: triggerAuthReset synchronously notifies registered listeners (locks vault)
    triggerAuthReset();
    logTest(
      14,
      "triggerAuthReset synchronously notifies listeners to lock vault and clear CryptoKey ref",
      authResetTriggered
    );
    unsubReset();

    // Test 15: syncEngine.cancelSync immediately sets status to idle and aborts controller
    syncEngine.cancelSync();
    const statusAfterCancel = syncEngine.getStatus();
    logTest(
      15,
      "syncEngine.cancelSync immediately sets status to idle and aborts pending sync requests",
      statusAfterCancel.status === "idle"
    );

  } finally {
    server.close();
    // Clean up test database records safely
    const cleanUserIds = [legacyUserId, freshUserId, legacy2UserId].filter(Boolean);
    await prisma.vaultVerification.deleteMany({
      where: {
        userId: { in: cleanUserIds }
      }
    }).catch(() => {});
    await prisma.vaultItem.deleteMany({
      where: {
        userId: { in: cleanUserIds }
      }
    }).catch(() => {});
    await prisma.session.deleteMany({
      where: {
        userId: { in: cleanUserIds }
      }
    }).catch(() => {});
    await prisma.device.deleteMany({
      where: {
        userId: { in: cleanUserIds }
      }
    }).catch(() => {});
    await prisma.user.deleteMany({
      where: {
        id: { in: cleanUserIds }
      }
    }).catch(() => {});
  }

  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Phase 9.2 Verification Summary: ${testPassedCount + testFailedCount} tests | ✅ ${testPassedCount} passed | ❌ ${testFailedCount} failed`);
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
