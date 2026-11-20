/**
 * VaultGuard – Phase 9.1 Critical Security Corrections Verification Suite
 *
 * Verifies:
 * - Multi-device master-password verification via server-synchronized canary
 * - Rejection of incorrect master passwords on clean/new devices
 * - Safe legacy vault migration from original device
 * - Protection against unauthorized canary initialization on legacy vaults
 * - Create-once enforcement for server verification canary (409 Conflict)
 * - Strict integrity verification (no silent swallowing of corrupted vault items)
 * - In-flight synchronization cancellation on vault lock (no stale state updates)
 * - Account-scoped local storage isolation and clean logout purging
 *
 * Usage: tsx --env-file=../VaultGuard-Backend/.env scripts/verify-phase9-1.ts
 */

import http from "node:http";
import assert from "node:assert";
import path from "node:path";

try {
  process.loadEnvFile(path.resolve(__dirname, "../../VaultGuard-Backend/.env"));
} catch {
  // If already loaded via command line flag, continue
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
  resetVaultDatabase
} from "../lib/storage/vault-db";
import { syncEngine } from "../lib/sync/sync-engine";
import { CryptographicError, DecryptionError, type EncryptedVaultRecord } from "../lib/crypto/types";

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

async function run() {
  console.log("================================================================================");
  console.log("VaultGuard Phase 9.1: Multi-Device Master Password & Security Corrections Suite");
  console.log("================================================================================\n");

  // Spin up ephemeral test server
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  process.env.NEXT_PUBLIC_API_BASE_URL = baseUrl;
  process.env.FRONTEND_URL = baseUrl;

  console.log(`Ephemeral backend server listening on ${baseUrl}\n`);

  const timestamp = Date.now();
  const user1Email = `p91_user1_${timestamp}@vaultguard.test`;
  const user2Email = `p91_user2_${timestamp}@vaultguard.test`;
  const accountPassword = "StrongAccountPassword#2026!";
  const masterPasswordCorrect = "CorrectMasterPassword#999!";
  const masterPasswordWrong = "WrongMasterPassword#000!";

  let user1Id: string = "";
  let user1Token: string = "";

  try {
    // ════════════════════════════════════════════════════════════════════════════
    // Section 1: Multi-Device Unlock & Canary Synchronization
    // ════════════════════════════════════════════════════════════════════════════
    console.log("── Section 1: Multi-Device Verification & Unlock ──");

    // 1. Device A: Register account
    const kdfMetaA = createDefaultKdfMetadata();
    const regRes = await authApi.register({
      email: user1Email,
      password: accountPassword,
      vaultKdfSalt: kdfMetaA.vaultKdfSalt,
      vaultKdfAlgorithm: kdfMetaA.vaultKdfAlgorithm,
      vaultKdfParameters: kdfMetaA.vaultKdfParameters
    });
    user1Id = regRes.id;
    setActiveStorageUser(user1Id);

    const loginResA = await authApi.login({
      email: user1Email,
      password: accountPassword,
      deviceName: "Device-A-Desktop"
    });
    user1Token = loginResA.token;
    setAccessToken(user1Token);

    logTest(1, "Device A registers and logs in with backend", Boolean(loginResA.token));

    // 2. Device A: Initialize vault (Derive key, encrypt canary, store on server)
    const keyA = await deriveVaultKey(masterPasswordCorrect, kdfMetaA.vaultKdfSalt, kdfMetaA.vaultKdfParameters.iterations);
    const canaryPayload = { verifier: "vaultguard-master-key-verified", createdAt: new Date().toISOString() };
    const encryptedCanaryA = await encryptVaultPayload(canaryPayload, keyA);

    const createdServerCanary = await vaultApi.createVerification({
      encryptedPayload: encryptedCanaryA.encryptedPayload,
      initializationVector: encryptedCanaryA.initializationVector,
      authenticationTag: encryptedCanaryA.authenticationTag,
      encryptionAlgorithm: encryptedCanaryA.encryptionAlgorithm,
      encryptionVersion: encryptedCanaryA.encryptionVersion,
      isLegacyMigration: false
    });

    logTest(2, "Device A stores encrypted verification canary on backend", Boolean(createdServerCanary.id));

    // Verify backend holds only ciphertext, IV, tag (Zero-Knowledge)
    const verificationInDb = await prisma.vaultVerification.findUnique({ where: { userId: user1Id } });
    const hasNoPlaintextInDb =
      verificationInDb !== null &&
      (Buffer.isBuffer(verificationInDb.encryptedPayload) || verificationInDb.encryptedPayload instanceof Uint8Array) &&
      (Buffer.isBuffer(verificationInDb.initializationVector) || verificationInDb.initializationVector instanceof Uint8Array) &&
      verificationInDb.initializationVector.length === 12 &&
      verificationInDb.authenticationTag.length === 16;
    logTest(3, "Backend database stores opaque binary ciphertext, 12-byte IV, and 16-byte tag only", hasNoPlaintextInDb);

    // 3. Device A: Create 2 encrypted vault items and sync them
    const item1Enc = await encryptVaultPayload({ service: "GitHub", username: "octocat", password: "pwd1" }, keyA);
    const item1Server = await vaultApi.createItem(item1Enc);
    const item2Enc = await encryptVaultPayload({ service: "Google", username: "user@gmail.com", password: "pwd2" }, keyA);
    const item2Server = await vaultApi.createItem(item2Enc);

    logTest(4, "Device A creates and synchronizes 2 encrypted vault items", Boolean(item1Server.id && item2Server.id));

    // 4. Device B: Clean browser environment simulation (Zero local records, zero local canary)
    // Switch active client to Device B session
    const loginResB = await authApi.login({
      email: user1Email,
      password: accountPassword,
      deviceName: "Device-B-Laptop"
    });
    setAccessToken(loginResB.token);

    // Switch storage user context to Device B clean profile
    const deviceBProfileId = `${user1Id}_deviceB`;
    setActiveStorageUser(deviceBProfileId);

    const deviceBInitialRecords = await listEncryptedRecords();
    const deviceBInitialCanary = await getAuthVerification();
    logTest(
      5,
      "Device B starts with clean profile (0 local records and no local canary)",
      deviceBInitialRecords.length === 0 && deviceBInitialCanary === null
    );

    // 5. Device B: Retrieve verification status from backend
    const deviceBStatus = await vaultApi.getVerification();
    logTest(
      6,
      "Device B retrieves remote verification record from backend",
      deviceBStatus.hasVerification === true && deviceBStatus.verification !== null
    );

    // 6. Device B: Wrong master password attempt
    const profile = await authApi.getMe();
    const keyBWrong = await deriveVaultKey(masterPasswordWrong, profile.vaultKdfSalt, profile.vaultKdfParameters.iterations);

    let wrongPasswordRejected = false;
    try {
      if (deviceBStatus.verification) {
        await decryptVaultPayload(deviceBStatus.verification, keyBWrong);
      }
    } catch (err) {
      if (err instanceof DecryptionError) {
        wrongPasswordRejected = true;
      }
    }
    logTest(7, "Device B strictly rejects incorrect master password with DecryptionError", wrongPasswordRejected);

    // Verify wrong password did NOT overwrite or poison anything on server or client
    const serverCanaryAfterFailedAttempt = await prisma.vaultVerification.findUnique({ where: { userId: user1Id } });
    assert(serverCanaryAfterFailedAttempt);
    const canaryUnchanged =
      Buffer.from(serverCanaryAfterFailedAttempt.encryptedPayload).toString("base64") === createdServerCanary.encryptedPayload;
    logTest(8, "Server verification canary remains completely unmodified after wrong password attempt", canaryUnchanged);

    // 7. Device B: Correct master password unlock
    const keyBCorrect = await deriveVaultKey(masterPasswordCorrect, profile.vaultKdfSalt, profile.vaultKdfParameters.iterations);
    let correctPasswordVerified = false;
    if (deviceBStatus.verification) {
      const decryptedCanary = await decryptVaultPayload<any>(deviceBStatus.verification, keyBCorrect);
      if (decryptedCanary.verifier === "vaultguard-master-key-verified") {
        correctPasswordVerified = true;
      }
    }
    logTest(9, "Device B successfully verifies master password using synchronized server canary", correctPasswordVerified);

    // 8. Device B: Downloads and decrypts Device A's items
    const remoteItemsOnB = await vaultApi.listItems();
    let decryptedOnBCount = 0;
    for (const item of remoteItemsOnB) {
      const decrypted = await decryptVaultPayload<any>(item as any, keyBCorrect);
      if (decrypted.service === "GitHub" || decrypted.service === "Google") {
        decryptedOnBCount++;
      }
      await saveEncryptedRecord({
        id: item.id,
        encryptedPayload: item.encryptedPayload,
        initializationVector: item.initializationVector,
        authenticationTag: item.authenticationTag,
        encryptionAlgorithm: item.encryptionAlgorithm as "AES-256-GCM",
        encryptionVersion: item.encryptionVersion as 1,
        revision: item.revision,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt
      });
    }
    logTest(10, "Device B downloads and decrypts Device A's records byte-for-byte", decryptedOnBCount === 2);

    // 9. Device B: Creates a new encrypted item and synchronizes it
    const item3Enc = await encryptVaultPayload({ service: "Amazon", username: "user@amazon.com", password: "pwd3" }, keyBCorrect);
    const item3Server = await vaultApi.createItem(item3Enc);
    logTest(11, "Device B creates new item 3 and uploads to backend", Boolean(item3Server.id));

    // 10. Device A: Retrieves Device B's new item via synchronization
    setAccessToken(user1Token);
    setActiveStorageUser(user1Id);
    const syncResA = await syncApi.getChanges(0, 100);
    const foundItem3InSync = syncResA.changes.some((c) => c.id === item3Server.id);
    logTest(12, "Device A retrieves Device B's synchronized new item via incremental sync", foundItem3InSync);

    // ════════════════════════════════════════════════════════════════════════════
    // Section 2: Legacy Vault Migration & Create-Once Enforcement
    // ════════════════════════════════════════════════════════════════════════════
    console.log("\n── Section 2: Legacy Canary Migration & Protection ──");

    // 11. Create a legacy user with items but NO remote verification record
    const legacyEmail = `legacy_${timestamp}@vaultguard.test`;
    const legacyKdf = createDefaultKdfMetadata();
    const legacyUser = await authApi.register({
      email: legacyEmail,
      password: accountPassword,
      vaultKdfSalt: legacyKdf.vaultKdfSalt,
      vaultKdfAlgorithm: legacyKdf.vaultKdfAlgorithm,
      vaultKdfParameters: legacyKdf.vaultKdfParameters
    });
    const legacyLogin = await authApi.login({ email: legacyEmail, password: accountPassword, deviceName: "Legacy-Device" });
    setAccessToken(legacyLogin.token);
    setActiveStorageUser(legacyUser.id);

    const legacyKey = await deriveVaultKey(masterPasswordCorrect, legacyKdf.vaultKdfSalt, legacyKdf.vaultKdfParameters.iterations);
    const legacyItemEnc = await encryptVaultPayload({ service: "LegacyBank", username: "bankuser", password: "bankpwd" }, legacyKey);
    await vaultApi.createItem(legacyItemEnc);

    // Save canary locally on Device A only (simulating pre-Phase 9.1 state)
    const localLegacyCanary = await encryptVaultPayload({ verifier: "vaultguard-master-key-verified" }, legacyKey);
    await saveAuthVerification(localLegacyCanary);

    // Verify backend has items but no verification record
    const legacyStatus = await vaultApi.getVerification();
    logTest(
      13,
      "Legacy vault state recognized: hasItems=true and hasVerification=false",
      legacyStatus.hasItems === true && legacyStatus.hasVerification === false
    );

    // 12. New Device attempts to initialize a new canary on legacy vault WITHOUT legacy migration flag
    let unauthorizedCanaryRejected = false;
    try {
      await vaultApi.createVerification({
        encryptedPayload: localLegacyCanary.encryptedPayload,
        initializationVector: localLegacyCanary.initializationVector,
        authenticationTag: localLegacyCanary.authenticationTag,
        encryptionAlgorithm: localLegacyCanary.encryptionAlgorithm,
        encryptionVersion: localLegacyCanary.encryptionVersion,
        isLegacyMigration: false // Standard initialization request
      });
    } catch (err: any) {
      if (err?.status === 409) {
        unauthorizedCanaryRejected = true;
      }
    }
    logTest(14, "Server strictly rejects standard initialization on legacy vault containing items (409 Conflict)", unauthorizedCanaryRejected);

    // 13. Original device performs approved legacy migration (isLegacyMigration: true)
    const migrationResult = await vaultApi.createVerification({
      encryptedPayload: localLegacyCanary.encryptedPayload,
      initializationVector: localLegacyCanary.initializationVector,
      authenticationTag: localLegacyCanary.authenticationTag,
      encryptionAlgorithm: localLegacyCanary.encryptionAlgorithm,
      encryptionVersion: localLegacyCanary.encryptionVersion,
      isLegacyMigration: true
    });
    logTest(15, "Original device successfully performs approved legacy migration", Boolean(migrationResult.id));

    // 14. Subsequent attempt to overwrite migrated canary rejected with 409 Conflict
    let overwriteRejected = false;
    try {
      await vaultApi.createVerification({
        encryptedPayload: localLegacyCanary.encryptedPayload,
        initializationVector: localLegacyCanary.initializationVector,
        authenticationTag: localLegacyCanary.authenticationTag,
        isLegacyMigration: true
      });
    } catch (err: any) {
      if (err?.status === 409) {
        overwriteRejected = true;
      }
    }
    logTest(16, "Create-once enforcement: second verification creation strictly rejected with 409 Conflict", overwriteRejected);

    // ════════════════════════════════════════════════════════════════════════════
    // Section 3: Decryption Integrity Enforcement
    // ════════════════════════════════════════════════════════════════════════════
    console.log("\n── Section 3: Decryption Failure & Tamper Protection ──");

    // 15. Verify that tampered ciphertext throws DecryptionError and is NOT silently ignored
    const corruptRecord: EncryptedVaultRecord = {
      id: "corrupt-test-uuid",
      encryptedPayload: Buffer.from("CorruptedCiphertextBytes!").toString("base64"),
      initializationVector: Buffer.from(generateInitializationVector()).toString("base64"),
      authenticationTag: Buffer.from("1234567890123456").toString("base64"),
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    let caughtIntegrityError = false;
    try {
      await decryptVaultPayload(corruptRecord, legacyKey);
    } catch (err) {
      if (err instanceof DecryptionError) {
        caughtIntegrityError = true;
      }
    }
    logTest(17, "Corrupt vault item payload strictly triggers DecryptionError (never silently ignored)", caughtIntegrityError);

    // ════════════════════════════════════════════════════════════════════════════
    // Section 4: In-Flight Synchronization Cancellation
    // ════════════════════════════════════════════════════════════════════════════
    console.log("\n── Section 4: In-Flight Synchronization Cancellation ──");

    // 16. Verify cancelSync immediately aborts running sync and marks cancelled
    let syncCancelled = false;
    let itemsUpdatedCalledAfterLock = false;

    // Start a sync pass with lock guard
    let vaultIsUnlocked = true;
    let lockGen = 1;

    const syncPromise = syncEngine.sync(
      legacyKey,
      (_updater) => {
        if (!vaultIsUnlocked || lockGen !== 1) {
          itemsUpdatedCalledAfterLock = true;
        }
      },
      () => vaultIsUnlocked,
      () => lockGen
    );

    // Immediately simulate lockVault
    vaultIsUnlocked = false;
    lockGen++;
    syncEngine.cancelSync();

    const syncRes = await syncPromise;
    logTest(18, "Calling cancelSync / locking during in-flight sync returns cancelled result", syncRes.cancelled === true);
    logTest(19, "Cancellation guard guarantees onItemsUpdated is never invoked after lock", itemsUpdatedCalledAfterLock === false);

    // ════════════════════════════════════════════════════════════════════════════
    // Section 5: Account-Scoped Local Storage Isolation
    // ════════════════════════════════════════════════════════════════════════════
    console.log("\n── Section 5: Account-Scoped Local Storage Isolation ──");

    // 17. Account 1 stores local records
    setActiveStorageUser("account_alpha");
    await saveEncryptedRecord({
      id: "alpha-record-1",
      encryptedPayload: "YWxwaGEtcGF5bG9hZA==",
      initializationVector: Buffer.from(generateInitializationVector()).toString("base64"),
      authenticationTag: Buffer.from("1234567890123456").toString("base64"),
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });

    const alphaRecords = await listEncryptedRecords();
    logTest(20, "Account Alpha saves and retrieves its local encrypted record", alphaRecords.length === 1);

    // 18. Account Beta logs in: Storage switches to Account Beta
    setActiveStorageUser("account_beta");
    const betaRecords = await listEncryptedRecords();
    logTest(21, "Account Beta cannot read Account Alpha's local records (strict isolation)", betaRecords.length === 0);

    const alphaRecordReadByBeta = await getEncryptedRecord("alpha-record-1");
    logTest(22, "Account Beta querying Account Alpha record ID returns null", alphaRecordReadByBeta === null);

    // 19. Account Alpha logs out -> clearAccountCache purges Alpha records
    await clearAccountCache("account_alpha");
    setActiveStorageUser("account_alpha");
    const alphaRecordsAfterPurge = await listEncryptedRecords();
    logTest(23, "clearAccountCache completely purges account records on logout", alphaRecordsAfterPurge.length === 0);

  } finally {
    // Teardown
    server.close();
    await prisma.vaultVerification.deleteMany({
      where: {
        user: {
          email: { in: [user1Email, user2Email, `legacy_${timestamp}@vaultguard.test`] }
        }
      }
    }).catch(() => {});
    await prisma.vaultItem.deleteMany({
      where: {
        user: {
          email: { in: [user1Email, user2Email, `legacy_${timestamp}@vaultguard.test`] }
        }
      }
    }).catch(() => {});
    await prisma.session.deleteMany({
      where: {
        user: {
          email: { in: [user1Email, user2Email, `legacy_${timestamp}@vaultguard.test`] }
        }
      }
    }).catch(() => {});
    await prisma.device.deleteMany({
      where: {
        user: {
          email: { in: [user1Email, user2Email, `legacy_${timestamp}@vaultguard.test`] }
        }
      }
    }).catch(() => {});
    await prisma.user.deleteMany({
      where: {
        email: { in: [user1Email, user2Email, `legacy_${timestamp}@vaultguard.test`] }
      }
    }).catch(() => {});
  }

  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Phase 9.1 Verification Summary: ${testPassedCount + testFailedCount} tests | ✅ ${testPassedCount} passed | ❌ ${testFailedCount} failed`);
  console.log("════════════════════════════════════════════════════════════\n");

  if (testFailedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

run().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
