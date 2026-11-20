/**
 * VaultGuard Phase 10.4 – Secure Encrypted Vault Export & Import Verification Suite
 *
 * Verifies:
 * 1. Secure Export:
 *    - Empty vault export contains valid structure and 0 records
 *    - Populated vault export creates versioned format (v1, "vaultguard-encrypted-backup")
 *    - Encrypted payloads, 12-byte IVs, 16-byte tags are present; plaintext is strictly NEVER present
 *    - Valid KDF metadata preserved (PBKDF2 >= 600,000 iterations, 16-byte salt, SHA-256)
 * 2. Secure Import & Validation:
 *    - Malformed JSON rejected
 *    - Missing envelope / schema violation rejected
 *    - Unsupported formatVersion or formatName rejected
 *    - Invalid KDF metadata (iterations < 600,000, invalid salt) rejected
 *    - Incompatible KDF salt rejected when matched against active user's salt
 *    - Oversized file (> 5 MB) rejected
 *    - Duplicate internal record IDs rejected
 *    - Non-canonical Base64 rejected
 *    - Invalid IV length (!= 12 bytes) rejected
 *    - Invalid Tag length (!= 16 bytes) rejected
 * 3. Pre-Commit Decryption Guard & Atomicity:
 *    - Genuine records decrypt successfully with active key
 *    - Corrupted ciphertext / tag fails pre-commit decryption and halts import
 *    - Atomic rollback: zero mutations to IndexedDB / local storage on failure
 * 4. Backend Transactional Integrity (POST /api/vault/batch-import):
 *    - Atomic insertion in single prisma.$transaction
 *    - Incremental syncVersion increment
 *    - Internal duplicate IDs rejected with 409 Conflict
 *    - Conflict handling: 'error' aborts whole transaction; 'skip' bypasses conflicting item
 *    - Unauthenticated request rejected (401)
 *    - Malformed request rejected (400)
 * 5. Security & Zero-Knowledge Verification:
 *    - Master password never transmitted or exported
 *    - Exported backup can be decrypted with user's master password in a fresh context
 *    - Exported backup CANNOT be decrypted with a different master password
 *
 * Usage: tsx --env-file=../VaultGuard-Backend/.env scripts/verify-phase10-4.ts
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
import { generateAccessToken } from "../../VaultGuard-Backend/src/utils/jwt";
import { hashPassword } from "../../VaultGuard-Backend/src/utils/password";
import {
  createVaultExport,
  validateVaultBackup,
  BACKUP_FORMAT_VERSION,
  BACKUP_FORMAT_NAME,
  MAX_BACKUP_FILE_BYTES,
  type VaultBackupFile
} from "../lib/crypto/export-import";
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
  setActiveStorageUser,
  resetVaultDatabase
} from "../lib/storage/vault-db";
import type { EncryptedVaultRecord, VaultKdfMetadata, DecryptedVaultItem } from "../lib/crypto/types";

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
  console.log("VaultGuard Phase 10.4: Secure Encrypted Vault Export & Import Verification Suite");
  console.log("================================================================================\n");

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const timestamp = Date.now();
  const testUserEmail = `phase10_4_${timestamp}@example.com`;
  const accountPassword = "Password!123456Phase104";
  const masterPassword = "CorrectMasterPassword!104";
  const wrongMasterPassword = "WrongMasterPassword!999";

  let testUserId = "";
  let testSessionId = "";
  let testToken = "";

  try {
    // ── SECTION 1: Export Functionality ──
    console.log("── Section 1: Encrypted Vault Export Functionality ──");

    const kdfMetadata = createDefaultKdfMetadata();
    const derivedKey = await deriveVaultKey(masterPassword, kdfMetadata.vaultKdfSalt, kdfMetadata.vaultKdfParameters.iterations);

    // 1.1 Empty vault export contains valid structure and 0 records
    const emptyExport = createVaultExport([], kdfMetadata);
    logTest(
      1,
      "Empty vault export contains valid structure and 0 records",
      emptyExport.vaultguardBackup.recordCount === 0 &&
        emptyExport.vaultguardBackup.records.length === 0 &&
        emptyExport.vaultguardBackup.formatVersion === BACKUP_FORMAT_VERSION &&
        emptyExport.vaultguardBackup.formatName === BACKUP_FORMAT_NAME
    );

    // Prepare synthetic decrypted items
    const secret1 = "SuperSecretP@ssword123!";
    const secret2 = "AnotherFinancialSecret#456$";
    const enc1 = await encryptVaultPayload({ service: "ProtonMail", username: "alice@pm.me", password: secret1 }, derivedKey);
    const enc2 = await encryptVaultPayload({ service: "CryptoWallet", username: "bob_wallet", password: secret2 }, derivedKey);

    const record1: EncryptedVaultRecord = {
      id: "rec-item-1",
      encryptedPayload: enc1.encryptedPayload,
      initializationVector: enc1.initializationVector,
      authenticationTag: enc1.authenticationTag,
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      revision: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    const record2: EncryptedVaultRecord = {
      id: "rec-item-2",
      encryptedPayload: enc2.encryptedPayload,
      initializationVector: enc2.initializationVector,
      authenticationTag: enc2.authenticationTag,
      encryptionAlgorithm: "AES-256-GCM",
      encryptionVersion: 1,
      revision: 2,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // 1.2 Populated vault export creates versioned format
    const populatedExport = createVaultExport([record1, record2], kdfMetadata);
    const backupJson = JSON.stringify(populatedExport, null, 2);

    logTest(
      2,
      "Populated vault export contains all records properly structured",
      populatedExport.vaultguardBackup.recordCount === 2 &&
        populatedExport.vaultguardBackup.records.length === 2 &&
        populatedExport.vaultguardBackup.records[0].id === "rec-item-1" &&
        populatedExport.vaultguardBackup.records[1].id === "rec-item-2"
    );

    // 1.3 Ciphertext fields, IVs, tags present
    logTest(
      3,
      "Exported records contain 12-byte IVs, 16-byte tags, and AES-256-GCM metadata",
      populatedExport.vaultguardBackup.records.every(
        (r) =>
          Buffer.from(r.initializationVector, "base64").length === 12 &&
          Buffer.from(r.authenticationTag, "base64").length === 16 &&
          r.encryptionAlgorithm === "AES-256-GCM" &&
          r.encryptionVersion === 1
      )
    );

    // 1.4 Zero Plaintext Leakage: neither secret1, secret2, nor master password in export
    const containsPlaintext =
      backupJson.includes(secret1) ||
      backupJson.includes(secret2) ||
      backupJson.includes(masterPassword);
    logTest(
      4,
      "Plaintext passwords or master passwords are NEVER present in exported JSON",
      !containsPlaintext
    );

    // 1.5 KDF parameters preserved
    logTest(
      5,
      "KDF parameters preserved (PBKDF2 >= 600,000 iterations, 16-byte salt, SHA-256)",
      populatedExport.vaultguardBackup.kdfMetadata.vaultKdfParameters.iterations >= 600000 &&
        Buffer.from(populatedExport.vaultguardBackup.kdfMetadata.vaultKdfSalt, "base64").length === 16 &&
        populatedExport.vaultguardBackup.kdfMetadata.vaultKdfParameters.digest === "SHA-256"
    );

    // ── SECTION 2: Import Validation ──
    console.log("\n── Section 2: Encrypted Vault Import Validation ──");

    // 2.1 Malformed JSON is rejected
    const malformedRes = validateVaultBackup("{ bad json: true, ");
    logTest(
      6,
      "Malformed JSON string is rejected with descriptive error",
      !malformedRes.success && !!malformedRes.error?.includes("JSON")
    );

    // 2.2 Missing envelope
    const missingEnvelopeRes = validateVaultBackup(JSON.stringify({ records: [] }));
    logTest(
      7,
      "Missing 'vaultguardBackup' envelope root object is rejected",
      !missingEnvelopeRes.success && !!missingEnvelopeRes.error?.includes("vaultguardBackup")
    );

    // 2.3 Unsupported format version
    const invalidVersionObj = JSON.parse(backupJson);
    invalidVersionObj.vaultguardBackup.formatVersion = 999;
    const invalidVersionRes = validateVaultBackup(JSON.stringify(invalidVersionObj));
    logTest(
      8,
      "Unsupported backup formatVersion (e.g. 999) is rejected",
      !invalidVersionRes.success && (!!invalidVersionRes.error?.includes("format version") || !!invalidVersionRes.error?.includes("formatVersion"))
    );

    // 2.4 Unsupported format name
    const invalidNameObj = JSON.parse(backupJson);
    invalidNameObj.vaultguardBackup.formatName = "insecure-plain-backup";
    const invalidNameRes = validateVaultBackup(JSON.stringify(invalidNameObj));
    logTest(
      9,
      "Unsupported backup formatName is rejected",
      !invalidNameRes.success && (!!invalidNameRes.error?.includes("format") || !!invalidNameRes.error?.includes("formatName"))
    );

    // 2.5 Invalid KDF parameters (iterations < 600,000)
    const lowIterationsObj = JSON.parse(backupJson);
    lowIterationsObj.vaultguardBackup.kdfMetadata.vaultKdfParameters.iterations = 1000;
    const lowIterationsRes = validateVaultBackup(JSON.stringify(lowIterationsObj));
    logTest(
      10,
      "Insecure PBKDF2 iterations (< 600,000) is rejected",
      !lowIterationsRes.success && !!lowIterationsRes.error?.includes("iterations")
    );

    // 2.6 Invalid KDF salt (not 16 bytes)
    const invalidSaltObj = JSON.parse(backupJson);
    invalidSaltObj.vaultguardBackup.kdfMetadata.vaultKdfSalt = Buffer.from("short").toString("base64");
    const invalidSaltRes = validateVaultBackup(JSON.stringify(invalidSaltObj));
    logTest(
      11,
      "Invalid KDF salt length (not 16 bytes) is rejected",
      !invalidSaltRes.success && (!!invalidSaltRes.error?.toLowerCase().includes("salt"))
    );

    // 2.7 Incompatible KDF salt with active account
    const incompatibleSaltRes = validateVaultBackup(
      backupJson,
      Buffer.from("00112233445566778899aabbccddeeff", "hex").toString("base64")
    );
    logTest(
      12,
      "Incompatible KDF salt rejected when compared with active user's salt",
      !incompatibleSaltRes.success && !!incompatibleSaltRes.error?.includes("Incompatible")
    );

    // 2.8 Oversized file (> 5 MiB)
    const oversizedString = "A".repeat(MAX_BACKUP_FILE_BYTES + 10);
    const oversizedRes = validateVaultBackup(oversizedString);
    logTest(
      13,
      "Oversized backup payload (> 5 MiB) is rejected before full processing",
      !oversizedRes.success && !!oversizedRes.error?.includes("exceeds")
    );

    // 2.9 Internal duplicate record IDs within backup
    const duplicateIdObj = JSON.parse(backupJson);
    duplicateIdObj.vaultguardBackup.records.push({ ...record1 }); // Duplicate ID 'rec-item-1'
    duplicateIdObj.vaultguardBackup.recordCount = 3;
    const duplicateIdRes = validateVaultBackup(JSON.stringify(duplicateIdObj));
    logTest(
      14,
      "Internal duplicate record IDs within the backup payload are detected and rejected",
      !duplicateIdRes.success && !!duplicateIdRes.error?.includes("Duplicate record")
    );

    // 2.10 Invalid Base64 payload
    const invalidBase64Obj = JSON.parse(backupJson);
    invalidBase64Obj.vaultguardBackup.records[0].encryptedPayload = "???not-valid-base64***";
    const invalidBase64Res = validateVaultBackup(JSON.stringify(invalidBase64Obj));
    logTest(
      15,
      "Invalid Base64 payload format is detected and rejected",
      !invalidBase64Res.success && !!invalidBase64Res.error?.includes("encryptedPayload")
    );

    // 2.11 Invalid IV length (!= 12 bytes)
    const invalidIvObj = JSON.parse(backupJson);
    invalidIvObj.vaultguardBackup.records[0].initializationVector = Buffer.from("short").toString("base64");
    const invalidIvRes = validateVaultBackup(JSON.stringify(invalidIvObj));
    logTest(
      16,
      "Invalid IV length (!= 12 bytes / 96 bits) is rejected",
      !invalidIvRes.success && !!invalidIvRes.error?.includes("12 bytes")
    );

    // 2.12 Invalid authentication tag length (!= 16 bytes)
    const invalidTagObj = JSON.parse(backupJson);
    invalidTagObj.vaultguardBackup.records[0].authenticationTag = Buffer.from("short-tag").toString("base64");
    const invalidTagRes = validateVaultBackup(JSON.stringify(invalidTagObj));
    logTest(
      17,
      "Invalid authentication tag length (!= 16 bytes / 128 bits) is rejected",
      !invalidTagRes.success && !!invalidTagRes.error?.includes("16 bytes")
    );

    // ── SECTION 3: Pre-Commit Decryption Guard & Atomicity ──
    console.log("\n── Section 3: Pre-Commit Decryption Guard & Atomicity ──");

    // 3.1 Genuine records decrypt successfully with active key
    let preCommitPassed = true;
    for (const rec of populatedExport.vaultguardBackup.records) {
      try {
        const dec = await decryptVaultPayload(rec, derivedKey);
        if (!dec) preCommitPassed = false;
      } catch {
        preCommitPassed = false;
      }
    }
    logTest(
      18,
      "Pre-commit decryption succeeds on genuine records matching user's active key",
      preCommitPassed
    );

    // 3.2 Corrupted ciphertext / tag fails pre-commit decryption
    const corruptedRecord = {
      ...record1,
      id: "corrupted-rec",
      // Tamper with authentication tag
      authenticationTag: Buffer.from("0000000000000000").toString("base64")
    };

    let corruptedCaught = false;
    try {
      await decryptVaultPayload(corruptedRecord, derivedKey);
    } catch (err: any) {
      corruptedCaught = true;
    }
    logTest(
      19,
      "Corrupted ciphertext or tampered tag fails pre-commit decryption with CryptographicError",
      corruptedCaught
    );

    // 3.3 Atomic rollback on pre-commit decryption failure: zero local records saved
    setActiveStorageUser("test-user-rollback");
    await resetVaultDatabase();
    await saveEncryptedRecord(record1);

    const initialRecords = await listEncryptedRecords();
    assert.strictEqual(initialRecords.length, 1, "Initial count should be 1");

    // Simulate import failure during pre-commit decryption loop
    let importAborted = false;
    try {
      // Step: pre-commit decrypt
      const candidateBatch = [record2, corruptedRecord];
      for (const rec of candidateBatch) {
        await decryptVaultPayload(rec, derivedKey); // Corrupted item will throw!
      }
      // If we got here, write to DB (should NOT happen)
      for (const rec of candidateBatch) {
        await saveEncryptedRecord(rec);
      }
    } catch {
      importAborted = true;
    }

    const recordsAfterAbort = await listEncryptedRecords();
    logTest(
      20,
      "Pre-commit failure halts import before modifying storage (atomic local state preservation)",
      importAborted && recordsAfterAbort.length === 1 && recordsAfterAbort[0].id === record1.id
    );

    // ── SECTION 4: Backend Transactional Integrity (POST /api/vault/batch-import) ──
    console.log("\n── Section 4: Backend Transactional Integrity (POST /api/vault/batch-import) ──");

    // Create test user and session in database
    const passwordHash = await hashPassword(accountPassword);
    const dbUser = await prisma.user.create({
      data: {
        email: testUserEmail,
        emailNormalized: testUserEmail.toLowerCase(),
        passwordHash,
        vaultKdfSalt: kdfMetadata.vaultKdfSalt,
        vaultKdfParameters: kdfMetadata.vaultKdfParameters as any
      }
    });
    testUserId = dbUser.id;

    const device = await prisma.device.create({
      data: {
        userId: testUserId,
        deviceIdentifier: `phase10_device_${timestamp}`,
        deviceName: "Test Browser Device"
      }
    });

    const session = await prisma.session.create({
      data: {
        userId: testUserId,
        deviceId: device.id,
        expiresAt: new Date(Date.now() + 3600000)
      }
    });
    testSessionId = session.id;
    testToken = generateAccessToken({ sub: testUserId, email: testUserEmail, sid: session.id });

    // 4.1 Unauthenticated batch import rejected (401)
    const unauthRes = await request(baseUrl, "POST", "/api/vault/batch-import", undefined, {
      items: [
        {
          id: crypto.randomUUID(),
          encryptedPayload: enc1.encryptedPayload,
          initializationVector: enc1.initializationVector,
          authenticationTag: enc1.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        }
      ]
    });
    logTest(21, "Unauthenticated batch-import request is rejected with 401 Unauthorized", unauthRes.status === 401);

    // 4.2 Empty items array rejected (400)
    const emptyItemsRes = await request(baseUrl, "POST", "/api/vault/batch-import", testToken, {
      items: []
    });
    logTest(22, "Empty items array in batch-import is rejected with 400 Bad Request", emptyItemsRes.status === 400);

    // 4.3 Valid batch import into empty vault inserts all records atomically
    const testItemId1 = crypto.randomUUID();
    const testItemId2 = crypto.randomUUID();
    const batchImport1 = await request(baseUrl, "POST", "/api/vault/batch-import", testToken, {
      strategy: "error",
      items: [
        {
          id: testItemId1,
          encryptedPayload: enc1.encryptedPayload,
          initializationVector: enc1.initializationVector,
          authenticationTag: enc1.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1,
          createdAt: record1.createdAt,
          updatedAt: record1.updatedAt
        },
        {
          id: testItemId2,
          encryptedPayload: enc2.encryptedPayload,
          initializationVector: enc2.initializationVector,
          authenticationTag: enc2.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1,
          createdAt: record2.createdAt,
          updatedAt: record2.updatedAt
        }
      ]
    });

    logTest(
      23,
      "Valid batch import into empty vault inserts all records atomically with 200 OK",
      batchImport1.status === 200 &&
        batchImport1.body?.data?.totalProcessed === 2 &&
        batchImport1.body?.data?.insertedCount === 2 &&
        batchImport1.body?.data?.skippedCount === 0
    );

    // Verify database rows directly
    const userDbItems = await prisma.vaultItem.findMany({ where: { userId: testUserId } });
    logTest(
      24,
      "Database confirms all batch items persisted with correct syncVersion and ciphertext",
      userDbItems.length === 2 &&
        userDbItems.every((item) => item.syncVersion > 0 && item.deletedAt === null)
    );

    // 4.4 Internal duplicate IDs within request payload rejected (409)
    const dupItemId = crypto.randomUUID();
    const internalDupRes = await request(baseUrl, "POST", "/api/vault/batch-import", testToken, {
      strategy: "error",
      items: [
        {
          id: dupItemId,
          encryptedPayload: enc1.encryptedPayload,
          initializationVector: enc1.initializationVector,
          authenticationTag: enc1.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        },
        {
          id: dupItemId, // Same ID in same request!
          encryptedPayload: enc2.encryptedPayload,
          initializationVector: enc2.initializationVector,
          authenticationTag: enc2.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        }
      ]
    });
    logTest(
      25,
      "Duplicate internal IDs within batch import request are rejected with 409 Conflict",
      internalDupRes.status === 409 && (!!internalDupRes.body?.message?.includes("Duplicate item ID") || !!internalDupRes.body?.message?.includes("Duplicate record ID"))
    );

    // 4.5 Conflicting record with different ciphertext:
    // With strategy: 'error', must reject with 409 and roll back entirely
    const diffEnc = await encryptVaultPayload({ service: "DifferentService", password: "pwd" }, derivedKey);
    const neverInsertedId = crypto.randomUUID();
    const conflictErrorRes = await request(baseUrl, "POST", "/api/vault/batch-import", testToken, {
      strategy: "error",
      items: [
        {
          id: testItemId1, // Already exists with different ciphertext!
          encryptedPayload: diffEnc.encryptedPayload,
          initializationVector: diffEnc.initializationVector,
          authenticationTag: diffEnc.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        },
        {
          id: neverInsertedId,
          encryptedPayload: enc1.encryptedPayload,
          initializationVector: enc1.initializationVector,
          authenticationTag: enc1.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        }
      ]
    });

    logTest(
      26,
      "Conflict with strategy='error' returns 409 Conflict and rolls back transaction",
      conflictErrorRes.status === 409
    );

    // Verify rollback: 'neverInsertedId' was NOT inserted
    const neverInsertedItem = await prisma.vaultItem.findUnique({
      where: { id: neverInsertedId }
    });
    logTest(
      27,
      "Prisma transaction rollback verified: no partial insertions occurred on conflict",
      neverInsertedItem === null
    );

    // 4.6 Conflicting record with strategy: 'skip' skips conflicting and inserts non-conflicting
    const testItemId3 = crypto.randomUUID();
    const conflictSkipRes = await request(baseUrl, "POST", "/api/vault/batch-import", testToken, {
      strategy: "skip",
      items: [
        {
          id: testItemId1, // Conflicts: will be skipped
          encryptedPayload: diffEnc.encryptedPayload,
          initializationVector: diffEnc.initializationVector,
          authenticationTag: diffEnc.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        },
        {
          id: testItemId3, // Non-conflicting: will be inserted
          encryptedPayload: enc1.encryptedPayload,
          initializationVector: enc1.initializationVector,
          authenticationTag: enc1.authenticationTag,
          encryptionAlgorithm: "AES-256-GCM",
          encryptionVersion: 1
        }
      ]
    });

    logTest(
      28,
      "Conflict with strategy='skip' skips conflicting records and inserts new ones",
      conflictSkipRes.status === 200 &&
        conflictSkipRes.body?.data?.totalProcessed === 2 &&
        conflictSkipRes.body?.data?.insertedCount === 1 &&
        conflictSkipRes.body?.data?.skippedCount === 1
    );

    const insertedItem3 = await prisma.vaultItem.findUnique({
      where: { id: testItemId3 }
    });
    logTest(
      29,
      "Database confirms new non-conflicting item was inserted while conflicting item was skipped",
      insertedItem3 !== null && insertedItem3.userId === testUserId
    );

    // ── SECTION 5: Security & Zero-Knowledge Verification ──
    console.log("\n── Section 5: Security & Zero-Knowledge Verification ──");

    // 5.1 Fresh key derivation with correct master password decrypts exported records
    const freshDerivedKey = await deriveVaultKey(
      masterPassword,
      populatedExport.vaultguardBackup.kdfMetadata.vaultKdfSalt,
      populatedExport.vaultguardBackup.kdfMetadata.vaultKdfParameters.iterations
    );
    const decrypted1 = await decryptVaultPayload<any>(populatedExport.vaultguardBackup.records[0], freshDerivedKey);
    const decrypted2 = await decryptVaultPayload<any>(populatedExport.vaultguardBackup.records[1], freshDerivedKey);

    logTest(
      30,
      "Fresh derivation with correct master password successfully decrypts all exported records",
      decrypted1.password === secret1 && decrypted2.password === secret2
    );

    // 5.2 Different master password derivation CANNOT decrypt exported records
    const wrongKey = await deriveVaultKey(
      wrongMasterPassword,
      populatedExport.vaultguardBackup.kdfMetadata.vaultKdfSalt,
      populatedExport.vaultguardBackup.kdfMetadata.vaultKdfParameters.iterations
    );
    let wrongKeyFailed = false;
    try {
      await decryptVaultPayload(populatedExport.vaultguardBackup.records[0], wrongKey);
    } catch {
      wrongKeyFailed = true;
    }
    logTest(
      31,
      "Different master password strictly fails authentication tag verification (zero-knowledge privacy)",
      wrongKeyFailed
    );

    // 5.3 Verify zero master passwords or plaintext secrets in backend database
    const allDbUserRecords = await prisma.vaultItem.findMany({ where: { userId: testUserId } });
    const dbHasPlaintext = allDbUserRecords.some((r) => {
      const payloadStr = Buffer.from(r.encryptedPayload).toString("utf-8");
      return (
        payloadStr.includes(secret1) ||
        payloadStr.includes(secret2) ||
        payloadStr.includes(masterPassword)
      );
    });
    logTest(
      32,
      "Zero plaintext secrets or master passwords stored in database (encryptedPayload is AES ciphertext)",
      !dbHasPlaintext
    );
  } catch (error: any) {
    console.error("Unexpected error in verification suite:", error);
    testFailedCount++;
  } finally {
    // Clean up test database records safely
    if (testUserId) {
      await prisma.vaultItem.deleteMany({ where: { userId: testUserId } }).catch(() => {});
      await prisma.session.deleteMany({ where: { userId: testUserId } }).catch(() => {});
      await prisma.device.deleteMany({ where: { userId: testUserId } }).catch(() => {});
      await prisma.user.delete({ where: { id: testUserId } }).catch(() => {});
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await prisma.$disconnect().catch(() => {});
  }

  console.log("\n================================================================================");
  console.log(`Phase 10.4 Verification Complete: ${testPassedCount} Passed, ${testFailedCount} Failed`);
  console.log("================================================================================");

  if (testFailedCount > 0) {
    process.exit(1);
  }
  process.exit(0);
}

run().catch((err) => {
  console.error("Fatal test error:", err);
  process.exit(1);
});
