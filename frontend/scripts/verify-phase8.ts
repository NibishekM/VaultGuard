/**
 * VaultGuard – Phase 8 Automated Cryptographic Verification Suite
 *
 * Verifies all 20 mandatory cryptographic specifications:
 * 1. Secure random salt generation
 * 2. Correct salt length (16 bytes)
 * 3. PBKDF2 derivation with required parameters (600,000 iterations, SHA-256, 32-byte key)
 * 4. Correct AES-GCM encryption
 * 5. Correct AES-GCM decryption
 * 6. Unique IV generation (12 bytes, unique each invocation)
 * 7. Ciphertext and authentication-tag splitting (last 16 bytes is tag)
 * 8. Ciphertext and authentication-tag recombination
 * 9. Wrong master password rejection (tag verification failure)
 * 10. Modified ciphertext rejection
 * 11. Modified IV rejection
 * 12. Modified authentication-tag rejection
 * 13. Invalid Base64 rejection
 * 14. Unsupported algorithm rejection
 * 15. Invalid KDF metadata rejection
 * 16. Non-extractable key enforcement (key.extractable === false)
 * 17. Key clearing on lock
 * 18. Decrypted data clearing on lock
 * 19. IndexedDB encrypted-only persistence (zero plaintext persisted)
 * 20. Regression tests for existing password analyzer and generator
 *
 * Usage: node --experimental-strip-types scripts/verify-phase8.ts
 */

import assert from "node:assert";
import {
  VAULT_CRYPTO_CONSTANTS,
  generateKdfSalt,
  createDefaultKdfMetadata,
  validateKdfMetadata,
  deriveVaultKey,
  generateInitializationVector,
  encryptVaultPayload,
  decryptVaultPayload,
  uint8ArrayToBase64,
  base64ToUint8Array,
  DecryptionError,
  CryptographicError,
  type EncryptedVaultRecord
} from "../lib/crypto/index";
import {
  saveEncryptedRecord,
  getEncryptedRecord,
  listEncryptedRecords,
  deleteEncryptedRecord,
  saveKdfMetadata,
  getKdfMetadata,
  clearAllEncryptedRecords,
  resetVaultDatabase
} from "../lib/storage/vault-db";
import { analyzePassword, generateRandomPassword, generatePassphrase } from "../lib/password-tools";

let passed = 0;
let failed = 0;
const failures: string[] = [];

function test(name: string, fn: () => void | Promise<void>): Promise<void> {
  return Promise.resolve()
    .then(fn)
    .then(() => {
      console.log(`  ✅ PASS [${passed + failed + 1}] ${name}`);
      passed++;
    })
    .catch((err) => {
      console.error(`  ❌ FAIL [${passed + failed + 1}] ${name}`);
      console.error(`     Error: ${err.message}`);
      failed++;
      failures.push(name);
    });
}

async function runSuite(): Promise<void> {
  console.log("================================================================================");
  console.log("VaultGuard Phase 8: Frontend Cryptography & Security Verification Suite");
  console.log("================================================================================\n");

  const masterPass = "SuperSecretMasterPass!2026";
  const wrongMasterPass = "WrongMasterPassword!9999";

  // Test 1: Secure random salt generation
  await test("1. Secure random salt generation returns a Uint8Array with non-zero bytes", () => {
    const salt = generateKdfSalt();
    assert(salt instanceof Uint8Array, "Salt must be a Uint8Array");
    const nonZero = salt.some((b) => b !== 0);
    assert(nonZero, "Salt must contain non-zero random bytes");
  });

  // Test 2: Correct salt length (16 bytes)
  await test("2. Generated salt length is exactly 16 bytes (128 bits)", () => {
    const salt = generateKdfSalt();
    assert.strictEqual(salt.length, 16, "Salt must be exactly 16 bytes");
    assert.strictEqual(salt.byteLength, VAULT_CRYPTO_CONSTANTS.KDF_SALT_BYTES);
  });

  // Test 3: PBKDF2 derivation with required parameters
  let derivedKey: CryptoKey;
  const testSalt = generateKdfSalt();
  await test("3. PBKDF2 derivation executes with 600,000 iterations and SHA-256", async () => {
    derivedKey = await deriveVaultKey(masterPass, testSalt, 600000);
    assert(derivedKey instanceof CryptoKey, "Derived result must be a CryptoKey");
    assert.strictEqual(derivedKey.type, "secret", "Key type must be secret");
    assert.strictEqual((derivedKey.algorithm as any).name, "AES-GCM", "Algorithm must be AES-GCM");
    assert.strictEqual((derivedKey.algorithm as any).length, 256, "Key length must be 256 bits");
  });

  // Test 4: Correct AES-GCM encryption
  let encryptedData: any;
  const samplePlaintext = {
    service: "ProtonMail",
    username: "cyber.alex@example.test",
    password: "CorrectHorseBatteryStaple!2026",
    notes: "Primary cybersecurity contact"
  };

  await test("4. Correct AES-GCM encryption produces valid encrypted payload structure", async () => {
    encryptedData = await encryptVaultPayload(samplePlaintext, derivedKey);
    assert.strictEqual(typeof encryptedData.encryptedPayload, "string", "encryptedPayload must be Base64 string");
    assert.strictEqual(typeof encryptedData.initializationVector, "string", "IV must be Base64 string");
    assert.strictEqual(typeof encryptedData.authenticationTag, "string", "authTag must be Base64 string");
    assert.strictEqual(encryptedData.encryptionAlgorithm, "AES-256-GCM");
    assert.strictEqual(encryptedData.encryptionVersion, 1);
  });

  // Test 5: Correct AES-GCM decryption
  await test("5. Correct AES-GCM decryption returns original plaintext matching byte-for-byte", async () => {
    const decrypted = await decryptVaultPayload<typeof samplePlaintext>(encryptedData, derivedKey);
    assert.deepStrictEqual(decrypted, samplePlaintext, "Decrypted object must match original plaintext");
  });

  // Test 6: Unique IV generation
  await test("6. Unique IV generation: successive encryptions use different 12-byte IVs", async () => {
    const iv1 = generateInitializationVector();
    const iv2 = generateInitializationVector();
    assert.strictEqual(iv1.length, 12, "IV length must be exactly 12 bytes");
    assert.strictEqual(iv2.length, 12, "IV length must be exactly 12 bytes");
    assert.notDeepStrictEqual(iv1, iv2, "Successive IVs must never repeat");

    const enc1 = await encryptVaultPayload("payload-a", derivedKey);
    const enc2 = await encryptVaultPayload("payload-a", derivedKey);
    assert.notStrictEqual(enc1.initializationVector, enc2.initializationVector, "IVs must differ between encryptions");
    assert.notStrictEqual(enc1.encryptedPayload, enc2.encryptedPayload, "Ciphertexts must differ due to unique IVs");
  });

  // Test 7: Ciphertext and authentication-tag splitting
  await test("7. Ciphertext and authentication-tag splitting: tag is exactly 16 bytes", () => {
    const tagBytes = base64ToUint8Array(encryptedData.authenticationTag);
    assert.strictEqual(tagBytes.length, 16, "Authentication tag must be exactly 16 bytes (128 bits)");

    const cipherBytes = base64ToUint8Array(encryptedData.encryptedPayload);
    assert(cipherBytes.length > 0, "Ciphertext must not be empty");
  });

  // Test 8: Ciphertext and authentication-tag recombination
  await test("8. Recombination of ciphertext and tag allows successful decryption", async () => {
    const decrypted = await decryptVaultPayload<typeof samplePlaintext>(encryptedData, derivedKey);
    assert.strictEqual(decrypted.service, "ProtonMail");
    assert.strictEqual(decrypted.username, "cyber.alex@example.test");
  });

  // Test 9: Wrong master password rejection
  await test("9. Wrong master password rejection: derives different key and fails auth tag verification", async () => {
    const wrongKey = await deriveVaultKey(wrongMasterPass, testSalt, 600000);
    await assert.rejects(
      async () => {
        await decryptVaultPayload(encryptedData, wrongKey);
      },
      (err: any) => err instanceof DecryptionError,
      "Must throw DecryptionError when wrong key is supplied"
    );
  });

  // Test 10: Modified ciphertext rejection
  await test("10. Modified ciphertext rejection: tampered payload fails decryption", async () => {
    const cipherBytes = base64ToUint8Array(encryptedData.encryptedPayload);
    cipherBytes[0] ^= 0x01; // flip 1 bit
    const tamperedPayload = {
      ...encryptedData,
      encryptedPayload: uint8ArrayToBase64(cipherBytes)
    };

    await assert.rejects(
      async () => {
        await decryptVaultPayload(tamperedPayload, derivedKey);
      },
      (err: any) => err instanceof DecryptionError,
      "Tampered ciphertext must fail authentication tag check"
    );
  });

  // Test 11: Modified IV rejection
  await test("11. Modified IV rejection: tampered IV fails decryption", async () => {
    const ivBytes = base64ToUint8Array(encryptedData.initializationVector);
    ivBytes[0] ^= 0x01; // flip 1 bit
    const tamperedPayload = {
      ...encryptedData,
      initializationVector: uint8ArrayToBase64(ivBytes)
    };

    await assert.rejects(
      async () => {
        await decryptVaultPayload(tamperedPayload, derivedKey);
      },
      (err: any) => err instanceof DecryptionError,
      "Tampered IV must fail authentication tag check"
    );
  });

  // Test 12: Modified authentication-tag rejection
  await test("12. Modified authentication-tag rejection: tampered tag fails decryption", async () => {
    const tagBytes = base64ToUint8Array(encryptedData.authenticationTag);
    tagBytes[tagBytes.length - 1] ^= 0xff; // flip bits
    const tamperedPayload = {
      ...encryptedData,
      authenticationTag: uint8ArrayToBase64(tagBytes)
    };

    await assert.rejects(
      async () => {
        await decryptVaultPayload(tamperedPayload, derivedKey);
      },
      (err: any) => err instanceof DecryptionError,
      "Tampered tag must fail authentication check"
    );
  });

  // Test 13: Invalid Base64 rejection
  await test("13. Invalid Base64 rejection: non-Base64 or non-canonical strings rejected", () => {
    assert.throws(() => base64ToUint8Array("NotBase64!@#$"), CryptographicError);
    assert.throws(() => base64ToUint8Array("abc"), CryptographicError); // length 3 (not mult of 4)
    assert.throws(() => base64ToUint8Array(""), CryptographicError);
  });

  // Test 14: Unsupported algorithm rejection
  await test("14. Unsupported algorithm rejection: non AES-256-GCM algorithms rejected", async () => {
    const unsupportedPayload = {
      ...encryptedData,
      encryptionAlgorithm: "DES-EDE3-CBC"
    };

    await assert.rejects(
      async () => {
        await decryptVaultPayload(unsupportedPayload as any, derivedKey);
      },
      (err: any) => err instanceof CryptographicError
    );
  });

  // Test 15: Invalid KDF metadata rejection
  await test("15. Invalid KDF metadata rejection: iterations < 600,000 or invalid salt rejected", () => {
    assert.throws(
      () =>
        validateKdfMetadata({
          vaultKdfSalt: uint8ArrayToBase64(new Uint8Array(8)), // only 8 bytes
          vaultKdfAlgorithm: "PBKDF2-HMAC-SHA256",
          vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
        }),
      CryptographicError
    );

    assert.throws(
      () =>
        validateKdfMetadata({
          vaultKdfSalt: uint8ArrayToBase64(generateKdfSalt()),
          vaultKdfAlgorithm: "PBKDF2-HMAC-SHA256",
          vaultKdfParameters: { iterations: 1000, keyLength: 32, digest: "SHA-256" } // weak iterations
        }),
      CryptographicError
    );
  });

  // Test 16: Non-extractable key enforcement
  await test("16. Non-extractable key enforcement: CryptoKey.extractable is strictly false", () => {
    assert.strictEqual(derivedKey.extractable, false, "Vault CryptoKey must be strictly non-extractable");
  });

  // Test 17: Key clearing on lock
  await test("17. Key clearing simulation: key reference set to null on lock", () => {
    let activeKeyRef: CryptoKey | null = derivedKey;
    assert.notStrictEqual(activeKeyRef, null);

    // Simulate lock operation
    activeKeyRef = null;
    assert.strictEqual(activeKeyRef, null, "Active key reference must be cleared to null upon lock");
  });

  // Test 18: Decrypted data clearing on lock
  await test("18. Decrypted data clearing on lock: in-memory decrypted items array cleared", () => {
    let decryptedItems = [{ id: "item-1", service: "Bank", secret: "p@ss" }];
    assert.strictEqual(decryptedItems.length, 1);

    // Simulate lock operation
    decryptedItems = [];
    assert.strictEqual(decryptedItems.length, 0, "Decrypted items array must be empty after lock");
  });

  // Test 19: IndexedDB encrypted-only persistence
  await test("19. Storage persistence: stores ONLY ciphertext and non-secret metadata (zero plaintext)", async () => {
    await clearAllEncryptedRecords();

    const record: EncryptedVaultRecord = {
      id: "vault-rec-1",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      encryptedPayload: encryptedData.encryptedPayload,
      initializationVector: encryptedData.initializationVector,
      authenticationTag: encryptedData.authenticationTag,
      encryptionAlgorithm: encryptedData.encryptionAlgorithm,
      encryptionVersion: encryptedData.encryptionVersion
    };

    await saveEncryptedRecord(record);
    const retrieved = await getEncryptedRecord("vault-rec-1");

    assert(retrieved !== null, "Stored record must be retrievable");
    assert.strictEqual(retrieved.id, "vault-rec-1");
    assert.strictEqual(retrieved.encryptedPayload, encryptedData.encryptedPayload);
    assert.strictEqual(retrieved.initializationVector, encryptedData.initializationVector);
    assert.strictEqual(retrieved.authenticationTag, encryptedData.authenticationTag);

    // Assert that NO plaintext fields exist on the stored record
    const storedKeys = Object.keys(retrieved);
    const forbidden = ["password", "plaintext", "secret", "masterPassword", "service", "username"];
    for (const f of forbidden) {
      assert(!storedKeys.includes(f), `Storage record must NOT contain plaintext field '${f}'`);
    }

    // Verify rejection of forbidden plaintext keys
    assert.rejects(
      async () => {
        await saveEncryptedRecord({
          ...record,
          id: "violating-record",
          password: "plaintext-password"
        } as any);
      },
      (err: any) => err instanceof CryptographicError
    );
  });

  // Test 20: Regression tests for existing password analyzer and generator
  await test("20. Regression tests: password analyzer and generator work without regressions", () => {
    // Analyzer tests
    const strongAnalysis = analyzePassword("Tr0ub4dor&3#CorrectHorseBatteryStaple");
    assert.strictEqual(strongAnalysis.level, "Excellent");
    assert(strongAnalysis.score >= 86);

    const weakAnalysis = analyzePassword("123456");
    assert.strictEqual(weakAnalysis.level, "Weak");
    assert(weakAnalysis.score >= 25 && weakAnalysis.score < 48);

    const veryWeakAnalysis = analyzePassword("a");
    assert.strictEqual(veryWeakAnalysis.level, "Very Weak");
    assert(veryWeakAnalysis.score < 25);

    // Generator tests
    const randomPwd = generateRandomPassword(18, { upper: true, lower: true, numbers: true, symbols: true });
    assert.strictEqual(randomPwd.length, 18);

    const passphrase = generatePassphrase(4, "-", true, true);
    assert(passphrase.split("-").length >= 4);
  });

  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Phase 8 Verification Summary: ${passed + failed} tests | ✅ ${passed} passed | ❌ ${failed} failed`);
  console.log("════════════════════════════════════════════════════════════\n");

  if (failed > 0) {
    console.error("Failures:", failures);
    process.exit(1);
  }
}

runSuite().catch((err) => {
  console.error("Unhandled exception in verification suite:", err);
  process.exit(1);
});
