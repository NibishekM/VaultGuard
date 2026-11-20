/**
 * VaultGuard – Server Verification Canary API Verification Suite (Phase 9.1)
 *
 * Verifies backend implementation of master-password verification canary:
 * 1. Authentication enforcement (401 for unauthenticated GET / POST)
 * 2. Input validation (Base64 encoding, 12-byte IV, 16-byte tag, max payload size)
 * 3. Forbidden plaintext key rejection (400 Bad Request)
 * 4. Create-once semantics (409 Conflict on overwrite attempt)
 * 5. User ownership and cross-user isolation
 * 6. Legacy vault protection (rejects unapproved canary creation when vault has items)
 * 7. Legacy migration approval (permits canary creation when isLegacyMigration: true)
 *
 * Usage: tsx --env-file=.env src/verify-verification.ts
 */

import http from "node:http";
import assert from "node:assert";
import app from "./app.js";
import prisma from "./config/db.js";
import { generateAccessToken } from "./utils/jwt.js";
import { hashPassword } from "./utils/password.js";

let passedCount = 0;
let failedCount = 0;

function logTest(num: number, desc: string, passed: boolean, detail?: string) {
  if (passed) {
    passedCount++;
    console.log(`  ✅ PASS [${num}] ${desc}${detail ? ` (${detail})` : ""}`);
  } else {
    failedCount++;
    console.error(`  ❌ FAIL [${num}] ${desc}${detail ? ` (${detail})` : ""}`);
  }
}

async function request(
  baseUrl: string,
  method: string,
  endpoint: string,
  token?: string,
  body?: unknown
) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-VaultGuard-Request": "1"
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${baseUrl}${endpoint}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined
  });

  let json: any = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }

  return { status: res.status, headers: res.headers, body: json };
}

async function run() {
  console.log("================================================================================");
  console.log("VaultGuard Phase 9.1: Server Verification Canary Backend Verification Suite");
  console.log("================================================================================\n");

  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as any).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  const timestamp = Date.now();
  const user1Email = `verif1_${timestamp}@vaultguard.test`;
  const user2Email = `verif2_${timestamp}@vaultguard.test`;
  const user3Email = `verif3_legacy_${timestamp}@vaultguard.test`;

  let user1Token = "";
  let user1Id = "";
  let user2Token = "";
  let user2Id = "";
  let user3Token = "";
  let user3Id = "";

  try {
    // Setup User 1 & 2
    const passwordHash = await hashPassword("ValidAccountPwd123!");

    const u1 = await prisma.user.create({
      data: {
        email: user1Email,
        emailNormalized: user1Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: "c2FsdDFzYWx0MXNhbHQx",
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    user1Id = u1.id;
    const d1 = await prisma.device.create({
      data: { userId: user1Id, deviceIdentifier: `dev1_${timestamp}`, deviceName: "TestDevice" }
    });
    const s1 = await prisma.session.create({
      data: { userId: user1Id, deviceId: d1.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    user1Token = generateAccessToken({ sub: user1Id, email: user1Email, sid: s1.id });

    const u2 = await prisma.user.create({
      data: {
        email: user2Email,
        emailNormalized: user2Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: "c2FsdDJzYWx0MnNhbHQy",
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    user2Id = u2.id;
    const d2 = await prisma.device.create({
      data: { userId: user2Id, deviceIdentifier: `dev2_${timestamp}`, deviceName: "TestDevice2" }
    });
    const s2 = await prisma.session.create({
      data: { userId: user2Id, deviceId: d2.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    user2Token = generateAccessToken({ sub: user2Id, email: user2Email, sid: s2.id });

    // 1. Authentication enforcement
    const unauthGet = await request(baseUrl, "GET", "/api/vault/verification");
    logTest(1, "GET /api/vault/verification without JWT returns 401 Unauthorized", unauthGet.status === 401);

    const unauthPost = await request(baseUrl, "POST", "/api/vault/verification", undefined, {
      encryptedPayload: "dGVzdA==",
      initializationVector: "MTIzNDU2Nzg5MDEy",
      authenticationTag: "MTIzNDU2Nzg5MDEyMzQ1Ng=="
    });
    logTest(2, "POST /api/vault/verification without JWT returns 401 Unauthorized", unauthPost.status === 401);

    // 2. Initial state for fresh user
    const freshGet = await request(baseUrl, "GET", "/api/vault/verification", user1Token);
    logTest(
      3,
      "Fresh user GET /api/vault/verification returns hasVerification: false, hasItems: false",
      freshGet.status === 200 &&
        freshGet.body?.data?.hasVerification === false &&
        freshGet.body?.data?.hasItems === false &&
        freshGet.body?.data?.verification === null
    );

    // 3. Validation: IV length must be exactly 12 bytes
    const badIv = await request(baseUrl, "POST", "/api/vault/verification", user1Token, {
      encryptedPayload: "dGVzdA==",
      initializationVector: Buffer.from("shortIV").toString("base64"),
      authenticationTag: "MTIzNDU2Nzg5MDEyMzQ1Ng=="
    });
    logTest(4, "POST /api/vault/verification with IV length != 12 bytes returns 400 Bad Request", badIv.status === 400);

    // 4. Validation: Tag length must be exactly 16 bytes
    const badTag = await request(baseUrl, "POST", "/api/vault/verification", user1Token, {
      encryptedPayload: "dGVzdA==",
      initializationVector: "MTIzNDU2Nzg5MDEy",
      authenticationTag: Buffer.from("shortTag").toString("base64")
    });
    logTest(5, "POST /api/vault/verification with tag length != 16 bytes returns 400 Bad Request", badTag.status === 400);

    // 5. Validation: Forbidden plaintext keys rejected
    const forbiddenKey = await request(baseUrl, "POST", "/api/vault/verification", user1Token, {
      encryptedPayload: "dGVzdA==",
      initializationVector: "MTIzNDU2Nzg5MDEy",
      authenticationTag: "MTIzNDU2Nzg5MDEyMzQ1Ng==",
      masterPassword: "leak"
    });
    logTest(6, "POST /api/vault/verification containing forbidden plaintext key returns 400 Bad Request", forbiddenKey.status === 400);

    // 6. Valid creation returns 201 Created
    const validCanary = {
      encryptedPayload: Buffer.from("EncryptedCanaryPayload").toString("base64"),
      initializationVector: Buffer.from("123456789012").toString("base64"),
      authenticationTag: Buffer.from("1234567890123456").toString("base64")
    };
    const createdRes = await request(baseUrl, "POST", "/api/vault/verification", user1Token, validCanary);
    logTest(7, "Valid POST /api/vault/verification returns 201 Created", createdRes.status === 201 && createdRes.body?.success === true);

    // 7. GET /api/vault/verification now returns populated record
    const populatedGet = await request(baseUrl, "GET", "/api/vault/verification", user1Token);
    logTest(
      8,
      "GET /api/vault/verification returns hasVerification: true with Base64 fields",
      populatedGet.status === 200 &&
        populatedGet.body?.data?.hasVerification === true &&
        populatedGet.body?.data?.verification?.encryptedPayload === validCanary.encryptedPayload
    );

    // 8. Create-once enforcement: second creation rejected with 409 Conflict
    const duplicateRes = await request(baseUrl, "POST", "/api/vault/verification", user1Token, validCanary);
    logTest(9, "Subsequent POST /api/vault/verification returns 409 Conflict (cannot overwrite)", duplicateRes.status === 409);

    // 9. User isolation: User 2's verification is still empty
    const user2Get = await request(baseUrl, "GET", "/api/vault/verification", user2Token);
    logTest(
      10,
      "User isolation: User 2 returns hasVerification: false (completely isolated from User 1)",
      user2Get.status === 200 && user2Get.body?.data?.hasVerification === false
    );

    // 10. Legacy vault protection: User 3 creates vault item first
    const u3 = await prisma.user.create({
      data: {
        email: user3Email,
        emailNormalized: user3Email.toLowerCase(),
        passwordHash,
        vaultKdfSalt: "c2FsdDNzYWx0M3NhbHQz",
        vaultKdfParameters: { iterations: 600000, keyLength: 32, digest: "SHA-256" }
      }
    });
    user3Id = u3.id;
    const d3 = await prisma.device.create({
      data: { userId: user3Id, deviceIdentifier: `dev3_${timestamp}`, deviceName: "TestDevice3" }
    });
    const s3 = await prisma.session.create({
      data: { userId: user3Id, deviceId: d3.id, expiresAt: new Date(Date.now() + 3600000) }
    });
    user3Token = generateAccessToken({ sub: user3Id, email: user3Email, sid: s3.id });

    // User 3 creates vault item
    await request(baseUrl, "POST", "/api/vault", user3Token, {
      encryptedPayload: Buffer.from("item-payload").toString("base64"),
      initializationVector: Buffer.from("123456789012").toString("base64"),
      authenticationTag: Buffer.from("1234567890123456").toString("base64")
    });

    // User 3 attempts standard canary creation on populated vault (without isLegacyMigration) -> rejected!
    const unapprovedLegacy = await request(baseUrl, "POST", "/api/vault/verification", user3Token, validCanary);
    logTest(
      11,
      "POST /api/vault/verification on vault with existing items without isLegacyMigration rejected with 409 Conflict",
      unapprovedLegacy.status === 409
    );

    // User 3 with isLegacyMigration: true -> approved!
    const approvedLegacy = await request(baseUrl, "POST", "/api/vault/verification", user3Token, {
      ...validCanary,
      isLegacyMigration: true
    });
    logTest(
      12,
      "POST /api/vault/verification with isLegacyMigration: true returns 201 Created",
      approvedLegacy.status === 201 && approvedLegacy.body?.success === true
    );

  } finally {
    server.close();
    // Cleanup test users
    await prisma.vaultVerification.deleteMany({
      where: {
        user: { email: { in: [user1Email, user2Email, user3Email] } }
      }
    }).catch(() => {});
    await prisma.vaultItem.deleteMany({
      where: {
        user: { email: { in: [user1Email, user2Email, user3Email] } }
      }
    }).catch(() => {});
    await prisma.session.deleteMany({
      where: {
        user: { email: { in: [user1Email, user2Email, user3Email] } }
      }
    }).catch(() => {});
    await prisma.device.deleteMany({
      where: {
        user: { email: { in: [user1Email, user2Email, user3Email] } }
      }
    }).catch(() => {});
    await prisma.user.deleteMany({
      where: {
        email: { in: [user1Email, user2Email, user3Email] }
      }
    }).catch(() => {});
  }

  console.log("\n════════════════════════════════════════════════════════════");
  console.log(`Verification API Suite: ${passedCount + failedCount} tests | ✅ ${passedCount} passed | ❌ ${failedCount} failed`);
  console.log("════════════════════════════════════════════════════════════\n");

  if (failedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

run().catch((err) => {
  console.error("Test failed with exception:", err);
  process.exit(1);
});
