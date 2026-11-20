/**
 * VaultGuard – Phase 6 Verification Test Suite
 * Tests: Device Management, Session Management, Token Revocation
 *
 * Runs an ephemeral HTTP server, exercises all Phase 6 endpoints,
 * performs DB-level assertions via Prisma, and cleans up after itself.
 *
 * Usage: tsx --env-file=.env src/verify-phase6.ts
 */

import http from "http";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import app from "./app.js";
import prisma from "./config/db.js";

// ─── Test Harness ─────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;
const failures: string[] = [];

function assert(condition: boolean, label: string): void {
  if (condition) {
    console.log(`  ✅ PASS [${passed + failed + 1}] ${label}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL [${passed + failed + 1}] ${label}`);
    failed++;
    failures.push(label);
  }
}

function assertEq<T>(actual: T, expected: T, label: string): void {
  assert(actual === expected, `${label} (got: ${JSON.stringify(actual)}, want: ${JSON.stringify(expected)})`);
}

// ─── HTTP Helper ──────────────────────────────────────────────────────────────

type FetchOptions = {
  method?: string;
  body?: unknown;
  headers?: Record<string, string>;
  cookie?: string;
};

type FetchResult = {
  status: number;
  data: any;
  headers: Record<string, string>;
  setCookieHeader: string | undefined;
};

async function req(
  port: number,
  path: string,
  opts: FetchOptions = {}
): Promise<FetchResult> {
  return new Promise((resolve, reject) => {
    const body = opts.body !== undefined ? JSON.stringify(opts.body) : undefined;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(opts.headers || {})
    };
    if (opts.cookie) headers["Cookie"] = opts.cookie;
    if (body) headers["Content-Length"] = Buffer.byteLength(body).toString();

    const reqOpts: http.RequestOptions = {
      hostname: "127.0.0.1",
      port,
      path,
      method: opts.method || "GET",
      headers
    };

    const r = http.request(reqOpts, (res) => {
      let raw = "";
      res.on("data", (chunk) => (raw += chunk));
      res.on("end", () => {
        let data: any = {};
        try { data = JSON.parse(raw); } catch { data = { raw }; }
        const resHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (typeof v === "string") resHeaders[k] = v;
          else if (Array.isArray(v)) resHeaders[k] = v[0];
        }
        const setCookieHeader = res.headers["set-cookie"]?.[0];
        resolve({ status: res.statusCode || 0, data, headers: resHeaders, setCookieHeader });
      });
    });

    r.on("error", reject);
    if (body) r.write(body);
    r.end();
  });
}

function extractCookieValue(setCookieHeader: string | undefined, name: string): string | null {
  if (!setCookieHeader) return null;
  const match = setCookieHeader.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

// ─── Test Data Setup ──────────────────────────────────────────────────────────

function uniqueEmail(): string {
  return `p6test_${crypto.randomBytes(6).toString("hex")}@vaultguard-test.local`;
}

const CSRF_HEADERS = {
  "X-VaultGuard-Request": "1",
  "Origin": "http://localhost:3000"
};

// ─── Main Test Runner ─────────────────────────────────────────────────────────

async function run(): Promise<void> {
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port;

  const cleanupUserIds: string[] = [];

  try {
    // ── SECTION 1: Registration + Basic Login ──────────────────────────────────
    console.log("\n── Section 1: Registration and Login ──");

    const email = uniqueEmail();
    const password = "P6-TestPassword-Secure!123";

    // Test 1: Register user
    const regRes = await req(port, "/api/auth/register", {
      method: "POST",
      body: { email, password }
    });
    assertEq(regRes.status, 201, "Register: returns 201");
    assert(regRes.data.success === true, "Register: success flag is true");

    // Retrieve user ID for cleanup
    const dbUser = await prisma.user.findUnique({ where: { emailNormalized: email.toLowerCase() } });
    if (dbUser) cleanupUserIds.push(dbUser.id);

    // Test 2: Login returns token + sessionId
    const loginRes = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email, password }
    });
    assertEq(loginRes.status, 200, "Login: returns 200");
    assert(typeof loginRes.data.data?.token === "string", "Login: response includes token");
    assert(typeof loginRes.data.data?.sessionId === "string", "Login: response includes sessionId");

    const accessToken1 = loginRes.data.data.token as string;
    const sessionId1 = loginRes.data.data.sessionId as string;

    // Test 3: Login sets HttpOnly refresh cookie
    const cookieHeader1 = loginRes.setCookieHeader;
    assert(typeof cookieHeader1 === "string", "Login: sets Set-Cookie header");
    assert(cookieHeader1?.includes("vg_refresh_token=") === true, "Login: cookie is named vg_refresh_token");
    assert(cookieHeader1?.includes("HttpOnly") === true, "Login: cookie is HttpOnly");
    assert(cookieHeader1?.includes("Path=/api/auth") === true, "Login: cookie path is /api/auth");

    const refreshToken1 = extractCookieValue(cookieHeader1, "vg_refresh_token");
    assert(refreshToken1 !== null, "Login: refresh token value extracted from cookie");

    // Test 4: Session created in database
    const dbSession1 = await prisma.session.findUnique({ where: { id: sessionId1 } });
    assert(dbSession1 !== null, "DB: Session record created after login");
    assert(dbSession1?.revokedAt === null, "DB: Session is not revoked initially");

    // Test 5: Device created in database
    const dbDevice1 = await prisma.device.findFirst({ where: { userId: dbUser!.id } });
    assert(dbDevice1 !== null, "DB: Device record created after login");
    assert(dbDevice1?.removedAt === null, "DB: Device is not removed initially");

    // ── SECTION 2: Login with Device Metadata ─────────────────────────────────
    console.log("\n── Section 2: Device Identifier and Name ──");

    const deviceId = `browser-${crypto.randomBytes(8).toString("hex")}`;
    const loginRes2 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email, password, deviceIdentifier: deviceId, deviceName: "Chrome on Windows" }
    });
    assertEq(loginRes2.status, 200, "Login with device: returns 200");
    const sessionId2 = loginRes2.data.data?.sessionId as string;
    const cookieHeader2 = loginRes2.setCookieHeader;
    const refreshToken2 = extractCookieValue(cookieHeader2, "vg_refresh_token");
    assert(typeof refreshToken2 === "string", "Login with device: refresh token issued");

    // Test 6: Named device stored in DB
    const dbDevice2 = await prisma.device.findFirst({ where: { userId: dbUser!.id, deviceIdentifier: deviceId } });
    assert(dbDevice2 !== null, "DB: Named device record created");
    assertEq(dbDevice2?.deviceName, "Chrome on Windows", "DB: Device name stored correctly");

    // ── SECTION 3: Access Token and requireAuth with Session Validation ────────
    console.log("\n── Section 3: Access Token and Session Validation ──");

    // Test 7: /api/auth/me succeeds with valid session token
    const meRes = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${accessToken1}` }
    });
    assertEq(meRes.status, 200, "GET /me: returns 200 with valid session token");
    assertEq(meRes.data.data?.email, email, "GET /me: returns correct email");

    // Test 8: /api/auth/me fails with no token
    const meNoAuth = await req(port, "/api/auth/me");
    assertEq(meNoAuth.status, 401, "GET /me: returns 401 without token");

    // Test 9: /api/auth/me fails with tampered token
    const tamperedToken = accessToken1.slice(0, -5) + "XXXXX";
    const meTampered = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${tamperedToken}` }
    });
    assertEq(meTampered.status, 401, "GET /me: returns 401 with tampered token");

    // Test 10: Revoke session, then access token should be rejected
    await prisma.session.update({ where: { id: sessionId1 }, data: { revokedAt: new Date() } });
    const meRevokedSession = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${accessToken1}` }
    });
    assertEq(meRevokedSession.status, 401, "GET /me: returns 401 after session revoked");

    // Restore session for further tests
    await prisma.session.update({ where: { id: sessionId1 }, data: { revokedAt: null } });

    // ── SECTION 4: Refresh Token Rotation ─────────────────────────────────────
    console.log("\n── Section 4: Refresh Token Rotation ──");

    // Test 11: Refresh without CSRF headers → 403
    const refreshNoCsrf = await req(port, "/api/auth/refresh", {
      method: "POST",
      cookie: `vg_refresh_token=${refreshToken2}`
    });
    assertEq(refreshNoCsrf.status, 403, "POST /refresh: returns 403 without CSRF headers");

    // Test 12: Refresh without cookie → 401
    const refreshNoCookie = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: CSRF_HEADERS
    });
    assertEq(refreshNoCookie.status, 401, "POST /refresh: returns 401 without cookie");

    // Test 13: Valid refresh → 200 with new tokens
    const refreshRes = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: CSRF_HEADERS,
      cookie: `vg_refresh_token=${refreshToken2}`
    });
    assertEq(refreshRes.status, 200, "POST /refresh: returns 200 with valid refresh token");
    assert(typeof refreshRes.data.data?.token === "string", "POST /refresh: new access token issued");
    const newCookieHeader = refreshRes.setCookieHeader;
    const refreshToken3 = extractCookieValue(newCookieHeader, "vg_refresh_token");
    assert(refreshToken3 !== null, "POST /refresh: new refresh token cookie set");
    assert(refreshToken3 !== refreshToken2, "POST /refresh: rotated token differs from old token");

    // Test 14: Old refresh token is consumed and cannot be reused
    const replayRes = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: CSRF_HEADERS,
      cookie: `vg_refresh_token=${refreshToken2}`
    });
    assertEq(replayRes.status, 401, "POST /refresh: replay of consumed token returns 401");

    // Test 15: After replay detection, session should be revoked
    const dbSession2After = await prisma.session.findUnique({ where: { id: sessionId2 } });
    assert(dbSession2After?.revokedAt !== null, "DB: Session revoked after replay attack detection");

    // Test 16: Old consumed refresh token is now rejected after session revocation
    const oldTokenAfterRevoke = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: CSRF_HEADERS,
      cookie: `vg_refresh_token=${refreshToken2}`
    });
    assertEq(oldTokenAfterRevoke.status, 401, "POST /refresh: further reuse of consumed token is rejected");

    // ── SECTION 5: Device Listing ─────────────────────────────────────────────
    console.log("\n── Section 5: Device Listing ──");

    // Create a fresh login for device list tests
    const loginRes3 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email, password, deviceIdentifier: "device-A", deviceName: "Device A" }
    });
    const accessToken3 = loginRes3.data.data?.token as string;
    const sessionId3 = loginRes3.data.data?.sessionId as string;
    const cookieHeader3 = loginRes3.setCookieHeader;
    const refreshToken4 = extractCookieValue(cookieHeader3, "vg_refresh_token");

    // Test 17: GET /api/devices returns 200
    const devicesRes = await req(port, "/api/devices", {
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(devicesRes.status, 200, "GET /devices: returns 200");
    assert(Array.isArray(devicesRes.data.data), "GET /devices: data is an array");

    // Test 18: At least one device in list
    assert(devicesRes.data.data.length >= 1, "GET /devices: at least one device listed");

    // Test 19: Current device has isCurrent: true
    const currentDevice = devicesRes.data.data.find((d: any) => d.isCurrent === true);
    assert(currentDevice !== undefined, "GET /devices: current device is marked with isCurrent=true");

    // Test 20: Devices do not expose removed devices
    const removedDeviceInList = devicesRes.data.data.find((d: any) => d.removedAt !== undefined);
    assert(removedDeviceInList === undefined, "GET /devices: removedAt is not exposed in device list");

    // Test 21: GET /api/devices without auth → 401
    const devicesNoAuth = await req(port, "/api/devices");
    assertEq(devicesNoAuth.status, 401, "GET /devices: returns 401 without auth");

    // ── SECTION 6: Device Removal ─────────────────────────────────────────────
    console.log("\n── Section 6: Device Removal ──");

    // Login with a second device so we can remove it
    const loginRes4 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email, password, deviceIdentifier: "device-B", deviceName: "Device B" }
    });
    const sessionId4 = loginRes4.data.data?.sessionId as string;

    // Find device B's ID
    const dbDeviceB = await prisma.device.findFirst({
      where: { userId: dbUser!.id, deviceIdentifier: "device-B" }
    });
    const deviceBId = dbDeviceB!.id;

    // Test 22: Cannot remove own current device
    const accessToken4 = loginRes4.data.data?.token as string;
    const devicesOwnRes = await req(port, `/api/devices/${deviceBId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken4}` }
    });
    assertEq(devicesOwnRes.status, 409, "DELETE /devices/:id: returns 409 when removing current device");

    // Test 23: Can remove another device from the same account (using device-A's token)
    const removeRes = await req(port, `/api/devices/${deviceBId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(removeRes.status, 200, "DELETE /devices/:id: returns 200 when removing other device");
    assert(removeRes.data.success === true, "DELETE /devices/:id: success is true");

    // Test 24: DB: Device B is soft-deleted (removedAt is set)
    const dbDeviceBAfter = await prisma.device.findUnique({ where: { id: deviceBId } });
    assert(dbDeviceBAfter?.removedAt !== null, "DB: Removed device has removedAt set");

    // Test 25: DB: Session for device B is revoked
    const dbSession4After = await prisma.session.findUnique({ where: { id: sessionId4 } });
    assert(dbSession4After?.revokedAt !== null, "DB: Session for removed device is revoked");

    // Test 26: Access token for device B session is now rejected
    const meDeviceBRevoked = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${accessToken4}` }
    });
    assertEq(meDeviceBRevoked.status, 401, "GET /me: returns 401 after device removal revokes session");

    // Test 27: Device B does not appear in device list
    const devicesAfterRemove = await req(port, "/api/devices", {
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    const deviceBInList = devicesAfterRemove.data.data?.find((d: any) => d.id === deviceBId);
    assert(deviceBInList === undefined, "GET /devices: removed device no longer appears in list");

    // Test 28: Invalid device UUID param → 400
    const invalidUuid = await req(port, "/api/devices/not-a-uuid", {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(invalidUuid.status, 400, "DELETE /devices/not-a-uuid: returns 400 for invalid UUID");

    // Test 29: Remove non-existent device → 404
    const fakeId = crypto.randomUUID();
    const fakeDeviceRes = await req(port, `/api/devices/${fakeId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(fakeDeviceRes.status, 404, "DELETE /devices/:id: returns 404 for non-existent device");

    // Test 30: Remove already-removed device → 409
    const alreadyRemovedRes = await req(port, `/api/devices/${deviceBId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(alreadyRemovedRes.status, 409, "DELETE /devices/:id: returns 409 for already-removed device");

    // ── SECTION 7: Logout ──────────────────────────────────────────────────────
    console.log("\n── Section 7: Logout ──");

    // Test 31: Logout without CSRF headers → 403
    const logoutNoCsrf = await req(port, "/api/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(logoutNoCsrf.status, 403, "POST /logout: returns 403 without CSRF headers");

    // Test 32: Logout without auth → 401
    const logoutNoAuth = await req(port, "/api/auth/logout", {
      method: "POST",
      headers: CSRF_HEADERS
    });
    assertEq(logoutNoAuth.status, 401, "POST /logout: returns 401 without Bearer token");

    // Test 33: Valid logout → 200
    const logoutRes = await req(port, "/api/auth/logout", {
      method: "POST",
      headers: { ...CSRF_HEADERS, Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(logoutRes.status, 200, "POST /logout: returns 200 on successful logout");
    assert(logoutRes.data.success === true, "POST /logout: success is true");

    // Test 34: Cookie is cleared on logout
    const logoutCookieHeader = logoutRes.setCookieHeader;
    assert(
      logoutCookieHeader !== undefined && logoutCookieHeader.includes("vg_refresh_token=;"),
      "POST /logout: refresh token cookie cleared"
    );

    // Test 35: Session is revoked in DB after logout
    const dbSession3After = await prisma.session.findUnique({ where: { id: sessionId3 } });
    assert(dbSession3After?.revokedAt !== null, "DB: Session revoked in DB after logout");

    // Test 36: Access token is rejected after logout (session revoked)
    const meAfterLogout = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${accessToken3}` }
    });
    assertEq(meAfterLogout.status, 401, "GET /me: returns 401 after logout revokes session");

    // Test 37: Refresh token is unusable after logout
    const refreshAfterLogout = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: CSRF_HEADERS,
      cookie: `vg_refresh_token=${refreshToken4}`
    });
    assertEq(refreshAfterLogout.status, 401, "POST /refresh: returns 401 after logout");

    // ── SECTION 8: Vault Access Regression ────────────────────────────────────
    console.log("\n── Section 8: Vault Access Regression ──");

    // Fresh login for vault tests
    const loginRes5 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email, password, deviceIdentifier: "vault-test-device" }
    });
    const vaultToken = loginRes5.data.data?.token as string;

    // Test 38: Vault access works with valid Phase-6 session token
    const vaultList = await req(port, "/api/vault", {
      headers: { Authorization: `Bearer ${vaultToken}` }
    });
    assertEq(vaultList.status, 200, "GET /vault: returns 200 with Phase-6 session token");

    // Test 39: Vault create works
    const iv = Buffer.alloc(12).toString("base64");
    const tag = Buffer.alloc(16).toString("base64");
    const payload = Buffer.from("encrypted-data-phase6-test").toString("base64");
    const createVault = await req(port, "/api/vault", {
      method: "POST",
      headers: { Authorization: `Bearer ${vaultToken}` },
      body: {
        encryptedPayload: payload,
        initializationVector: iv,
        authenticationTag: tag,
        encryptionAlgorithm: "AES-256-GCM",
        encryptionVersion: 1
      }
    });
    assertEq(createVault.status, 201, "POST /vault: returns 201 with Phase-6 session token");
    const vaultItemId = createVault.data.data?.id as string;

    // Test 40: Vault delete works
    const deleteVault = await req(port, `/api/vault/${vaultItemId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${vaultToken}` }
    });
    assertEq(deleteVault.status, 200, "DELETE /vault/:id: returns 200 with Phase-6 session token");

    // ── SECTION 9: Session Expiry ──────────────────────────────────────────────
    console.log("\n── Section 9: Session Expiry ──");

    // Create a session that is immediately expired
    const loginRes6 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email, password, deviceIdentifier: "expire-test-device" }
    });
    const expiredToken = loginRes6.data.data?.token as string;
    const expiredSessionId = loginRes6.data.data?.sessionId as string;

    // Force-expire the session
    await prisma.session.update({
      where: { id: expiredSessionId },
      data: { expiresAt: new Date(Date.now() - 1000) }
    });

    // Test 41: Expired session is rejected by requireAuth
    const meExpired = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${expiredToken}` }
    });
    assertEq(meExpired.status, 401, "GET /me: returns 401 when session is expired");

    // ── SECTION 10: Health and Root Endpoints (regression) ────────────────────
    console.log("\n── Section 10: Regression – Root and Health Endpoints ──");

    // Test 42: Root endpoint
    const rootRes = await req(port, "/");
    assertEq(rootRes.status, 200, "GET /: returns 200 (regression)");

    // Test 43: Health endpoint
    const healthRes = await req(port, "/api/health");
    assertEq(healthRes.status, 200, "GET /api/health: returns 200 (regression)");

    // ── SECTION 11: Phase 6.1 – Concurrency & Edge Case Hardening ──────────────
    console.log("\n── Section 11: Phase 6.1 Security Hardening Tests ──");

    // Test A: Concurrent refresh
    const emailA = uniqueEmail();
    const passA = "P61-ConcurPass-!1234";
    await req(port, "/api/auth/register", { method: "POST", body: { email: emailA, password: passA } });
    const userA_record = await prisma.user.findUnique({ where: { emailNormalized: emailA.toLowerCase() } });
    if (userA_record) cleanupUserIds.push(userA_record.id);

    const loginResA = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailA, password: passA, deviceIdentifier: "concur-device" }
    });
    const rfTokenA = extractCookieValue(loginResA.setCookieHeader, "vg_refresh_token");
    const sessIdA = loginResA.data.data?.sessionId;

    // Send two simultaneous refresh requests using the exact same refresh token
    const [cRes1, cRes2] = await Promise.all([
      req(port, "/api/auth/refresh", { method: "POST", headers: CSRF_HEADERS, cookie: `vg_refresh_token=${rfTokenA}` }),
      req(port, "/api/auth/refresh", { method: "POST", headers: CSRF_HEADERS, cookie: `vg_refresh_token=${rfTokenA}` })
    ]);

    // Test 63: Exactly one of the concurrent requests succeeds
    const has200 = (cRes1.status === 200 && cRes2.status !== 200) || (cRes1.status !== 200 && cRes2.status === 200);
    assert(has200, "Test A: Exactly one concurrent refresh request succeeds with HTTP 200");

    // Test 64: The losing concurrent request is rejected safely
    const winningRes = cRes1.status === 200 ? cRes1 : cRes2;
    const losingRes = cRes1.status === 200 ? cRes2 : cRes1;
    assert(
      losingRes.status === 409 || losingRes.status === 401,
      `Test A: Losing request rejected safely with non-200 status (got: ${losingRes.status})`
    );

    // Test 65: Only one active unconsumed refresh token exists for the session
    const activeTokensCount = await prisma.refreshToken.count({
      where: { sessionId: sessIdA, consumedAt: null, revokedAt: null }
    });
    assertEq(activeTokensCount, 1, "Test A: Exactly one active unconsumed refresh token exists (no branching)");

    // Test 66: The winning request's new access token is valid and session is active
    const winningAccessToken = winningRes.data.data?.token;
    const meWithWinningToken = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${winningAccessToken}` }
    });
    assertEq(meWithWinningToken.status, 200, "Test A: Winning access token is valid and session is active");

    // Test 67: Session is not revoked by the concurrent race
    const sessAfterConcur = await prisma.session.findUnique({ where: { id: sessIdA } });
    assert(sessAfterConcur?.revokedAt === null, "Test A: Session was not revoked by the concurrent race");

    // Test B: Cross-user device deletion
    const emailU1 = uniqueEmail();
    const emailU2 = uniqueEmail();
    await req(port, "/api/auth/register", { method: "POST", body: { email: emailU1, password: passA } });
    await req(port, "/api/auth/register", { method: "POST", body: { email: emailU2, password: passA } });
    const u1Record = await prisma.user.findUnique({ where: { emailNormalized: emailU1.toLowerCase() } });
    const u2Record = await prisma.user.findUnique({ where: { emailNormalized: emailU2.toLowerCase() } });
    if (u1Record) cleanupUserIds.push(u1Record.id);
    if (u2Record) cleanupUserIds.push(u2Record.id);

    const loginU1 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailU1, password: passA, deviceIdentifier: "u1-device" }
    });
    const loginU2 = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailU2, password: passA, deviceIdentifier: "u2-device" }
    });
    const u1Token = loginU1.data.data?.token;
    const u2SessionId = loginU2.data.data?.sessionId;
    const u2Device = await prisma.device.findFirst({ where: { userId: u2Record!.id } });

    // Test 68: User 1 attempts to delete User 2's device -> 404
    const crossDelRes = await req(port, `/api/devices/${u2Device!.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${u1Token}` }
    });
    assertEq(crossDelRes.status, 404, "Test B: Cross-user device deletion returns 404 Not Found");

    // Test 69: User 2's device remains active and not soft-deleted
    const u2DeviceAfter = await prisma.device.findUnique({ where: { id: u2Device!.id } });
    assert(u2DeviceAfter?.removedAt === null, "Test B: User 2 device was not removed");

    // Test 70: User 2's session remains active and not revoked
    const u2SessAfter = await prisma.session.findUnique({ where: { id: u2SessionId } });
    assert(u2SessAfter?.revokedAt === null, "Test B: User 2 session was not revoked");

    // Test C: CSRF Origin mismatch
    const evilHeaders = {
      "X-VaultGuard-Request": "1",
      "Origin": "http://evil-malicious-site.com"
    };
    const rfU1 = extractCookieValue(loginU1.setCookieHeader, "vg_refresh_token");

    // Test 71: Refresh with unauthorized Origin returns 403
    const csrfRefreshRes = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: evilHeaders,
      cookie: `vg_refresh_token=${rfU1}`
    });
    assertEq(csrfRefreshRes.status, 403, "Test C: Refresh with untrusted Origin returns 403 Forbidden");

    // Test 72: Logout with unauthorized Origin returns 403
    const csrfLogoutRes = await req(port, "/api/auth/logout", {
      method: "POST",
      headers: { ...evilHeaders, Authorization: `Bearer ${u1Token}` }
    });
    assertEq(csrfLogoutRes.status, 403, "Test C: Logout with untrusted Origin returns 403 Forbidden");

    // Test 73: User 1 session remains active after rejected CSRF attempts
    const u1SessionId = loginU1.data.data?.sessionId;
    const u1SessAfterCsrf = await prisma.session.findUnique({ where: { id: u1SessionId } });
    assert(u1SessAfterCsrf?.revokedAt === null, "Test C: Session remains active after rejected CSRF attempts");

    // Test D: Refresh-token hash verification
    const capturedRfToken = rfU1!;
    const expectedHash = crypto.createHash("sha256").update(capturedRfToken).digest("hex");

    // Test 74: Database stores tokenHash equal to computed SHA-256
    const dbRfRecord = await prisma.refreshToken.findUnique({ where: { tokenHash: expectedHash } });
    assert(dbRfRecord !== null, "Test D: DB record found using computed SHA-256 hash");
    assertEq(dbRfRecord?.tokenHash, expectedHash, "Test D: Stored tokenHash matches computed SHA-256 hex");

    // Test 75: Plaintext refresh token is NOT stored anywhere in the database record
    const rawRows = await prisma.$queryRaw<any[]>`SELECT * FROM refresh_tokens WHERE tokenHash = ${expectedHash}`;
    const rawStr = JSON.stringify(rawRows[0]);
    assert(!rawStr.includes(capturedRfToken), "Test D: Plaintext token is never stored in database");

    // Test E: Unknown random refresh token
    const randomToken = crypto.randomBytes(32).toString("hex");

    // Test 76: Random unknown refresh token returns 401
    const randomRefreshRes = await req(port, "/api/auth/refresh", {
      method: "POST",
      headers: CSRF_HEADERS,
      cookie: `vg_refresh_token=${randomToken}`
    });
    assertEq(randomRefreshRes.status, 401, "Test E: Unknown random refresh token returns 401 Unauthorized");

    // Test 77: Existing user session remains active and unrevoked
    const u1SessAfterRandom = await prisma.session.findUnique({ where: { id: u1SessionId } });
    assert(u1SessAfterRandom?.revokedAt === null, "Test E: User 1 session remains active and unrevoked");

    // Test F: SEC-P6-02 Verification (Tokens without sid or malformed sid rejected)
    const secret = process.env.JWT_SECRET!;

    // Test 78: Token without sid claim is rejected with 401
    const tokenWithoutSid = jwt.sign(
      { sub: u1Record!.id, email: u1Record!.email },
      secret,
      { algorithm: "HS256", expiresIn: "15m" }
    );
    const meWithoutSid = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${tokenWithoutSid}` }
    });
    assertEq(meWithoutSid.status, 401, "SEC-P6-02: Access token without sid is rejected with 401");

    // Test 79: Token with malformed (non-UUID) sid is rejected with 401
    const tokenMalformedSid = jwt.sign(
      { sub: u1Record!.id, email: u1Record!.email, sid: "not-a-valid-uuid-format" },
      secret,
      { algorithm: "HS256", expiresIn: "15m" }
    );
    const meMalformedSid = await req(port, "/api/auth/me", {
      headers: { Authorization: `Bearer ${tokenMalformedSid}` }
    });
    assertEq(meMalformedSid.status, 401, "SEC-P6-02: Access token with malformed sid is rejected with 401");

  } finally {
    // ── Cleanup ───────────────────────────────────────────────────────────────
    console.log("\n── Cleanup ──");
    for (const userId of cleanupUserIds) {
      // Cascading deletes: vaultItems, devices, sessions, refreshTokens all cascade from User
      await prisma.user.delete({ where: { id: userId } }).catch(() => {});
    }
    console.log(`  🧹 Cleaned up ${cleanupUserIds.length} test user(s)`);

    await prisma.$disconnect();
    server.close();

    // ── Summary ───────────────────────────────────────────────────────────────
    console.log(`\n${"═".repeat(60)}`);
    console.log(`Phase 6 Results: ${passed + failed} tests | ✅ ${passed} passed | ❌ ${failed} failed`);
    if (failures.length > 0) {
      console.error("\nFailed tests:");
      failures.forEach((f) => console.error(`  • ${f}`));
    }
    console.log("═".repeat(60));

    if (failed > 0) process.exit(1);
  }
}

run().catch((err) => {
  console.error("\n💥 Unexpected error:", err);
  process.exit(1);
});
