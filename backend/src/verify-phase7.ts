/**
 * VaultGuard – Phase 7 Verification Test Suite
 * Tests: Encrypted Vault Synchronization Engine
 *
 * Runs an ephemeral HTTP server, exercises all Phase 7 synchronization endpoints,
 * validates concurrency, cursor pagination, tombstones, and regression scenarios,
 * performs DB-level assertions via Prisma, and cleans up test records safely.
 *
 * Usage: tsx --env-file=.env src/verify-phase7.ts
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
  assert(
    actual === expected,
    `${label} (got: ${JSON.stringify(actual)}, want: ${JSON.stringify(expected)})`
  );
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
        try {
          data = JSON.parse(raw);
        } catch {
          data = { raw };
        }
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

function uniqueEmail(): string {
  return `p7test_${crypto.randomBytes(6).toString("hex")}@vaultguard-test.local`;
}

function makeEncryptedPayload(text = "secret-item-data") {
  return {
    encryptedPayload: Buffer.from(text).toString("base64"),
    initializationVector: Buffer.alloc(12, 1).toString("base64"),
    authenticationTag: Buffer.alloc(16, 2).toString("base64"),
    encryptionAlgorithm: "AES-256-GCM" as const,
    encryptionVersion: 1
  };
}

// ─── Main Test Runner ─────────────────────────────────────────────────────────

async function run(): Promise<void> {
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as any).port;

  const cleanupUserIds: string[] = [];

  try {
    // ── SECTION A: Synchronization Version Assignment (Tests 1–5) ─────────────
    console.log("\n── Section A: Synchronization Version Assignment ──");

    const emailA = uniqueEmail();
    const passA = "P7-SyncMasterPassword!123";

    await req(port, "/api/auth/register", { method: "POST", body: { email: emailA, password: passA } });
    const userA_db = await prisma.user.findUnique({ where: { emailNormalized: emailA.toLowerCase() } });
    if (userA_db) cleanupUserIds.push(userA_db.id);

    const loginResA = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailA, password: passA, deviceIdentifier: "laptop-dev" }
    });
    const tokenA = loginResA.data.data?.token as string;
    const authHeadersA = { Authorization: `Bearer ${tokenA}` };

    // Test 1: Create vault item assigns syncVersion === 1
    const createRes1 = await req(port, "/api/vault", {
      method: "POST",
      headers: authHeadersA,
      body: makeEncryptedPayload("item-1")
    });
    assertEq(createRes1.status, 201, "Create item returns 201 Created");
    assertEq(createRes1.data.data?.syncVersion, 1, "Created item assigned syncVersion 1");
    const item1Id = createRes1.data.data?.id;

    const userDbAfterCreate = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    assertEq(userDbAfterCreate?.syncVersion, 1, "User syncVersion advanced to 1 in database");

    // Test 2: Update item increments syncVersion to 2
    const updateRes1 = await req(port, `/api/vault/${item1Id}`, {
      method: "PUT",
      headers: authHeadersA,
      body: { ...makeEncryptedPayload("item-1-updated"), expectedRevision: 1 }
    });
    assertEq(updateRes1.status, 200, "Update item returns 200 OK");
    assertEq(updateRes1.data.data?.syncVersion, 2, "Updated item assigned syncVersion 2");
    assertEq(updateRes1.data.data?.revision, 2, "Updated item revision is 2");

    const userDbAfterUpdate = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    assertEq(userDbAfterUpdate?.syncVersion, 2, "User syncVersion advanced to 2 in database");

    // Test 3: Delete item increments syncVersion to 3
    const deleteRes1 = await req(port, `/api/vault/${item1Id}`, {
      method: "DELETE",
      headers: authHeadersA
    });
    assertEq(deleteRes1.status, 200, "Delete item returns 200 OK");
    assertEq(deleteRes1.data.data?.syncVersion, 3, "Deleted item assigned syncVersion 3");

    const userDbAfterDelete = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    assertEq(userDbAfterDelete?.syncVersion, 3, "User syncVersion advanced to 3 in database");

    // Test 4: Verify versions are strictly ordered and unique per user
    const dbItemsUserA = await prisma.vaultItem.findMany({
      where: { userId: userA_db!.id },
      select: { syncVersion: true, revision: true }
    });
    const versionsA = dbItemsUserA.map((i) => i.syncVersion);
    const uniqueVersions = new Set(versionsA);
    assertEq(uniqueVersions.size, versionsA.length, "All sync versions for user are unique");

    // Test 5: Failed update (revision mismatch) does NOT consume a committed version
    // First create item 2
    const createRes2 = await req(port, "/api/vault", {
      method: "POST",
      headers: authHeadersA,
      body: makeEncryptedPayload("item-2")
    });
    const item2Id = createRes2.data.data?.id;
    assertEq(createRes2.data.data?.syncVersion, 4, "Item 2 assigned syncVersion 4");

    const userBeforeFailedUpdate = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    const versionBeforeFailed = userBeforeFailedUpdate!.syncVersion;

    // Attempt update with mismatched expectedRevision (expecting 99 instead of 1)
    const failedUpdateRes = await req(port, `/api/vault/${item2Id}`, {
      method: "PUT",
      headers: authHeadersA,
      body: { ...makeEncryptedPayload("item-2-stale"), expectedRevision: 99 }
    });
    assertEq(failedUpdateRes.status, 409, "Mismatched revision update returns 409 Conflict");

    const userAfterFailedUpdate = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    assertEq(
      userAfterFailedUpdate?.syncVersion,
      versionBeforeFailed,
      "Failed 409 update did NOT consume or advance user's committed syncVersion"
    );

    // ── SECTION B: Incremental Synchronization (Tests 6–16) ───────────────────
    console.log("\n── Section B: Incremental Synchronization ──");

    // Test 6: Initial synchronization using cursor 0
    const syncRes0 = await req(port, "/api/sync/changes?since=0", {
      headers: authHeadersA
    });
    assertEq(syncRes0.status, 200, "GET /api/sync/changes?since=0 returns 200 OK");
    assertEq(syncRes0.data.success, true, "Sync response has success: true");
    assert(Array.isArray(syncRes0.data.changes), "Sync response changes is an array");
    // Items so far: item 1 (tombstone, syncVersion 3) and item 2 (active, syncVersion 4)
    assertEq(syncRes0.data.changes.length, 2, "Cursor 0 returns both changes (tombstone + active)");
    assertEq(syncRes0.data.currentSyncVersion, 4, "currentSyncVersion is 4");
    assertEq(syncRes0.data.nextCursor, 4, "nextCursor advanced to 4");
    assertEq(syncRes0.data.hasMore, false, "hasMore is false when all records returned");

    // Test 7: Synchronization after a known cursor (since=3 returns only syncVersion 4)
    const syncResSince3 = await req(port, "/api/sync/changes?since=3", {
      headers: authHeadersA
    });
    assertEq(syncResSince3.status, 200, "Sync with since=3 returns 200 OK");
    assertEq(syncResSince3.data.changes.length, 1, "since=3 returns exactly 1 change (item 2)");
    assertEq(syncResSince3.data.changes[0]?.id, item2Id, "Returned change is item 2");
    assertEq(syncResSince3.data.changes[0]?.syncVersion, 4, "Returned change syncVersion is 4");

    // Test 8: Empty synchronization response when cursor equals currentSyncVersion
    const syncResCurrent = await req(port, "/api/sync/changes?since=4", {
      headers: authHeadersA
    });
    assertEq(syncResCurrent.status, 200, "Sync with since=currentSyncVersion returns 200 OK");
    assertEq(syncResCurrent.data.changes.length, 0, "No changes returned when up to date");
    assertEq(syncResCurrent.data.nextCursor, 4, "nextCursor remains at currentSyncVersion");
    assertEq(syncResCurrent.data.hasMore, false, "hasMore is false");

    // Add more items to thoroughly test pagination
    await req(port, "/api/vault", { method: "POST", headers: authHeadersA, body: makeEncryptedPayload("item-3") }); // sv 5
    await req(port, "/api/vault", { method: "POST", headers: authHeadersA, body: makeEncryptedPayload("item-4") }); // sv 6
    await req(port, "/api/vault", { method: "POST", headers: authHeadersA, body: makeEncryptedPayload("item-5") }); // sv 7
    // Total items now: item1 (sv 3, deleted), item2 (sv 4), item3 (sv 5), item4 (sv 6), item5 (sv 7) -> 5 items total

    // Test 9: Pagination with a small limit (limit=2)
    const page1Res = await req(port, "/api/sync/changes?since=0&limit=2", {
      headers: authHeadersA
    });
    assertEq(page1Res.status, 200, "Page 1 returns 200 OK");
    assertEq(page1Res.data.changes.length, 2, "Page 1 returns exactly 2 records");
    assertEq(page1Res.data.hasMore, true, "Page 1 hasMore is true");
    const page1NextCursor = page1Res.data.nextCursor;
    assertEq(page1NextCursor, page1Res.data.changes[1].syncVersion, "Page 1 nextCursor equals last record's syncVersion");

    // Test 10: Page 2 using page 1's nextCursor
    const page2Res = await req(port, `/api/sync/changes?since=${page1NextCursor}&limit=2`, {
      headers: authHeadersA
    });
    assertEq(page2Res.status, 200, "Page 2 returns 200 OK");
    assertEq(page2Res.data.changes.length, 2, "Page 2 returns exactly 2 records");
    assertEq(page2Res.data.hasMore, true, "Page 2 hasMore is true");
    const page2NextCursor = page2Res.data.nextCursor;

    // Test 11: Page 3 using page 2's nextCursor
    const page3Res = await req(port, `/api/sync/changes?since=${page2NextCursor}&limit=2`, {
      headers: authHeadersA
    });
    assertEq(page3Res.status, 200, "Page 3 returns 200 OK");
    assertEq(page3Res.data.changes.length, 1, "Page 3 returns remaining 1 record");
    assertEq(page3Res.data.hasMore, false, "Page 3 hasMore is false");
    assertEq(page3Res.data.nextCursor, 7, "Page 3 nextCursor reaches currentSyncVersion 7");

    // Test 12: Verify no record is skipped across paginated requests
    const allPaginatedIds = [
      ...page1Res.data.changes.map((c: any) => c.id),
      ...page2Res.data.changes.map((c: any) => c.id),
      ...page3Res.data.changes.map((c: any) => c.id)
    ];
    assertEq(allPaginatedIds.length, 5, "Total paginated records equals exactly 5");
    const uniquePaginatedIds = new Set(allPaginatedIds);
    assertEq(uniquePaginatedIds.size, 5, "No duplicate or skipped records across pages");

    // Test 13: Invalid non-integer cursor rejection
    const invalidCursorRes = await req(port, "/api/sync/changes?since=not-an-integer", {
      headers: authHeadersA
    });
    assertEq(invalidCursorRes.status, 400, "Non-integer cursor rejected with 400 Bad Request");

    // Test 14: Negative cursor rejection
    const negativeCursorRes = await req(port, "/api/sync/changes?since=-1", {
      headers: authHeadersA
    });
    assertEq(negativeCursorRes.status, 400, "Negative cursor rejected with 400 Bad Request");

    // Test 15: Invalid limit rejection (0 and >500)
    const zeroLimitRes = await req(port, "/api/sync/changes?limit=0", { headers: authHeadersA });
    assertEq(zeroLimitRes.status, 400, "Limit 0 rejected with 400 Bad Request");
    const excessiveLimitRes = await req(port, "/api/sync/changes?limit=501", { headers: authHeadersA });
    assertEq(excessiveLimitRes.status, 400, "Limit 501 rejected with 400 Bad Request");

    // Test 16: Cursor greater than currentSyncVersion rejection
    const futureCursorRes = await req(port, "/api/sync/changes?since=999999", {
      headers: authHeadersA
    });
    assertEq(futureCursorRes.status, 400, "Cursor > currentSyncVersion rejected with 400 Bad Request");

    // ── SECTION C: Ownership and Security (Tests 17–23) ───────────────────────
    console.log("\n── Section C: Ownership and Security ──");

    const emailB = uniqueEmail();
    await req(port, "/api/auth/register", { method: "POST", body: { email: emailB, password: passA } });
    const userB_db = await prisma.user.findUnique({ where: { emailNormalized: emailB.toLowerCase() } });
    if (userB_db) cleanupUserIds.push(userB_db.id);

    const loginResB = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailB, password: passA, deviceIdentifier: "phone-dev" }
    });
    const tokenB = loginResB.data.data?.token as string;
    const authHeadersB = { Authorization: `Bearer ${tokenB}` };

    // Create item for User B (sv 1 for user B)
    await req(port, "/api/vault", { method: "POST", headers: authHeadersB, body: makeEncryptedPayload("user-b-item") });

    // Test 17: User B cannot retrieve User A's synchronization changes
    const syncResB = await req(port, "/api/sync/changes?since=0", { headers: authHeadersB });
    assertEq(syncResB.status, 200, "User B sync returns 200 OK");
    assertEq(syncResB.data.changes.length, 1, "User B receives only User B's 1 record");
    assertEq(syncResB.data.currentSyncVersion, 1, "User B currentSyncVersion is 1 (completely isolated from User A's 7)");

    // Test 18: Client cannot supply userId query parameter to access another user's records
    const spoofUserRes = await req(port, `/api/sync/changes?since=0&userId=${userA_db!.id}`, {
      headers: authHeadersB
    });
    assertEq(spoofUserRes.status, 400, "Query parameter 'userId' strictly rejected with 400 Bad Request");

    // Test 19: Missing authentication rejection
    const noAuthSyncRes = await req(port, "/api/sync/changes");
    assertEq(noAuthSyncRes.status, 401, "Sync without Bearer token rejected with 401 Unauthorized");

    // Test 20: Invalid JWT rejection
    const tamperedSyncRes = await req(port, "/api/sync/changes", {
      headers: { Authorization: `Bearer ${tokenA}TAMPERED` }
    });
    assertEq(tamperedSyncRes.status, 401, "Tampered JWT rejected with 401 Unauthorized");

    // Test 21: Missing or malformed sid rejection
    const secret = process.env.JWT_SECRET!;
    const tokenWithoutSid = jwt.sign({ sub: userA_db!.id, email: userA_db!.email }, secret, {
      algorithm: "HS256",
      expiresIn: "15m"
    });
    const noSidSyncRes = await req(port, "/api/sync/changes", {
      headers: { Authorization: `Bearer ${tokenWithoutSid}` }
    });
    assertEq(noSidSyncRes.status, 401, "Token without sid rejected with 401 Unauthorized");

    // Test 22: Revoked session rejection
    const loginTemp = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailA, password: passA, deviceIdentifier: "temp-device" }
    });
    const tempToken = loginTemp.data.data?.token as string;
    const tempSessionId = loginTemp.data.data?.sessionId as string;

    // Revoke temp session
    await prisma.session.update({ where: { id: tempSessionId }, data: { revokedAt: new Date() } });
    const revokedSyncRes = await req(port, "/api/sync/changes", {
      headers: { Authorization: `Bearer ${tempToken}` }
    });
    assertEq(revokedSyncRes.status, 401, "Revoked session rejected with 401 Unauthorized");

    // Test 23: Removed-device session rejection
    const loginTempDev = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailA, password: passA, deviceIdentifier: "remove-test-dev" }
    });
    const tempDevToken = loginTempDev.data.data?.token as string;
    const tempDev = await prisma.device.findFirst({ where: { userId: userA_db!.id, deviceIdentifier: "remove-test-dev" } });

    // Mark device removed
    await prisma.device.update({ where: { id: tempDev!.id }, data: { removedAt: new Date() } });
    const removedDevSyncRes = await req(port, "/api/sync/changes", {
      headers: { Authorization: `Bearer ${tempDevToken}` }
    });
    assertEq(removedDevSyncRes.status, 401, "Removed-device session rejected with 401 Unauthorized");

    // ── SECTION D: Conflict Handling (Tests 24–27) ────────────────────────────
    console.log("\n── Section D: Conflict Handling ──");

    // Create item for conflict test
    const itemConflictRes = await req(port, "/api/vault", {
      method: "POST",
      headers: authHeadersA,
      body: makeEncryptedPayload("conflict-item")
    });
    const conflictItemId = itemConflictRes.data.data?.id;

    const userPreConflict = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    const versionBeforeConflict = userPreConflict!.syncVersion;

    // Test 24: First update with expectedRevision: 1 succeeds
    const firstUpdateRes = await req(port, `/api/vault/${conflictItemId}`, {
      method: "PUT",
      headers: authHeadersA,
      body: { ...makeEncryptedPayload("conflict-item-rev2"), expectedRevision: 1 }
    });
    assertEq(firstUpdateRes.status, 200, "First device update with expectedRevision=1 succeeds (200)");
    assertEq(firstUpdateRes.data.data?.revision, 2, "Item revision advanced to 2");

    // Test 25: Second device with stale expectedRevision: 1 receives 409 Conflict
    const secondUpdateRes = await req(port, `/api/vault/${conflictItemId}`, {
      method: "PUT",
      headers: authHeadersA,
      body: { ...makeEncryptedPayload("conflict-item-competing"), expectedRevision: 1 }
    });
    assertEq(secondUpdateRes.status, 409, "Second device with stale expectedRevision=1 gets 409 Conflict");

    // Test 26: Verify server-side record remained revision 2 with Device 1's payload
    const itemAfterConflict = await req(port, `/api/vault/${conflictItemId}`, {
      headers: authHeadersA
    });
    assertEq(itemAfterConflict.data.data?.revision, 2, "Server-side revision remains 2");
    assertEq(
      itemAfterConflict.data.data?.encryptedPayload,
      Buffer.from("conflict-item-rev2").toString("base64"),
      "Server-side payload remains Device 1's successful write"
    );

    // Test 27: Verify user's syncVersion was incremented by exactly 1 (for the successful write)
    const userPostConflict = await prisma.user.findUnique({ where: { id: userA_db!.id } });
    assertEq(
      userPostConflict!.syncVersion,
      versionBeforeConflict + 1,
      "User syncVersion incremented by exactly 1; 409 failure did not consume version"
    );

    // ── SECTION E: Tombstone Synchronization (Tests 28–31) ────────────────────
    console.log("\n── Section E: Tombstone Synchronization ──");

    // Create item to be deleted
    const tombstoneItemRes = await req(port, "/api/vault", {
      method: "POST",
      headers: authHeadersA,
      body: makeEncryptedPayload("item-to-tombstone")
    });
    const tombstoneItemId = tombstoneItemRes.data.data?.id;
    const tombstoneCreateVersion = tombstoneItemRes.data.data?.syncVersion;

    // Test 28: Delete the vault item
    const delTombRes = await req(port, `/api/vault/${tombstoneItemId}`, {
      method: "DELETE",
      headers: authHeadersA
    });
    assertEq(delTombRes.status, 200, "DELETE /api/vault/:id returns 200 OK");
    const delSyncVersion = delTombRes.data.data?.syncVersion;
    assert(delSyncVersion > tombstoneCreateVersion, "Deletion assigned a newer syncVersion than creation");

    // Test 29: Tombstone appears in incremental changes
    const syncTombRes = await req(port, `/api/sync/changes?since=${delSyncVersion - 1}`, {
      headers: authHeadersA
    });
    assertEq(syncTombRes.status, 200, "Sync returns 200 OK");
    const tombChange = syncTombRes.data.changes.find((c: any) => c.id === tombstoneItemId);
    assert(tombChange !== undefined, "Tombstone record found in sync changes");
    assertEq(tombChange?.isDeleted, true, "Tombstone has isDeleted: true");
    assert(typeof tombChange?.deletedAt === "string", "Tombstone has deletedAt timestamp string");
    assertEq(tombChange?.encryptedPayload, undefined, "Tombstone does NOT expose active encrypted payload");

    // Test 30: Deleted item does NOT appear in active vault listing
    const listActiveRes = await req(port, "/api/vault", { headers: authHeadersA });
    const foundInActive = listActiveRes.data.data?.find((i: any) => i.id === tombstoneItemId);
    assertEq(foundInActive, undefined, "Deleted item excluded from active GET /api/vault listing");

    // Test 31: Repeated sync does not resurrect deleted records
    const syncRepeatRes = await req(port, `/api/sync/changes?since=${delSyncVersion - 1}`, {
      headers: authHeadersA
    });
    const tombRepeat = syncRepeatRes.data.changes.find((c: any) => c.id === tombstoneItemId);
    assertEq(tombRepeat?.isDeleted, true, "Repeated sync continues to return tombstone with isDeleted: true");

    const listRepeatRes = await req(port, "/api/vault", { headers: authHeadersA });
    const foundInActiveRepeat = listRepeatRes.data.data?.find((i: any) => i.id === tombstoneItemId);
    assertEq(foundInActiveRepeat, undefined, "Repeated checks confirm item remains excluded from active vault");

    // ── SECTION F: Concurrency (Tests 32–35) ──────────────────────────────────
    console.log("\n── Section F: Concurrency ──");

    const emailC = uniqueEmail();
    await req(port, "/api/auth/register", { method: "POST", body: { email: emailC, password: passA } });
    const userC_db = await prisma.user.findUnique({ where: { emailNormalized: emailC.toLowerCase() } });
    if (userC_db) cleanupUserIds.push(userC_db.id);

    const loginResC = await req(port, "/api/auth/login", {
      method: "POST",
      body: { email: emailC, password: passA, deviceIdentifier: "concur-device" }
    });
    const tokenC = loginResC.data.data?.token as string;
    const authHeadersC = { Authorization: `Bearer ${tokenC}` };

    // Test 32: Run 4 concurrent vault item creations for User C
    const concurCreations = await Promise.all([
      req(port, "/api/vault", { method: "POST", headers: authHeadersC, body: makeEncryptedPayload("concur-1") }),
      req(port, "/api/vault", { method: "POST", headers: authHeadersC, body: makeEncryptedPayload("concur-2") }),
      req(port, "/api/vault", { method: "POST", headers: authHeadersC, body: makeEncryptedPayload("concur-3") }),
      req(port, "/api/vault", { method: "POST", headers: authHeadersC, body: makeEncryptedPayload("concur-4") })
    ]);
    const allCreated201 = concurCreations.every((r) => r.status === 201);
    assert(allCreated201, "All 4 concurrent creations succeed with 201 Created");

    // Test 33: Verify all 4 syncVersion values are unique and strictly 1, 2, 3, 4
    const createdSyncVersions = concurCreations.map((r) => r.data.data?.syncVersion).sort((a: number, b: number) => a - b);
    assertEq(JSON.stringify(createdSyncVersions), JSON.stringify([1, 2, 3, 4]), "Concurrent creations assigned unique, strictly sequential syncVersions [1, 2, 3, 4]");

    // Test 34: Verify every committed mutation appears in synchronization
    const syncConcurRes = await req(port, "/api/sync/changes?since=0", { headers: authHeadersC });
    assertEq(syncConcurRes.data.changes.length, 4, "Sync returns all 4 concurrently created items");
    assertEq(syncConcurRes.data.currentSyncVersion, 4, "User C currentSyncVersion matches 4");

    // Test 35: Verify user syncVersion matches max VaultItem syncVersion in database
    const userC_after = await prisma.user.findUnique({ where: { id: userC_db!.id } });
    assertEq(userC_after?.syncVersion, 4, "User C DB syncVersion is 4");

    // ── SECTION G: Regression (Tests 36–40) ────────────────────────────────────
    console.log("\n── Section G: Regression & Security Invariants ──");

    // Test 36: Root endpoint
    const rootRes = await req(port, "/");
    assertEq(rootRes.status, 200, "GET / returns 200 OK (regression)");

    // Test 37: Health endpoint
    const healthRes = await req(port, "/api/health");
    assertEq(healthRes.status, 200, "GET /api/health returns 200 OK (regression)");

    // Test 38: Auth profile endpoint
    const meRes = await req(port, "/api/auth/me", { headers: authHeadersA });
    assertEq(meRes.status, 200, "GET /api/auth/me returns 200 OK (regression)");

    // Test 39: Device management listing
    const devicesRes = await req(port, "/api/devices", { headers: authHeadersA });
    assertEq(devicesRes.status, 200, "GET /api/devices returns 200 OK (regression)");

    // Test 40: Zero-Knowledge request validation (forbidden plaintext key rejected)
    const zkViolationRes = await req(port, "/api/vault", {
      method: "POST",
      headers: authHeadersA,
      body: {
        ...makeEncryptedPayload("test"),
        password: "plaintext-password-attempt"
      }
    });
    assertEq(zkViolationRes.status, 400, "Forbidden plaintext key 'password' rejected with 400 Bad Request");

  } finally {
    // ── Cleanup ───────────────────────────────────────────────────────────────
    console.log("\n── Cleanup ──");
    for (const userId of cleanupUserIds) {
      await prisma.user.delete({ where: { id: userId } }).catch(() => {});
    }
    console.log(`  🧹 Cleaned up ${cleanupUserIds.length} test user(s)`);

    await prisma.$disconnect();
    server.close();

    // ── Summary ───────────────────────────────────────────────────────────────
    console.log(`\n${"═".repeat(60)}`);
    console.log(`Phase 7 Results: ${passed + failed} tests | ✅ ${passed} passed | ❌ ${failed} failed`);
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
