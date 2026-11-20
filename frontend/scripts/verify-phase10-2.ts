/**
 * VaultGuard Phase 10.2 – Live Vault Health & Metrics Engine Verification Suite
 *
 * Exhaustively tests all 18 required scenarios from the Phase 10.2 specification:
 * 1. Empty vault
 * 2. One strong password
 * 3. One weak password
 * 4. One fair/medium password
 * 5. Multiple strong passwords
 * 6. Two accounts using exactly the same password
 * 7. Multiple groups of reused passwords
 * 8. Passwords differing only by letter case
 * 9. Passwords containing leading or trailing spaces
 * 10. Entries with missing password fields
 * 11. Entries with blank password values
 * 12. Entries with missing optional metadata
 * 13. Mixed weak, fair, strong, and reused passwords
 * 14. Health score lower and upper boundaries (0 and 100)
 * 15. Recalculation after an entry is edited
 * 16. Recalculation after an entry is deleted
 * 17. No previous-account metrics after account switching
 * 18. No metrics from decrypted data after vault lock
 * Plus: Immutability and determinism verification
 */

import { computeVaultMetrics, getLockedVaultMetrics, getEmptyVaultMetrics } from "../lib/vault-metrics";
import type { DecryptedVaultItem } from "../lib/crypto/types";

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  [PASS] ${testName}`);
    passed++;
  } else {
    console.error(`  [FAIL] ${testName}${detail ? `: ${detail}` : ""}`);
    failed++;
  }
}

function makeItem(id: string, password?: string, overrides: Partial<DecryptedVaultItem> = {}): DecryptedVaultItem {
  return {
    id,
    service: overrides.service ?? `Service-${id}`,
    username: overrides.username ?? `user-${id}@test.local`,
    password,
    category: overrides.category ?? "Personal",
    health: overrides.health ?? "Strong",
    favorite: overrides.favorite ?? false,
    notes: overrides.notes ?? "",
    createdAt: overrides.createdAt ?? new Date().toISOString(),
    updatedAt: overrides.updatedAt ?? new Date().toISOString()
  };
}

async function runTests() {
  console.log("=== VaultGuard Phase 10.2 – Live Vault Health & Metrics Engine Tests ===\n");

  // Synthetic test passwords
  const STRONG_PWD = "B@mb00#Cany0n!Spruc3$2026"; // Excellent score (86 in analyzer -> 100 scaled)
  const STRONG_PWD_2 = "X9#mK$2vL@8pQ!zR%4wT";    // Excellent score
  const FAIR_PWD = "Summer24";                    // Moderate score (59 in analyzer -> 69 scaled)
  const WEAK_PWD = "password";                    // Very weak score (0 in analyzer)
  const WEAK_PWD_2 = "123456";                    // Very weak score (5 in analyzer)

  // --------------------------------------------------------------------------
  // Test 1: Empty vault
  // --------------------------------------------------------------------------
  console.log("Test 1: Empty vault");
  {
    const metrics = computeVaultMetrics([]);
    assert(metrics.totalEntries === 0, "totalEntries is 0");
    assert(metrics.usablePasswordEntries === 0, "usablePasswordEntries is 0");
    assert(metrics.weakCount === 0, "weakCount is 0");
    assert(metrics.fairCount === 0, "fairCount is 0");
    assert(metrics.strongCount === 0, "strongCount is 0");
    assert(metrics.reusedPasswordCount === 0, "reusedPasswordCount is 0");
    assert(metrics.affectedAccountsCount === 0, "affectedAccountsCount is 0");
    assert(metrics.healthScore === null, "healthScore is null (not fabricated)");
    assert(metrics.isEmpty === true, "isEmpty flag is true");
    assert(metrics.isLocked === false, "isLocked is false");
  }

  // --------------------------------------------------------------------------
  // Test 2: One strong password
  // --------------------------------------------------------------------------
  console.log("\nTest 2: One strong password");
  {
    const items = [makeItem("1", STRONG_PWD)];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 1, "totalEntries is 1");
    assert(metrics.usablePasswordEntries === 1, "usablePasswordEntries is 1");
    assert(metrics.strongCount === 1, "strongCount is 1");
    assert(metrics.fairCount === 0, "fairCount is 0");
    assert(metrics.weakCount === 0, "weakCount is 0");
    assert(metrics.reusedPasswordCount === 0, "reusedPasswordCount is 0");
    assert(metrics.healthScore === 100, "healthScore is 100 for single excellent password");
  }

  // --------------------------------------------------------------------------
  // Test 3: One weak password
  // --------------------------------------------------------------------------
  console.log("\nTest 3: One weak password");
  {
    const items = [makeItem("1", WEAK_PWD)];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 1, "totalEntries is 1");
    assert(metrics.usablePasswordEntries === 1, "usablePasswordEntries is 1");
    assert(metrics.weakCount === 1, "weakCount is 1");
    assert(metrics.fairCount === 0, "fairCount is 0");
    assert(metrics.strongCount === 0, "strongCount is 0");
    assert(metrics.healthScore === 0, "healthScore penalized to 0 for single weak password");
  }

  // --------------------------------------------------------------------------
  // Test 4: One fair/medium password
  // --------------------------------------------------------------------------
  console.log("\nTest 4: One fair/medium password");
  {
    const items = [makeItem("1", FAIR_PWD)];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 1, "totalEntries is 1");
    assert(metrics.usablePasswordEntries === 1, "usablePasswordEntries is 1");
    assert(metrics.fairCount === 1, "fairCount is 1");
    assert(metrics.weakCount === 0, "weakCount is 0");
    assert(metrics.strongCount === 0, "strongCount is 0");
    assert(
      metrics.healthScore !== null && metrics.healthScore >= 50 && metrics.healthScore <= 70,
      `healthScore is moderate (${metrics.healthScore}/100)`
    );
  }

  // --------------------------------------------------------------------------
  // Test 5: Multiple strong passwords
  // --------------------------------------------------------------------------
  console.log("\nTest 5: Multiple strong passwords");
  {
    const items = [
      makeItem("1", STRONG_PWD),
      makeItem("2", STRONG_PWD_2),
      makeItem("3", "K9#fR!7wQ$2pL@8mZ%4tY")
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 3, "totalEntries is 3");
    assert(metrics.usablePasswordEntries === 3, "usablePasswordEntries is 3");
    assert(metrics.strongCount === 3, "strongCount is 3");
    assert(metrics.reusedPasswordCount === 0, "reusedPasswordCount is 0");
    assert(metrics.healthScore === 100, "healthScore is 100 for all-strong unique passwords");
  }

  // --------------------------------------------------------------------------
  // Test 6: Two accounts using exactly the same password
  // --------------------------------------------------------------------------
  console.log("\nTest 6: Two accounts using exactly the same password");
  {
    const SHARED = "SharedSecret!2026";
    const items = [
      makeItem("1", SHARED, { service: "Service A" }),
      makeItem("2", SHARED, { service: "Service B" })
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 2, "totalEntries is 2");
    assert(metrics.usablePasswordEntries === 2, "usablePasswordEntries is 2");
    assert(metrics.reusedPasswordCount === 1, "reusedPasswordCount is 1 (one duplicate group)");
    assert(metrics.affectedAccountsCount === 2, "affectedAccountsCount is 2 (both accounts affected)");
    assert(
      metrics.healthScore !== null && metrics.healthScore < 80,
      `healthScore is penalized for reuse (${metrics.healthScore}/100)`
    );
  }

  // --------------------------------------------------------------------------
  // Test 7: Multiple groups of reused passwords
  // --------------------------------------------------------------------------
  console.log("\nTest 7: Multiple groups of reused passwords");
  {
    const GROUP_1 = "AlphaSecret!2026";
    const GROUP_2 = "BetaSecret!2026";
    const UNIQUE = "UniqueSecret!2026#99";
    const items = [
      makeItem("1", GROUP_1),
      makeItem("2", GROUP_1),
      makeItem("3", GROUP_2),
      makeItem("4", GROUP_2),
      makeItem("5", GROUP_2),
      makeItem("6", UNIQUE)
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 6, "totalEntries is 6");
    assert(metrics.reusedPasswordCount === 2, "reusedPasswordCount is 2 (two distinct duplicate groups)");
    assert(metrics.affectedAccountsCount === 5, "affectedAccountsCount is 5 (2 + 3 accounts affected)");
  }

  // --------------------------------------------------------------------------
  // Test 8: Passwords differing only by letter case
  // --------------------------------------------------------------------------
  console.log("\nTest 8: Passwords differing only by letter case");
  {
    const items = [
      makeItem("1", "Password123!"),
      makeItem("2", "password123!")
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.reusedPasswordCount === 0, "reusedPasswordCount is 0 (case-sensitive check)");
    assert(metrics.affectedAccountsCount === 0, "affectedAccountsCount is 0");
  }

  // --------------------------------------------------------------------------
  // Test 9: Passwords containing leading or trailing spaces
  // --------------------------------------------------------------------------
  console.log("\nTest 9: Passwords containing leading or trailing spaces");
  {
    const items = [
      makeItem("1", "Password123!"),
      makeItem("2", "Password123! "),
      makeItem("3", " Password123!")
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.reusedPasswordCount === 0, "reusedPasswordCount is 0 (untrimmed exact match check)");
    assert(metrics.affectedAccountsCount === 0, "affectedAccountsCount is 0");
  }

  // --------------------------------------------------------------------------
  // Test 10: Entries with missing password fields
  // --------------------------------------------------------------------------
  console.log("\nTest 10: Entries with missing password fields");
  {
    const items = [
      makeItem("1", undefined),
      makeItem("2", STRONG_PWD)
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 2, "totalEntries is 2");
    assert(metrics.usablePasswordEntries === 1, "usablePasswordEntries is 1");
    assert(metrics.missingPasswordCount === 1, "missingPasswordCount is 1");
    assert(metrics.strongCount === 1, "strongCount is 1 (missing password not classified as strong)");
  }

  // --------------------------------------------------------------------------
  // Test 11: Entries with blank password values
  // --------------------------------------------------------------------------
  console.log("\nTest 11: Entries with blank password values");
  {
    const items = [
      makeItem("1", ""),
      makeItem("2", "")
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 2, "totalEntries is 2");
    assert(metrics.usablePasswordEntries === 0, "usablePasswordEntries is 0");
    assert(metrics.missingPasswordCount === 2, "missingPasswordCount is 2");
    assert(metrics.reusedPasswordCount === 0, "reusedPasswordCount is 0 (blank passwords ignored for reuse)");
    assert(metrics.strongCount === 0, "strongCount is 0 (blank passwords not classified as strong)");
    assert(metrics.healthScore === 0, "healthScore is 0 for vault with no usable credentials");
  }

  // --------------------------------------------------------------------------
  // Test 12: Entries with missing optional metadata
  // --------------------------------------------------------------------------
  console.log("\nTest 12: Entries with missing optional metadata");
  {
    const rawItems: any[] = [
      { id: "raw-1", password: STRONG_PWD },
      { id: "raw-2", password: FAIR_PWD, service: "Partial Service" }
    ];
    const metrics = computeVaultMetrics(rawItems);
    assert(metrics.totalEntries === 2, "totalEntries is 2");
    assert(metrics.usablePasswordEntries === 2, "usablePasswordEntries is 2");
    assert(metrics.strongCount === 1, "strongCount is 1");
    assert(metrics.fairCount === 1, "fairCount is 1");
  }

  // --------------------------------------------------------------------------
  // Test 13: Mixed weak, fair, strong, and reused passwords
  // --------------------------------------------------------------------------
  console.log("\nTest 13: Mixed weak, fair, strong, and reused passwords");
  {
    const SHARED_FAIR = "Autumn2026";
    const items = [
      makeItem("1", STRONG_PWD),
      makeItem("2", SHARED_FAIR),
      makeItem("3", SHARED_FAIR),
      makeItem("4", WEAK_PWD),
      makeItem("5", "") // blank entry
    ];
    const metrics = computeVaultMetrics(items);
    assert(metrics.totalEntries === 5, "totalEntries is 5");
    assert(metrics.usablePasswordEntries === 4, "usablePasswordEntries is 4");
    assert(metrics.missingPasswordCount === 1, "missingPasswordCount is 1");
    assert(metrics.strongCount === 1, "strongCount is 1");
    assert(metrics.fairCount === 2, "fairCount is 2");
    assert(metrics.weakCount === 1, "weakCount is 1");
    assert(metrics.reusedPasswordCount === 1, "reusedPasswordCount is 1");
    assert(metrics.affectedAccountsCount === 2, "affectedAccountsCount is 2");
    assert(
      metrics.healthScore !== null && metrics.healthScore >= 0 && metrics.healthScore <= 100,
      `healthScore is bounded (${metrics.healthScore}/100)`
    );
  }

  // --------------------------------------------------------------------------
  // Test 14: Health score lower and upper boundaries
  // --------------------------------------------------------------------------
  console.log("\nTest 14: Health score lower and upper boundaries");
  {
    // Perfect upper boundary = 100
    const perfectItems = [makeItem("1", STRONG_PWD), makeItem("2", STRONG_PWD_2)];
    const perfectMetrics = computeVaultMetrics(perfectItems);
    assert(perfectMetrics.healthScore === 100, "Upper boundary is exactly 100");

    // Worst lower boundary = 0
    const worstItems = [
      makeItem("1", WEAK_PWD),
      makeItem("2", WEAK_PWD),
      makeItem("3", WEAK_PWD_2)
    ];
    const worstMetrics = computeVaultMetrics(worstItems);
    assert(worstMetrics.healthScore === 0, "Lower boundary is exactly 0");
  }

  // --------------------------------------------------------------------------
  // Test 15: Recalculation after an entry is edited
  // --------------------------------------------------------------------------
  console.log("\nTest 15: Recalculation after an entry is edited");
  {
    let items = [
      makeItem("1", WEAK_PWD),
      makeItem("2", STRONG_PWD)
    ];
    const beforeEdit = computeVaultMetrics(items);
    assert(beforeEdit.weakCount === 1, "before edit weakCount is 1");

    // User updates item 1 from weak to strong
    items = items.map(it => it.id === "1" ? { ...it, password: STRONG_PWD_2 } : it);
    const afterEdit = computeVaultMetrics(items);
    assert(afterEdit.weakCount === 0, "after edit weakCount is 0");
    assert(afterEdit.strongCount === 2, "after edit strongCount is 2");
    assert(
      (afterEdit.healthScore ?? 0) > (beforeEdit.healthScore ?? 0),
      `healthScore increased from ${beforeEdit.healthScore} to ${afterEdit.healthScore}`
    );
  }

  // --------------------------------------------------------------------------
  // Test 16: Recalculation after an entry is deleted
  // --------------------------------------------------------------------------
  console.log("\nTest 16: Recalculation after an entry is deleted");
  {
    const SHARED = "SharedSecret!2026";
    let items = [
      makeItem("1", SHARED),
      makeItem("2", SHARED),
      makeItem("3", STRONG_PWD)
    ];
    const beforeDelete = computeVaultMetrics(items);
    assert(beforeDelete.reusedPasswordCount === 1, "before delete has 1 reused group");
    assert(beforeDelete.affectedAccountsCount === 2, "before delete has 2 affected accounts");

    // User deletes duplicate item 2
    items = items.filter(it => it.id !== "2");
    const afterDelete = computeVaultMetrics(items);
    assert(afterDelete.reusedPasswordCount === 0, "after delete reusedPasswordCount is 0");
    assert(afterDelete.affectedAccountsCount === 0, "after delete affectedAccountsCount is 0");
    assert(
      (afterDelete.healthScore ?? 0) > (beforeDelete.healthScore ?? 0),
      `healthScore increased after removing duplicate from ${beforeDelete.healthScore} to ${afterDelete.healthScore}`
    );
  }

  // --------------------------------------------------------------------------
  // Test 17: No previous-account metrics after account switching
  // --------------------------------------------------------------------------
  console.log("\nTest 17: No previous-account metrics after account switching");
  {
    // When an account switch occurs, VaultContext locks the vault and sets items to []
    const lockedMetrics = getLockedVaultMetrics();
    assert(lockedMetrics.isLocked === true, "isLocked is true");
    assert(lockedMetrics.totalEntries === 0, "totalEntries reset to 0");
    assert(lockedMetrics.healthScore === null, "healthScore reset to null (no previous account metrics shown)");
    assert(lockedMetrics.weakCount === 0, "weakCount reset to 0");
    assert(lockedMetrics.reusedPasswordCount === 0, "reusedPasswordCount reset to 0");
  }

  // --------------------------------------------------------------------------
  // Test 18: No metrics from decrypted data after vault lock
  // --------------------------------------------------------------------------
  console.log("\nTest 18: No metrics from decrypted data after vault lock");
  {
    const decryptedItems = [makeItem("1", STRONG_PWD), makeItem("2", WEAK_PWD)];
    // While unlocked:
    const unlockedMetrics = computeVaultMetrics(decryptedItems);
    assert(unlockedMetrics.totalEntries === 2, "unlocked metrics show active records");

    // Upon lockVault():
    const lockedState = computeVaultMetrics([], { isLocked: true });
    assert(lockedState.isLocked === true, "lockedState.isLocked is true");
    assert(lockedState.totalEntries === 0, "lockedState has 0 entries");
    assert(lockedState.healthScore === null, "lockedState has null health score");
  }

  // --------------------------------------------------------------------------
  // Test 19: Immutability and determinism
  // --------------------------------------------------------------------------
  console.log("\nTest 19: Immutability and determinism");
  {
    const items = [
      makeItem("1", STRONG_PWD),
      makeItem("2", WEAK_PWD)
    ];
    const itemsSnapshot = JSON.stringify(items);
    const m1 = computeVaultMetrics(items);
    const m2 = computeVaultMetrics(items);

    assert(JSON.stringify(items) === itemsSnapshot, "computeVaultMetrics does NOT mutate input items");
    assert(JSON.stringify(m1) === JSON.stringify(m2), "computeVaultMetrics is 100% deterministic");
  }

  console.log("\n-------------------------------------------------------");
  console.log(`Phase 10.2 Test Results: ${passed} passed, ${failed} failed.`);
  console.log("-------------------------------------------------------\n");

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error("Test execution error:", err);
  process.exit(1);
});
