/**
 * VaultGuard Phase 10.5 – Contextual Security Assistant Verification Suite
 *
 * Exhaustively verifies:
 * 1. Empty vault response & recommendations
 * 2. Locked vault response & zero secret leakage
 * 3. Weak-password identification by service name
 * 4. Reused-password identification across duplicate groups
 * 5. Missing-password handling & recommendations
 * 6. Correct prioritization (CRITICAL -> HIGH -> MEDIUM -> LOW -> POSITIVE)
 * 7. Correct recommendations for a healthy vault
 * 8. Zero exposure of actual password values in recommendations and chat
 * 9. No false claims of breach detection, malware, or dark web monitoring
 * 10. Account-switch context isolation
 * 11. Lock/logout context clearing
 * 12. Recalculation when vault contents change
 * 13. Malformed and incomplete record handling
 * 14. Immutability: zero mutation of original vault records
 * 15. Zero external network dependency (runs with network/fetch disabled)
 * 16. Non-regression of standard assistant questions and follow-ups
 */

import {
  analyzeVaultSecurity,
  getAssistantResponse,
  getContextualSuggestedPrompts,
  DEFAULT_SUGGESTED_PROMPTS,
  type VaultAssistantAnalysis,
  type AssistantRecommendation
} from "../lib/security-assistant";
import { computeVaultMetrics, getLockedVaultMetrics, getEmptyVaultMetrics } from "../lib/vault-metrics";
import type { DecryptedVaultItem } from "../lib/crypto/types";

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✅ PASS [${passed + failed + 1}] ${testName}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL [${passed + failed + 1}] ${testName}${detail ? `: ${detail}` : ""}`);
    failed++;
  }
}

function makeItem(
  id: string,
  service: string,
  password?: string,
  overrides: Partial<DecryptedVaultItem> = {}
): DecryptedVaultItem {
  return {
    id,
    service,
    username: overrides.username ?? `user-${id}@test.local`,
    password,
    category: overrides.category ?? "Personal",
    health: overrides.health ?? "Strong",
    favorite: overrides.favorite ?? false,
    notes: overrides.notes ?? "",
    createdAt: overrides.createdAt ?? new Date().toISOString(),
    updatedAt: overrides.updatedAt ?? new Date().toISOString(),
  };
}

async function run() {
  console.log("================================================================================");
  console.log("VaultGuard Phase 10.5: Contextual Security Assistant Verification Suite");
  console.log("================================================================================\n");

  // ─────────────────────────────────────────────────────────────────────────────
  // Section 1: Empty and Locked Vault States
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("── Section 1: Empty and Locked Vault States ──");

  // Test 1: Empty vault response
  const emptyMetrics = getEmptyVaultMetrics();
  const emptyAnalysis = analyzeVaultSecurity([], emptyMetrics, { isLocked: false });
  assert(
    emptyAnalysis.isEmpty === true &&
    emptyAnalysis.totalEntries === 0 &&
    emptyAnalysis.healthScore === null &&
    emptyAnalysis.recommendations.length > 0 &&
    emptyAnalysis.recommendations[0].id === "empty-vault-add-first",
    "Empty vault analysis returns honest empty state with initial guidance"
  );

  const emptyResponse = getAssistantResponse("How secure is my vault?", emptyAnalysis);
  assert(
    emptyResponse.text.toLowerCase().includes("currently empty") &&
    emptyResponse.text.toLowerCase().includes("0 saved") &&
    emptyResponse.followUps.length > 0,
    "Empty vault query explains vault is empty and suggests adding first entry"
  );

  // Test 2: Locked vault response
  const dummyItems = [makeItem("1", "GitHub", "SuperSecretPassword123!")];
  const lockedMetrics = getLockedVaultMetrics();
  const lockedAnalysis = analyzeVaultSecurity(dummyItems, lockedMetrics, { isLocked: true });
  assert(
    lockedAnalysis.isLocked === true &&
    lockedAnalysis.isEmpty === true &&
    lockedAnalysis.totalEntries === 0 &&
    lockedAnalysis.healthScore === null &&
    lockedAnalysis.recommendations.length === 0 &&
    lockedAnalysis.reusedGroups.length === 0,
    "Locked vault analysis clears all metrics and leaves recommendations empty"
  );

  const lockedResponse = getAssistantResponse("Are there any weak passwords?", lockedAnalysis);
  assert(
    lockedResponse.text.toLowerCase().includes("currently locked") &&
    lockedResponse.text.toLowerCase().includes("unlock") &&
    !lockedResponse.text.includes("GitHub"),
    "Locked vault query refuses to disclose credentials or service names"
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // Section 2: Vulnerability Identification
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n── Section 2: Vulnerability Identification ──");

  // Test 3: Weak-password identification
  const weakItems = [
    makeItem("1", "Northstar Mail", "123456"), // Weak
    makeItem("2", "Atlas Finance", "VeryStrongPassword#987654321"), // Strong
  ];
  const weakMetrics = computeVaultMetrics(weakItems);
  const weakAnalysis = analyzeVaultSecurity(weakItems, weakMetrics);
  assert(
    weakAnalysis.weakCount === 1 &&
    weakAnalysis.weakServices.includes("Northstar Mail") &&
    !weakAnalysis.weakServices.includes("Atlas Finance"),
    "Weak password identified by service name (Northstar Mail)"
  );

  const weakResponse = getAssistantResponse("Are there any weak passwords?", weakAnalysis);
  assert(
    weakResponse.text.includes("Northstar Mail") &&
    !weakResponse.text.includes("123456"),
    "Assistant weak-password query identifies affected service without leaking password text"
  );

  // Test 4: Reused-password identification
  const SHARED_PASSWORD = "IdenticalSharedPassword!2026";
  const reusedItems = [
    makeItem("1", "Service Alpha", SHARED_PASSWORD),
    makeItem("2", "Service Beta", SHARED_PASSWORD),
    makeItem("3", "Service Gamma", "UniquePassword$456"),
  ];
  const reusedMetrics = computeVaultMetrics(reusedItems);
  const reusedAnalysis = analyzeVaultSecurity(reusedItems, reusedMetrics);
  assert(
    reusedAnalysis.reusedPasswordCount === 1 &&
    reusedAnalysis.affectedAccountsCount === 2 &&
    reusedAnalysis.reusedGroups.length === 1 &&
    reusedAnalysis.reusedGroups[0].serviceNames.includes("Service Alpha") &&
    reusedAnalysis.reusedGroups[0].serviceNames.includes("Service Beta"),
    "Reused password identified across Service Alpha and Service Beta"
  );

  const reusedResponse = getAssistantResponse("Do I have reused passwords?", reusedAnalysis);
  assert(
    reusedResponse.text.includes("Service Alpha") &&
    reusedResponse.text.includes("Service Beta") &&
    !reusedResponse.text.includes(SHARED_PASSWORD),
    "Assistant reused-password query lists affected services without exposing the shared secret"
  );

  // Test 5: Missing-password handling
  const missingItems = [
    makeItem("1", "Complete Service", "StrongSecret#123"),
    makeItem("2", "Missing Service 1", ""),
    makeItem("3", "Missing Service 2", undefined),
  ];
  const missingMetrics = computeVaultMetrics(missingItems);
  const missingAnalysis = analyzeVaultSecurity(missingItems, missingMetrics);
  assert(
    missingAnalysis.missingPasswordCount === 2 &&
    missingAnalysis.missingServices.includes("Missing Service 1") &&
    missingAnalysis.missingServices.includes("Missing Service 2") &&
    missingAnalysis.recommendations.some(r => r.id === "medium-missing-passwords"),
    "Missing passwords identified and flagged with medium-priority recommendation"
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // Section 3: Prioritization and Healthy Vaults
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n── Section 3: Prioritization and Healthy Vaults ──");

  // Test 6: Correct prioritization (CRITICAL for reused weak passwords)
  const compoundItems = [
    makeItem("1", "Weak Reused 1", "qwerty"), // Reused AND weak
    makeItem("2", "Weak Reused 2", "qwerty"), // Reused AND weak
    makeItem("3", "Just Weak", "123456"),     // Weak only
    makeItem("4", "Missing One", ""),         // Missing
  ];
  const compoundMetrics = computeVaultMetrics(compoundItems);
  const compoundAnalysis = analyzeVaultSecurity(compoundItems, compoundMetrics);
  assert(
    compoundAnalysis.recommendations[0].priority === "CRITICAL" &&
    compoundAnalysis.topPriority?.priority === "CRITICAL" &&
    compoundAnalysis.topPriority?.id === "critical-reused-weak-passwords",
    "Compounded reused-weak password assigned CRITICAL priority above all other issues"
  );

  // Verify priority ordering: CRITICAL -> HIGH -> MEDIUM -> LOW
  const priorityOrder = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, POSITIVE: 5 };
  let isStrictlySorted = true;
  for (let i = 0; i < compoundAnalysis.recommendations.length - 1; i++) {
    const pCurrent = priorityOrder[compoundAnalysis.recommendations[i].priority];
    const pNext = priorityOrder[compoundAnalysis.recommendations[i + 1].priority];
    if (pCurrent > pNext) {
      isStrictlySorted = false;
      break;
    }
  }
  assert(isStrictlySorted, "Recommendations are strictly ordered from highest to lowest priority");

  // Test 7: Correct recommendations for a healthy vault
  const healthyItems = [
    makeItem("1", "Bank A", "k9#mW$82vL!zQ4pT*rY6"),
    makeItem("2", "Work Mail", "d7&sH@91cN#xR5mK!tW3"),
    makeItem("3", "Cloud Storage", "p2$vB*64zF!mL8tQ#wX9"),
  ];
  const healthyMetrics = computeVaultMetrics(healthyItems);
  const healthyAnalysis = analyzeVaultSecurity(healthyItems, healthyMetrics);
  assert(
    healthyAnalysis.weakCount === 0 &&
    healthyAnalysis.reusedPasswordCount === 0 &&
    healthyAnalysis.missingPasswordCount === 0 &&
    healthyAnalysis.recommendations.some(r => r.priority === "POSITIVE") &&
    healthyAnalysis.positiveNotes.length > 0,
    "Healthy vault generates POSITIVE recommendation and recognizes strong hygiene"
  );

  const healthyFixResponse = getAssistantResponse("Which passwords should I improve first?", healthyAnalysis);
  assert(
    healthyFixResponse.text.includes("great shape") &&
    healthyFixResponse.text.includes("0 weak passwords") &&
    healthyFixResponse.text.includes("0 reused passwords"),
    "Improve-first query on healthy vault accurately confirms 0 issues to fix"
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // Section 4: Privacy, Zero-Knowledge & Boundary Guarantees
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n── Section 4: Privacy, Zero-Knowledge & Boundary Guarantees ──");

  // Test 8: No exposure of actual password values anywhere
  const SENSITIVE_PASSWORDS = [
    "MySuperSecretP@ssword123",
    "P@ssw0rd999!DoNotLeak",
    "qwerty12345",
  ];
  const privacyItems = [
    makeItem("1", "Email Account", SENSITIVE_PASSWORDS[0]),
    makeItem("2", "Finance Account", SENSITIVE_PASSWORDS[0]), // Reused
    makeItem("3", "Social Account", SENSITIVE_PASSWORDS[2]),   // Weak
  ];
  const privacyMetrics = computeVaultMetrics(privacyItems);
  const privacyAnalysis = analyzeVaultSecurity(privacyItems, privacyMetrics);

  let leaksSecret = false;
  for (const rec of privacyAnalysis.recommendations) {
    for (const pwd of SENSITIVE_PASSWORDS) {
      if (rec.title.includes(pwd) || rec.desc.includes(pwd) || rec.actionText.includes(pwd)) {
        leaksSecret = true;
      }
    }
  }
  assert(!leaksSecret, "Zero raw password strings exist in generated recommendations");

  const privacyQuestions = [
    "How secure is my vault?",
    "Which passwords should I improve first?",
    "Do I have reused passwords?",
    "How can I improve my security score?",
    "What should I fix first?",
    "Are there any weak passwords?",
    "What does my vault health mean?",
    "What should I do next?",
  ];

  let conversationalLeak = false;
  for (const q of privacyQuestions) {
    const res = getAssistantResponse(q, privacyAnalysis);
    for (const pwd of SENSITIVE_PASSWORDS) {
      if (res.text.includes(pwd)) {
        conversationalLeak = true;
      }
    }
  }
  assert(!conversationalLeak, "Zero raw password strings appear in conversational answers across all prompts");

  // Test 9: No false claims of breach detection or external threat intelligence
  const allAssistantOutputs = privacyQuestions.map(q => getAssistantResponse(q, privacyAnalysis).text);
  const forbiddenPhrases = [
    "dark web",
    "haveibeenpwned",
    "breach database",
    "malware detected",
    "compromised in a breach",
    "real-time attack",
    "threat intelligence feed",
  ];

  let hasForbiddenClaim = false;
  for (const output of allAssistantOutputs) {
    for (const phrase of forbiddenPhrases) {
      if (output.toLowerCase().includes(phrase)) {
        hasForbiddenClaim = true;
      }
    }
  }
  assert(!hasForbiddenClaim, "Zero false claims of external breach monitoring or dark-web detection");

  // ─────────────────────────────────────────────────────────────────────────────
  // Section 5: State Machine Lifecycle & Memory Invariants
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n── Section 5: State Machine Lifecycle & Memory Invariants ──");

  // Test 10: Account-switch context isolation
  const userAItems = [makeItem("1", "User A Bank", "BankPass#123456789")];
  const userBItems = [makeItem("2", "User B Gaming", "GamingPass!987654321")];

  const analysisUserA = analyzeVaultSecurity(userAItems, computeVaultMetrics(userAItems), { userEmail: "a@test.com" });
  const analysisUserB = analyzeVaultSecurity(userBItems, computeVaultMetrics(userBItems), { userEmail: "b@test.com" });

  assert(
    analysisUserA.weakServices.length === 0 &&
    analysisUserA.totalEntries === 1 &&
    analysisUserB.totalEntries === 1 &&
    !getAssistantResponse("How secure is my vault?", analysisUserA).text.includes("Gaming") &&
    !getAssistantResponse("How secure is my vault?", analysisUserB).text.includes("Bank"),
    "Account-switch: User A and User B assistant analyses maintain strict mutual isolation"
  );

  // Test 11: Lock/logout context clearing
  const lockedClearedAnalysis = analyzeVaultSecurity(userAItems, getLockedVaultMetrics(), { isLocked: true });
  assert(
    lockedClearedAnalysis.recommendations.length === 0 &&
    lockedClearedAnalysis.topPriority === null &&
    lockedClearedAnalysis.weakServices.length === 0 &&
    lockedClearedAnalysis.reusedGroups.length === 0 &&
    lockedClearedAnalysis.staleServices.length === 0,
    "Vault lock immediately purges all recommendations and service references from analysis state"
  );

  // Test 12: Recalculation when vault contents change
  const initialItems = [makeItem("1", "Streaming Service", "123456")]; // 1 weak item
  const initialAnalysis = analyzeVaultSecurity(initialItems, computeVaultMetrics(initialItems));
  assert(initialAnalysis.weakCount === 1, "Initial vault has 1 weak password");

  // Replace with updated strong password
  const updatedItems = [makeItem("1", "Streaming Service", "X8#vK2$zL9!mQ4@rT7*pW1")];
  const updatedAnalysis = analyzeVaultSecurity(updatedItems, computeVaultMetrics(updatedItems));
  assert(
    updatedAnalysis.weakCount === 0 &&
    (updatedAnalysis.healthScore ?? 0) > (initialAnalysis.healthScore ?? 0),
    "Vault update dynamically eliminates weak password and recalculates health score"
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // Section 6: Edge Cases, Robustness & Network Freedom
  // ─────────────────────────────────────────────────────────────────────────────
  console.log("\n── Section 6: Edge Cases, Robustness & Network Freedom ──");

  // Test 13: Malformed and incomplete record handling
  const malformedItems: any[] = [
    null,
    undefined,
    {},
    { id: "bad-1" }, // No service, no password
    { id: "bad-2", service: "   ", password: null }, // Blank service, null password
    { id: "bad-3", service: 12345, password: ["array"] }, // Bad types
    { id: "bad-4", service: "Stale App", password: "SomePass#123", updatedAt: "not-a-real-date" },
    { id: "stale-valid", service: "Old Email", password: "OldPass#123", updatedAt: "2020-01-01T00:00:00Z" }, // Valid stale
  ];

  let threwMalformed = false;
  let malformedAnalysis: VaultAssistantAnalysis | null = null;
  try {
    const malformedMetrics = computeVaultMetrics(malformedItems);
    malformedAnalysis = analyzeVaultSecurity(malformedItems, malformedMetrics);
  } catch (err) {
    threwMalformed = true;
  }
  assert(!threwMalformed && malformedAnalysis !== null, "Malformed and incomplete items handled gracefully without crashing");
  assert(malformedAnalysis?.staleServices.includes("Old Email") === true, "Valid historical timestamp recognized as stale without error");

  // Test 14: Immutability: zero mutation of original vault records
  const immutableInput = [
    makeItem("imm-1", "Untouched Service", "Secret$123456789"),
  ];
  const clonedSnapshot = JSON.stringify(immutableInput);
  analyzeVaultSecurity(immutableInput, computeVaultMetrics(immutableInput));
  assert(JSON.stringify(immutableInput) === clonedSnapshot, "Input vault records are 100% immutable and unmutated by analysis");

  // Test 15: Zero external network dependency (runs with network/fetch disabled)
  const originalFetch = globalThis.fetch;
  let fetchAttempted = false;
  (globalThis as any).fetch = () => {
    fetchAttempted = true;
    throw new Error("Security violation: assistant attempted network access!");
  };

  try {
    const netTestAnalysis = analyzeVaultSecurity(privacyItems, privacyMetrics);
    for (const q of DEFAULT_SUGGESTED_PROMPTS) {
      getAssistantResponse(q, netTestAnalysis);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert(!fetchAttempted, "Assistant analysis executes 100% client-side with zero network calls");

  // Test 16: Non-regression of standard assistant questions and follow-ups
  const standardQuestions = [
    "How secure is my vault?",
    "Which passwords should I improve first?",
    "Do I have reused passwords?",
    "How can I improve my security score?",
    "What should I fix first?",
    "Are there any weak passwords?",
    "What does my vault health mean?",
    "What should I do next?",
  ];

  let allQuestionsHandled = true;
  for (const question of standardQuestions) {
    const res = getAssistantResponse(question, privacyAnalysis);
    if (!res || !res.text || res.text.trim().length === 0 || !Array.isArray(res.followUps) || res.followUps.length === 0) {
      allQuestionsHandled = false;
      break;
    }
  }
  assert(allQuestionsHandled, "All 8 required specification questions return actionable text with follow-ups");

  // Test 17: Contextual prompt adaptation
  const contextualEmptyPrompts = getContextualSuggestedPrompts(emptyAnalysis);
  const contextualWeakPrompts = getContextualSuggestedPrompts(weakAnalysis);
  const contextualReusedPrompts = getContextualSuggestedPrompts(reusedAnalysis);
  assert(
    contextualEmptyPrompts.includes("How do I add an entry?") &&
    contextualWeakPrompts.includes("Which passwords should I improve first?") &&
    contextualReusedPrompts.includes("Do I have reused passwords?"),
    "Suggested prompt chips dynamically adapt to the user's specific vault condition"
  );

  // Test 18: Zero-Knowledge & AI privacy inquiry
  const aiPrivacyResponse = getAssistantResponse("Is my data sent to an AI service?", privacyAnalysis);
  assert(
    aiPrivacyResponse.text.includes("100% Local Execution") &&
    aiPrivacyResponse.text.includes("Zero External AI Services") &&
    aiPrivacyResponse.topic === "privacy",
    "Direct privacy question explains 100% local rule-based execution and absence of external AI"
  );

  console.log("\n================================================================================");
  console.log(`Phase 10.5 Verification Complete: ${passed} Passed, ${failed} Failed`);
  console.log("================================================================================\n");

  if (failed > 0) {
    process.exit(1);
  }
}

run().catch(err => {
  console.error("Unhandled exception in Phase 10.5 verification suite:", err);
  process.exit(1);
});
