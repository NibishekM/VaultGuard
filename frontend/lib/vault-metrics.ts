/**
 * VaultGuard – Live Vault Health & Metrics Engine (Phase 10.2)
 *
 * Provides pure, zero-knowledge, local computation of password health analytics
 * derived strictly from decrypted vault items held in memory.
 *
 * Privacy & Security Guarantees:
 * - 100% computed client-side in browser memory.
 * - Decrypted passwords and metrics are NEVER sent to the backend or logged.
 * - Zero persistence in localStorage, sessionStorage, or IndexedDB.
 * - Password reuse detection performs strict case-sensitive, untrimmed comparisons.
 * - Missing or blank passwords are never classified as strong.
 * - When vault is locked or empty, returns honest non-fabricated states.
 */

import { analyzePassword } from "./password-tools";
import type { DecryptedVaultItem } from "./crypto/types";

export interface VaultMetrics {
  /** Total count of all items saved in the vault */
  totalEntries: number;
  /** Count of entries containing non-empty, usable password strings */
  usablePasswordEntries: number;
  /** Count of entries where the password is missing, undefined, or empty */
  missingPasswordCount: number;
  /** Count of usable passwords classified as Weak (score < 48) */
  weakCount: number;
  /** Count of usable passwords classified as Fair / Moderate (48 <= score < 70) */
  fairCount: number;
  /** Count of usable passwords classified as Strong (score >= 70) */
  strongCount: number;
  /** Count of distinct password values that are reused across 2 or more accounts */
  reusedPasswordCount: number;
  /** Total number of accounts/entries affected by password reuse */
  affectedAccountsCount: number;
  /** Overall vault health score (0-100 integer), or null when vault is empty/locked */
  healthScore: number | null;
  /** Formatted health breakdown for UI distribution bars */
  healthBreakdown: [
    { label: "Strong"; count: number; color: string },
    { label: "Moderate"; count: number; color: string },
    { label: "Weak"; count: number; color: string }
  ];
  /** Whether the vault is currently locked */
  isLocked: boolean;
  /** Whether the vault contains zero saved items */
  isEmpty: boolean;
}

/**
 * Computes comprehensive health and security metrics from an array of decrypted vault items.
 *
 * @param items Array of decrypted vault items from VaultContext
 * @param options Optional configuration (e.g. isLocked flag)
 * @returns Fully typed, immutable VaultMetrics object
 */
export function computeVaultMetrics(
  items: Array<Partial<DecryptedVaultItem> | Record<string, any>>,
  options?: { isLocked?: boolean }
): VaultMetrics {
  if (options?.isLocked) {
    return getLockedVaultMetrics();
  }

  const totalEntries = items.length;
  if (totalEntries === 0) {
    return getEmptyVaultMetrics();
  }

  let usablePasswordEntries = 0;
  let missingPasswordCount = 0;
  let weakCount = 0;
  let fairCount = 0;
  let strongCount = 0;
  let totalRawScore = 0;

  // Exact password occurrence map for case-sensitive, untrimmed reuse comparison
  const passwordCounts = new Map<string, number>();

  for (const item of items) {
    const pwd = item?.password;
    if (typeof pwd === "string" && pwd.length > 0) {
      usablePasswordEntries++;
      // Count exact character match without normalization (preserves case, spaces, symbols)
      passwordCounts.set(pwd, (passwordCounts.get(pwd) || 0) + 1);

      // Analyze password strength using deterministic scoring
      const analysis = analyzePassword(pwd);
      totalRawScore += analysis.score;

      // Deterministic classification thresholds:
      // Strong: score >= 70 (Strong & Excellent)
      // Fair:   48 <= score < 70 (Moderate)
      // Weak:   score < 48 (Weak & Very Weak)
      if (analysis.score >= 70) {
        strongCount++;
      } else if (analysis.score >= 48) {
        fairCount++;
      } else {
        weakCount++;
      }
    } else {
      // Missing or blank password values are tracked separately and NEVER classified as strong
      missingPasswordCount++;
    }
  }

  // Calculate duplicate password groups and affected accounts
  let reusedPasswordCount = 0;
  let affectedAccountsCount = 0;

  for (const [, count] of passwordCounts.entries()) {
    if (count > 1) {
      reusedPasswordCount++;
      affectedAccountsCount += count;
    }
  }

  // Calculate Overall Health Score (0-100)
  let healthScore: number | null = null;

  if (usablePasswordEntries > 0) {
    // analyzePassword produces a max raw score of 86 for an Excellent password.
    // We scale the average raw score to a standard 0-100 baseline.
    const averageRawScore = totalRawScore / usablePasswordEntries;
    const scaledBaseScore = Math.min(100, (averageRawScore / 86) * 100);

    // Reuse penalty: up to 35 points based on proportion of accounts with reused passwords,
    // plus 3 points per duplicate group beyond the first (capped at 15 extra points)
    const reuseRatio = affectedAccountsCount / usablePasswordEntries;
    const extraGroupPenalty = reusedPasswordCount > 1 ? Math.min(15, (reusedPasswordCount - 1) * 3) : 0;
    const reusePenalty = Math.round(reuseRatio * 35) + extraGroupPenalty;

    // Weak password penalty: up to 30 points based on proportion of weak passwords
    const weakRatio = weakCount / usablePasswordEntries;
    const weakPenalty = Math.round(weakRatio * 30);

    // Missing password penalty: up to 20 points based on proportion of missing passwords in vault
    const missingRatio = missingPasswordCount / totalEntries;
    const missingPenalty = Math.round(missingRatio * 20);

    const calculated = Math.round(scaledBaseScore - reusePenalty - weakPenalty - missingPenalty);
    // Strict boundary enforcement: always clamped between 0 and 100
    healthScore = Math.max(0, Math.min(100, calculated));
  } else {
    // If there are entries but none have usable passwords, health score is 0 (unprotected accounts)
    healthScore = 0;
  }

  return {
    totalEntries,
    usablePasswordEntries,
    missingPasswordCount,
    weakCount,
    fairCount,
    strongCount,
    reusedPasswordCount,
    affectedAccountsCount,
    healthScore,
    healthBreakdown: [
      { label: "Strong", count: strongCount, color: "#45D6A0" },
      { label: "Moderate", count: fairCount, color: "#9275F5" },
      { label: "Weak", count: weakCount, color: "#E9AA62" }
    ],
    isLocked: false,
    isEmpty: false
  };
}

/**
 * Returns an honest metrics object representing a locked vault state.
 * Never displays cached credentials, previous account data, or fabricated scores.
 */
export function getLockedVaultMetrics(): VaultMetrics {
  return {
    totalEntries: 0,
    usablePasswordEntries: 0,
    missingPasswordCount: 0,
    weakCount: 0,
    fairCount: 0,
    strongCount: 0,
    reusedPasswordCount: 0,
    affectedAccountsCount: 0,
    healthScore: null,
    healthBreakdown: [
      { label: "Strong", count: 0, color: "#45D6A0" },
      { label: "Moderate", count: 0, color: "#9275F5" },
      { label: "Weak", count: 0, color: "#E9AA62" }
    ],
    isLocked: true,
    isEmpty: true
  };
}

/**
 * Returns an honest metrics object representing an unlocked but empty vault.
 */
export function getEmptyVaultMetrics(): VaultMetrics {
  return {
    totalEntries: 0,
    usablePasswordEntries: 0,
    missingPasswordCount: 0,
    weakCount: 0,
    fairCount: 0,
    strongCount: 0,
    reusedPasswordCount: 0,
    affectedAccountsCount: 0,
    healthScore: null,
    healthBreakdown: [
      { label: "Strong", count: 0, color: "#45D6A0" },
      { label: "Moderate", count: 0, color: "#9275F5" },
      { label: "Weak", count: 0, color: "#E9AA62" }
    ],
    isLocked: false,
    isEmpty: true
  };
}
