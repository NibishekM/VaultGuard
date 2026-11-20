/**
 * VaultGuard – Contextual Security Assistant Engine (Phase 10.5)
 *
 * Provides pure, zero-knowledge, local contextual recommendations and conversational
 * security guidance derived strictly from the active user's decrypted vault items and metrics.
 *
 * Privacy & Security Guarantees:
 * - 100% computed client-side in browser memory.
 * - Decrypted passwords and vault records are NEVER transmitted to any external AI service,
 *   third-party API, backend endpoint, analytics tracker, or remote logger.
 * - Actual password values are NEVER included in recommendations or conversational responses.
 * - Does not infer that a password is breached merely because it is weak or reused.
 * - Does not falsely claim to monitor the dark web, check breach databases, or detect real-time attacks.
 * - When vault is locked or empty, provides honest non-fabricated states.
 * - Supports instant context clearing on lock, logout, session expiration, and account switching.
 */

import { analyzePassword } from "./password-tools";
import type { VaultMetrics } from "./vault-metrics";
import type { DecryptedVaultItem } from "./crypto/types";

export type AssistantPriority = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "POSITIVE";
export type PriorityTone = "rose" | "amber" | "violet" | "green" | "cyan";

export interface AssistantRecommendation {
  id: string;
  title: string;
  priority: AssistantPriority;
  tone: PriorityTone;
  desc: string;
  actionText: string;
  affectedCount?: number;
  affectedServices?: string[];
}

export interface ReusedGroupSummary {
  serviceNames: string[];
  count: number;
  isWeak: boolean;
}

export interface VaultAssistantAnalysis {
  isLocked: boolean;
  isEmpty: boolean;
  totalEntries: number;
  usablePasswordEntries: number;
  healthScore: number | null;
  weakCount: number;
  reusedPasswordCount: number;
  affectedAccountsCount: number;
  missingPasswordCount: number;
  stalePasswordCount: number;
  recommendations: AssistantRecommendation[];
  topPriority: AssistantRecommendation | null;
  positiveNotes: string[];
  reusedGroups: ReusedGroupSummary[];
  weakServices: string[];
  missingServices: string[];
  staleServices: string[];
}

export interface AssistantResponse {
  text: string;
  followUps: string[];
  topic: string;
}

const STALE_THRESHOLD_DAYS = 180; // 6 months

/**
 * Deterministically analyzes decrypted vault records and precomputed metrics to produce
 * prioritized, actionable contextual security guidance.
 *
 * @param items Array of decrypted vault items from VaultContext
 * @param metrics Authoritative VaultMetrics computed for the active vault
 * @param options Contextual options such as locked state and active account identifier
 */
export function analyzeVaultSecurity(
  items: Array<Partial<DecryptedVaultItem> | Record<string, any>>,
  metrics: VaultMetrics,
  options?: { isLocked?: boolean; userEmail?: string }
): VaultAssistantAnalysis {
  const isLocked = Boolean(options?.isLocked || metrics.isLocked);

  if (isLocked) {
    return {
      isLocked: true,
      isEmpty: true,
      totalEntries: 0,
      usablePasswordEntries: 0,
      healthScore: null,
      weakCount: 0,
      reusedPasswordCount: 0,
      affectedAccountsCount: 0,
      missingPasswordCount: 0,
      stalePasswordCount: 0,
      recommendations: [],
      topPriority: null,
      positiveNotes: [],
      reusedGroups: [],
      weakServices: [],
      missingServices: [],
      staleServices: [],
    };
  }

  const totalEntries = items.length;
  if (totalEntries === 0 || metrics.isEmpty) {
    const emptyRec: AssistantRecommendation = {
      id: "empty-vault-add-first",
      title: "Add your first account entry",
      priority: "LOW",
      tone: "cyan",
      desc: "Your vault is currently empty. Add login credentials or import an encrypted backup to start receiving personalized security guidance.",
      actionText: "Click '+ Add Entry' in your vault to save your first account.",
      affectedCount: 0,
      affectedServices: [],
    };

    return {
      isLocked: false,
      isEmpty: true,
      totalEntries: 0,
      usablePasswordEntries: 0,
      healthScore: null,
      weakCount: 0,
      reusedPasswordCount: 0,
      affectedAccountsCount: 0,
      missingPasswordCount: 0,
      stalePasswordCount: 0,
      recommendations: [emptyRec],
      topPriority: emptyRec,
      positiveNotes: ["Zero-knowledge encryption engine is active and ready."],
      reusedGroups: [],
      weakServices: [],
      missingServices: [],
      staleServices: [],
    };
  }

  const weakServices: string[] = [];
  const missingServices: string[] = [];
  const staleServices: string[] = [];
  const passwordToServices = new Map<string, string[]>();
  const passwordToIsWeak = new Map<string, boolean>();

  const nowMs = Date.now();
  const staleCutoffMs = nowMs - STALE_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;

  for (const item of items) {
    const serviceName = (typeof item?.service === "string" && item.service.trim().length > 0)
      ? item.service.trim()
      : "Unnamed Account";

    const pwd = item?.password;
    if (typeof pwd === "string" && pwd.length > 0) {
      // Analyze strength using existing password analyzer
      const analysis = analyzePassword(pwd);
      const isWeak = analysis.score < 48;

      if (isWeak) {
        if (!weakServices.includes(serviceName)) {
          weakServices.push(serviceName);
        }
      }

      // Group exact case-sensitive, untrimmed password for reuse detection
      const existing = passwordToServices.get(pwd) || [];
      existing.push(serviceName);
      passwordToServices.set(pwd, existing);
      passwordToIsWeak.set(pwd, isWeak);

      // Check for reliable age if valid ISO timestamp exists
      const timestamp = item?.updatedAt || item?.createdAt;
      if (timestamp) {
        const dateObj = new Date(timestamp);
        if (!isNaN(dateObj.getTime()) && dateObj.getTime() < staleCutoffMs) {
          if (!staleServices.includes(serviceName)) {
            staleServices.push(serviceName);
          }
        }
      }
    } else {
      if (!missingServices.includes(serviceName)) {
        missingServices.push(serviceName);
      }
    }
  }

  // Identify duplicate password groups (without leaking password text)
  const reusedGroups: ReusedGroupSummary[] = [];
  let criticalReusedWeakCount = 0;

  for (const [pwd, serviceNames] of passwordToServices.entries()) {
    if (serviceNames.length > 1) {
      const isWeak = Boolean(passwordToIsWeak.get(pwd));
      if (isWeak) {
        criticalReusedWeakCount++;
      }
      reusedGroups.push({
        serviceNames,
        count: serviceNames.length,
        isWeak,
      });
    }
  }

  // Construct structured, prioritized recommendations
  const recommendations: AssistantRecommendation[] = [];
  const positiveNotes: string[] = [];

  // 1. CRITICAL PRIORITY: Reused Weak Passwords or 0 Usable Passwords with multiple items
  if (criticalReusedWeakCount > 0) {
    const affectedGroupServices = Array.from(
      new Set(reusedGroups.filter(g => g.isWeak).flatMap(g => g.serviceNames))
    );
    recommendations.push({
      id: "critical-reused-weak-passwords",
      title: "Urgent: Reused weak passwords",
      priority: "CRITICAL",
      tone: "rose",
      desc: `${affectedGroupServices.length} accounts share a password that is both reused and below minimum complexity standards. Compounded reuse of weak passwords presents the highest risk of credential stuffing.`,
      actionText: `Immediately generate unique, high-entropy passwords for ${formatServiceList(affectedGroupServices)}.`,
      affectedCount: affectedGroupServices.length,
      affectedServices: affectedGroupServices,
    });
  } else if (metrics.usablePasswordEntries === 0 && totalEntries >= 2) {
    recommendations.push({
      id: "critical-all-accounts-missing-passwords",
      title: "All vault accounts lack passwords",
      priority: "CRITICAL",
      tone: "rose",
      desc: "Multiple account records are saved in your vault, but none contain stored passwords. Accounts cannot be autofilled or protected without stored credentials.",
      actionText: "Edit your vault entries and add passwords or generate new ones.",
      affectedCount: totalEntries,
      affectedServices: missingServices,
    });
  }

  // 2. HIGH PRIORITY: Reused Passwords (if not already handled as critical)
  if (metrics.reusedPasswordCount > 0 && criticalReusedWeakCount === 0) {
    const allReusedServices = Array.from(new Set(reusedGroups.flatMap(g => g.serviceNames)));
    recommendations.push({
      id: "high-reused-passwords",
      title: "Eliminate password reuse",
      priority: "HIGH",
      tone: "amber",
      desc: `${metrics.affectedAccountsCount} accounts share ${metrics.reusedPasswordCount} identical password${metrics.reusedPasswordCount === 1 ? "" : "s"}. If one of these services experiences a data breach, all other accounts sharing the password are vulnerable.`,
      actionText: `Update ${formatServiceList(allReusedServices)} with unique passwords using the inline generator.`,
      affectedCount: metrics.affectedAccountsCount,
      affectedServices: allReusedServices,
    });
  }

  // 3. HIGH PRIORITY: Weak Passwords
  if (metrics.weakCount > 0) {
    recommendations.push({
      id: "high-weak-passwords",
      title: "Replace weak passwords",
      priority: "HIGH",
      tone: "amber",
      desc: `${metrics.weakCount} password${metrics.weakCount === 1 ? " falls" : "s fall"} below the 12-character and multi-character complexity threshold. Short or predictable passwords can be compromised quickly.`,
      actionText: `Strengthen ${formatServiceList(weakServices)} by generating 20+ character passphrases or passwords.`,
      affectedCount: metrics.weakCount,
      affectedServices: weakServices,
    });
  }

  // 4. MEDIUM PRIORITY: Missing Passwords
  if (metrics.missingPasswordCount > 0 && !(metrics.usablePasswordEntries === 0 && totalEntries >= 2)) {
    recommendations.push({
      id: "medium-missing-passwords",
      title: "Store missing credentials",
      priority: "MEDIUM",
      tone: "violet",
      desc: `${metrics.missingPasswordCount} entry has no password stored. Unprotected accounts cannot be automatically verified or checked for security hygiene.`,
      actionText: `Add stored passwords for ${formatServiceList(missingServices)}.`,
      affectedCount: metrics.missingPasswordCount,
      affectedServices: missingServices,
    });
  }

  // 5. MEDIUM PRIORITY: Fair / Moderate Passwords (when no weak passwords exist)
  if (metrics.fairCount > 0 && metrics.weakCount === 0 && metrics.reusedPasswordCount === 0) {
    recommendations.push({
      id: "medium-upgrade-moderate-passwords",
      title: "Strengthen moderate passwords",
      priority: "MEDIUM",
      tone: "violet",
      desc: `${metrics.fairCount} password${metrics.fairCount === 1 ? " has" : "s have"} moderate complexity. Increasing length to 16–20 characters and adding symbols will maximize your security score.`,
      actionText: "Use the password generator to increase password lengths beyond 16 characters.",
      affectedCount: metrics.fairCount,
      affectedServices: [],
    });
  }

  // 6. MEDIUM PRIORITY: Stale Passwords (older than 6 months with reliable timestamps)
  if (staleServices.length > 0) {
    recommendations.push({
      id: "medium-stale-passwords",
      title: "Review older credentials",
      priority: "MEDIUM",
      tone: "violet",
      desc: `${staleServices.length} account${staleServices.length === 1 ? " hasn't" : "s haven't"} been updated in over 6 months. Periodic review helps ensure secondary factors and contact emails remain current.`,
      actionText: `Review credentials and active 2FA options for ${formatServiceList(staleServices)}.`,
      affectedCount: staleServices.length,
      affectedServices: staleServices,
    });
  }

  // 7. LOW PRIORITY: General Hygiene
  recommendations.push({
    id: "low-multi-factor-authentication",
    title: "Enable multi-factor authentication",
    priority: "LOW",
    tone: "cyan",
    desc: "Passwords alone can be intercepted on compromised networks. Enabling two-factor authentication (TOTP or hardware keys) prevents unauthorized access even if a password is exposed.",
    actionText: "Configure an authenticator app or security key on your primary email, banking, and cloud accounts.",
    affectedCount: 0,
    affectedServices: [],
  });

  recommendations.push({
    id: "low-encrypted-vault-backup",
    title: "Maintain an encrypted backup",
    priority: "LOW",
    tone: "cyan",
    desc: "VaultGuard uses zero-knowledge AES-256-GCM encryption. Storing a periodic offline encrypted backup file protects against accidental device loss.",
    actionText: "Navigate to Settings > Sync & backup and export a zero-knowledge encrypted backup.",
    affectedCount: 0,
    affectedServices: [],
  });

  // Positive Security Observations
  if (metrics.reusedPasswordCount === 0 && metrics.usablePasswordEntries > 0) {
    positiveNotes.push("Zero password reuse: Every saved credential is completely unique across accounts.");
  }
  if (metrics.weakCount === 0 && metrics.usablePasswordEntries > 0) {
    positiveNotes.push("No weak passwords: All analyzed passwords satisfy strong complexity standards.");
  }
  if (metrics.healthScore !== null && metrics.healthScore >= 80) {
    positiveNotes.push(`Excellent health score: Your vault score is ${metrics.healthScore}/100.`);
  }
  if (metrics.missingPasswordCount === 0 && metrics.totalEntries > 0) {
    positiveNotes.push("Complete vault coverage: 100% of saved vault entries have stored passwords.");
  }

  // If vault is clean (no critical, high, or medium issues), surface a positive recommendation card
  if (metrics.weakCount === 0 && metrics.reusedPasswordCount === 0 && metrics.missingPasswordCount === 0) {
    const positiveRec: AssistantRecommendation = {
      id: "positive-great-vault-hygiene",
      title: "Strong vault security hygiene",
      priority: "POSITIVE",
      tone: "green",
      desc: "All saved credentials in your vault are unique and strong. You have zero weak passwords and zero duplicates.",
      actionText: "Continue using the inline password generator when registering for new online services.",
      affectedCount: metrics.totalEntries,
      affectedServices: [],
    };
    recommendations.unshift(positiveRec);
  }

  const topPriority = recommendations.length > 0 ? recommendations[0] : null;

  return {
    isLocked: false,
    isEmpty: false,
    totalEntries,
    usablePasswordEntries: metrics.usablePasswordEntries,
    healthScore: metrics.healthScore,
    weakCount: metrics.weakCount,
    reusedPasswordCount: metrics.reusedPasswordCount,
    affectedAccountsCount: metrics.affectedAccountsCount,
    missingPasswordCount: metrics.missingPasswordCount,
    stalePasswordCount: staleServices.length,
    recommendations,
    topPriority,
    positiveNotes,
    reusedGroups,
    weakServices,
    missingServices,
    staleServices,
  };
}

/**
 * Helper to format a list of service names gracefully for display (e.g. "GitHub, Google, and Slack").
 * Guarantees zero password text is ever printed.
 */
function formatServiceList(services: string[], maxDisplay = 3): string {
  if (!services || services.length === 0) return "your affected accounts";
  const sanitized = services.map(s => s.trim().slice(0, 30));
  if (sanitized.length === 1) return sanitized[0];
  if (sanitized.length === 2) return `${sanitized[0]} and ${sanitized[1]}`;
  const displayed = sanitized.slice(0, maxDisplay);
  const remaining = sanitized.length - maxDisplay;
  if (remaining > 0) {
    return `${displayed.join(", ")}, and ${remaining} other${remaining === 1 ? "" : "s"}`;
  }
  return `${displayed.slice(0, -1).join(", ")}, and ${displayed[displayed.length - 1]}`;
}

/**
 * Standard suggested prompt questions offered to the user in the Assistant interface.
 */
export const DEFAULT_SUGGESTED_PROMPTS = [
  "How secure is my vault?",
  "Which passwords should I improve first?",
  "Do I have reused passwords?",
  "How can I improve my security score?",
  "What should I fix first?",
  "Are there any weak passwords?",
  "What does my vault health mean?",
  "What should I do next?",
];

/**
 * Generates dynamic, context-aware suggested prompts tailored to the current vault condition.
 */
export function getContextualSuggestedPrompts(analysis: VaultAssistantAnalysis): string[] {
  if (analysis.isLocked) {
    return [
      "How do I unlock my vault?",
      "What is zero knowledge?",
      "Is my data sent to an AI?",
    ];
  }

  if (analysis.isEmpty) {
    return [
      "How do I add an entry?",
      "How can I import my passwords?",
      "What is zero knowledge?",
    ];
  }

  const prompts: string[] = [];

  if (analysis.reusedPasswordCount > 0) {
    prompts.push("Do I have reused passwords?");
  }
  if (analysis.weakCount > 0) {
    prompts.push("Which passwords should I improve first?");
  }
  if (analysis.healthScore !== null && analysis.healthScore < 80) {
    prompts.push("How can I improve my security score?");
  } else {
    prompts.push("How secure is my vault?");
  }

  prompts.push("What should I do next?");
  prompts.push("What does my vault health mean?");

  return prompts.slice(0, 4);
}

/**
 * Generates an honest, deterministic, contextual assistant response for any given user query.
 * Executes 100% locally with zero external network or AI dependencies.
 *
 * @param query The user's input question or selected prompt
 * @param analysis The active VaultAssistantAnalysis derived from the user's unlocked vault
 * @param context Optional display metadata like username
 */
export function getAssistantResponse(
  query: string,
  analysis: VaultAssistantAnalysis,
  context?: { userName?: string }
): AssistantResponse {
  const q = query.trim().toLowerCase();

  // 1. Locked Vault Invariant Check
  if (analysis.isLocked) {
    return {
      text: "Your vault is currently locked. To safeguard your zero-knowledge privacy, credentials and health metrics are completely inaccessible in memory until you unlock your vault with your master password.",
      followUps: ["How do I unlock my vault?", "What is zero knowledge?"],
      topic: "locked_vault",
    };
  }

  // 2. Empty Vault Invariant Check
  if (analysis.isEmpty) {
    return {
      text: "Your vault is currently empty with 0 saved entries. To evaluate your password strength, detect potential reuse, and receive personalized recommendations, add your first account entry using '+ Add Entry' or import an encrypted backup from Settings.",
      followUps: ["How do I add an entry?", "What is zero knowledge?"],
      topic: "empty_vault",
    };
  }

  // 3. Question: "How secure is my vault?" / "How safe is my vault?" / "What is my health score?"
  if (
    q.includes("how secure") ||
    q.includes("how safe") ||
    q.includes("vault security") ||
    q.includes("vault safe") ||
    q.includes("my security score") ||
    q.includes("my health score")
  ) {
    const score = analysis.healthScore ?? 0;
    let scoreAssessment = "";
    if (score >= 80) {
      scoreAssessment = `Your overall vault health score is **${score}/100 (Strong)**. All or nearly all of your saved credentials have high entropy and zero duplicate usage.`;
    } else if (score >= 50) {
      scoreAssessment = `Your overall vault health score is **${score}/100 (Moderate)**. While your core encryption is secure, your score is lowered by ${
        analysis.reusedPasswordCount > 0 ? `${analysis.affectedAccountsCount} accounts with reused passwords` : ""
      }${
        analysis.reusedPasswordCount > 0 && analysis.weakCount > 0 ? " and " : ""
      }${
        analysis.weakCount > 0 ? `${analysis.weakCount} weak passwords` : ""
      }.`;
    } else {
      scoreAssessment = `Your overall vault health score is **${score}/100 (Needs Improvement)**. You have significant vulnerabilities including ${
        analysis.weakCount > 0 ? `${analysis.weakCount} weak passwords` : ""
      }${
        analysis.weakCount > 0 && analysis.reusedPasswordCount > 0 ? " and " : ""
      }${
        analysis.reusedPasswordCount > 0 ? `${analysis.affectedAccountsCount} accounts sharing identical passwords` : ""
      }.`;
    }

    const itemsSummary = `You currently have **${analysis.totalEntries} saved ${analysis.totalEntries === 1 ? "account" : "accounts"}** in your vault (${analysis.usablePasswordEntries} with active passwords).`;

    return {
      text: `${itemsSummary} ${scoreAssessment}\n\nAll cryptographic checks and scoring were executed locally on your device without sending any data to external servers.`,
      followUps: [
        analysis.weakCount > 0 || analysis.reusedPasswordCount > 0
          ? "Which passwords should I improve first?"
          : "What should I do next?",
        "What does my vault health mean?",
      ],
      topic: "vault_security",
    };
  }

  // 4. Question: "Which passwords should I improve first?" / "What should I fix first?" / "What to fix"
  if (
    q.includes("improve first") ||
    q.includes("fix first") ||
    q.includes("what should i fix") ||
    q.includes("which passwords should i") ||
    q.includes("highest priority") ||
    q.includes("urgent")
  ) {
    if (analysis.topPriority && analysis.topPriority.priority !== "POSITIVE" && analysis.topPriority.priority !== "LOW") {
      const top = analysis.topPriority;
      return {
        text: `**Priority Action (${top.priority}): ${top.title}**\n\n${top.desc}\n\n**Recommended Step:** ${top.actionText}`,
        followUps: [
          analysis.reusedPasswordCount > 0 ? "Do I have reused passwords?" : "Are there any weak passwords?",
          "How can I improve my security score?",
        ],
        topic: "priority_fix",
      };
    }

    return {
      text: `Your vault is in great shape! You have **0 weak passwords** and **0 reused passwords**. All ${analysis.totalEntries} accounts satisfy high-security standards.\n\nTo further harden your protection, ensure multi-factor authentication (2FA) is enabled on your primary email and banking services.`,
      followUps: ["How secure is my vault?", "What does my vault health mean?"],
      topic: "priority_fix",
    };
  }

  // 5. Question: "Do I have reused passwords?" / "duplicates" / "shared passwords"
  if (
    q.includes("reused") ||
    q.includes("duplicate") ||
    q.includes("shared password") ||
    q.includes("same password")
  ) {
    if (analysis.reusedPasswordCount > 0) {
      const groupSummaries = analysis.reusedGroups
        .slice(0, 3)
        .map((g, i) => `Group ${i + 1}: ${formatServiceList(g.serviceNames)} (${g.count} accounts${g.isWeak ? " · Weak Password" : ""})`)
        .join("\n- ");

      return {
        text: `Yes, you have **${analysis.reusedPasswordCount} reused password ${analysis.reusedPasswordCount === 1 ? "group" : "groups"}** affecting **${analysis.affectedAccountsCount} accounts**:\n\n- ${groupSummaries}\n\n**Why this matters:** Credential reuse makes you vulnerable to credential stuffing attacks: if an attacker compromises one service, they will automatically attempt the same password on your other accounts. Generating a unique password for each account prevents this lateral movement.`,
        followUps: ["Which passwords should I improve first?", "How can I improve my security score?"],
        topic: "reused_passwords",
      };
    }

    return {
      text: `**No reused passwords detected.** All ${analysis.usablePasswordEntries} accounts with stored credentials have completely distinct, unique passwords. This is a critical security best practice that prevents lateral account takeover.`,
      followUps: ["Are there any weak passwords?", "How secure is my vault?"],
      topic: "reused_passwords",
    };
  }

  // 6. Question: "Are there any weak passwords?" / "weak passwords" / "bad passwords"
  if (
    q.includes("weak password") ||
    q.includes("bad password") ||
    q.includes("simple password") ||
    q.includes("poor password")
  ) {
    if (analysis.weakCount > 0) {
      const services = formatServiceList(analysis.weakServices);
      return {
        text: `You have **${analysis.weakCount} weak password${analysis.weakCount === 1 ? "" : "s"}** in your vault, affecting: **${services}**.\n\n**Why this matters:** These passwords score below 48/100 on our deterministic strength analyzer. They may be under 12 characters, repeat characters, or omit uppercase letters, numbers, or symbols, making them susceptible to automated dictionary and brute-force cracking.\n\n**Recommended Step:** Open your vault, edit each entry, and click 'Generate password' to replace them with a 20+ character random password.`,
        followUps: ["Which passwords should I improve first?", "How can I improve my security score?"],
        topic: "weak_passwords",
      };
    }

    return {
      text: `**No weak passwords found.** All ${analysis.usablePasswordEntries} analyzed passwords in your vault meet or exceed our strong complexity requirements (12+ characters with diverse character sets and absence of common patterns).`,
      followUps: ["Do I have reused passwords?", "How secure is my vault?"],
      topic: "weak_passwords",
    };
  }

  // 7. Question: "How can I improve my security score?" / "increase score" / "better score"
  if (
    q.includes("improve my security score") ||
    q.includes("improve my score") ||
    q.includes("increase score") ||
    q.includes("higher score") ||
    q.includes("boost score")
  ) {
    const steps: string[] = [];
    if (analysis.reusedPasswordCount > 0) {
      steps.push(`**Eliminate Reuse (+up to 35 pts):** Replace shared passwords on ${analysis.affectedAccountsCount} accounts with unique generated passwords.`);
    }
    if (analysis.weakCount > 0) {
      steps.push(`**Upgrade Weak Passwords (+up to 30 pts):** Upgrade ${analysis.weakCount} weak passwords to 20+ character high-entropy passwords.`);
    }
    if (analysis.missingPasswordCount > 0) {
      steps.push(`**Add Missing Passwords (+up to 20 pts):** Save stored passwords for your ${analysis.missingPasswordCount} incomplete entries.`);
    }

    if (steps.length === 0) {
      return {
        text: `Your vault is already at top security with a health score of **${analysis.healthScore}/100**!\n\nTo maintain this high standard:\n1. Keep using VaultGuard's inline generator for all new registrations.\n2. Enable two-factor authentication (TOTP or hardware security keys) on sensitive accounts.\n3. Export an encrypted backup periodically to protect against local data loss.`,
        followUps: ["What does my vault health mean?", "What should I do next?"],
        topic: "improve_score",
      };
    }

    return {
      text: `To increase your health score (currently **${analysis.healthScore ?? 0}/100**), prioritize these impactful steps:\n\n1. ${steps.join("\n2. ")}\n\nEach update immediately recalculates your score locally in real time.`,
      followUps: ["Which passwords should I improve first?", "What should I do next?"],
      topic: "improve_score",
    };
  }

  // 8. Question: "What does my vault health mean?" / "explain health"
  if (
    q.includes("health mean") ||
    q.includes("health score mean") ||
    q.includes("explain health") ||
    q.includes("what is health")
  ) {
    return {
      text: `Your **Vault Health Score** (0–100) measures how resilient your saved credentials are against modern credential-stuffing and brute-force attacks:\n\n- **Baseline Strength (0–100):** Scaled average of all passwords based on length, character entropy, and absence of predictable sequences.\n- **Reuse Penalty (-up to 35 pts):** Deducts points based on the ratio of accounts sharing identical passwords across services.\n- **Weak Password Penalty (-up to 30 pts):** Deducts points for credentials under 12 characters or with low entropy.\n- **Missing Password Penalty (-up to 20 pts):** Deducts points for entries saved without credentials.\n\nAll math runs client-side in memory; zero credentials or scores are ever sent to remote servers.`,
      followUps: ["How can I improve my security score?", "How secure is my vault?"],
      topic: "explain_health",
    };
  }

  // 9. Question: "What should I do next?" / "next steps" / "next actions"
  if (
    q.includes("do next") ||
    q.includes("next step") ||
    q.includes("next action") ||
    q.includes("what should i do")
  ) {
    if (analysis.recommendations.length > 0) {
      const topRecs = analysis.recommendations.slice(0, 3);
      const itemsText = topRecs
        .map((r, i) => `${i + 1}. **[${r.priority}] ${r.title}**: ${r.actionText}`)
        .join("\n");

      return {
        text: `Here are your recommended next steps based on your live vault contents:\n\n${itemsText}\n\nAddressing higher-priority issues first will have the largest positive impact on your vault's security posture.`,
        followUps: ["Which passwords should I improve first?", "How secure is my vault?"],
        topic: "next_steps",
      };
    }

    return {
      text: "Your vault is in optimal condition! Continue using unique 20+ character passwords for new accounts and maintain an encrypted backup file.",
      followUps: ["How secure is my vault?", "What does my vault health mean?"],
      topic: "next_steps",
    };
  }

  // 10. Privacy & Zero-Knowledge Questions
  if (
    q.includes("zero knowledge") ||
    q.includes("ai") ||
    q.includes("privacy") ||
    q.includes("cloud") ||
    q.includes("third party") ||
    q.includes("where is my data")
  ) {
    return {
      text: `**VaultGuard Zero-Knowledge Guarantee:**\n\n- **100% Local Execution:** This assistant is a deterministic, rule-based security engine that runs entirely inside your browser.\n- **Zero External AI Services:** No passwords, vault records, usernames, or telemetry are ever transmitted to OpenAI, Google, Anthropic, or any third-party AI API.\n- **In-Memory Analysis:** Recommendations are calculated strictly from your unlocked vault items held in memory and are wiped immediately upon vault lock or logout.`,
      followUps: ["How secure is my vault?", "What should I do next?"],
      topic: "privacy",
    };
  }

  // 11. Fallback for general questions
  return {
    text: `I've analyzed your **${analysis.totalEntries} vault ${analysis.totalEntries === 1 ? "entry" : "entries"}** locally. Your current health score is **${analysis.healthScore ?? 0}/100** with **${analysis.weakCount} weak** and **${analysis.reusedPasswordCount} reused** password issues.\n\nTry asking one of the recommended questions below to inspect your vault's security in detail.`,
    followUps: [
      "How secure is my vault?",
      analysis.weakCount > 0 ? "Which passwords should I improve first?" : "Do I have reused passwords?",
      "How can I improve my security score?",
    ],
    topic: "general_help",
  };
}
