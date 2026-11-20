/**
 * VaultGuard – Secure Clipboard Auto-Clear Utility (Phase 10.1)
 *
 * Provides safe, automatic clearing of sensitive secrets copied to the system clipboard.
 * Invariants:
 * - Default 30-second timeout.
 * - Single active timer across repeated copies (cancels previous timers).
 * - Safe conditional clearing: only clears if clipboard still contains the exact secret copied.
 * - Never overwrites unrelated content copied by the user or other applications.
 * - If read permission is denied, does not blindly clear the clipboard.
 * - Handles SSR / headless environments where navigator.clipboard is unavailable.
 * - Zero logging of sensitive plaintext values.
 * - Provides immediate clearing hooks for vault-lock and logout/session-expiration lifecycles.
 */

export interface ClipboardCopyResult {
  success: boolean;
  autoClearScheduled: boolean;
  timeoutSeconds: number;
  message: string;
}

// In-memory module state for active clipboard ownership tracking
let activeClearTimer: ReturnType<typeof setTimeout> | null = null;
let lastCopiedSecret: string | null = null;

export const DEFAULT_CLIPBOARD_AUTO_CLEAR_SECONDS = 30;

/**
 * Copies sensitive text to the clipboard with an automatic clear timeout.
 *
 * @param text The sensitive text to copy (e.g. password)
 * @param timeoutSeconds Duration before clipboard is automatically cleared (default 30s)
 */
export async function copyToClipboardWithAutoClear(
  text: string,
  timeoutSeconds: number = DEFAULT_CLIPBOARD_AUTO_CLEAR_SECONDS
): Promise<ClipboardCopyResult> {
  // Cancel any existing active timer from a previous copy
  cancelClipboardAutoClear();

  if (
    typeof navigator === "undefined" ||
    !navigator.clipboard ||
    typeof navigator.clipboard.writeText !== "function"
  ) {
    return {
      success: false,
      autoClearScheduled: false,
      timeoutSeconds,
      message: "Clipboard access is unavailable in this environment. Select the text to copy manually."
    };
  }

  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return {
      success: false,
      autoClearScheduled: false,
      timeoutSeconds,
      message: "Clipboard write permission was denied or unavailable."
    };
  }

  // Record active secret to ensure we only clear our own content
  lastCopiedSecret = text;

  // Schedule auto-clear if timeoutSeconds > 0
  if (timeoutSeconds > 0) {
    activeClearTimer = setTimeout(async () => {
      await performConditionalClear(text);
    }, timeoutSeconds * 1000);

    return {
      success: true,
      autoClearScheduled: true,
      timeoutSeconds,
      message: `Password copied. Clipboard will be cleared automatically after ${timeoutSeconds} seconds.`
    };
  }

  return {
    success: true,
    autoClearScheduled: false,
    timeoutSeconds: 0,
    message: "Password copied to clipboard."
  };
}

/**
 * Conditionally clears the clipboard ONLY if it still holds the expected secret.
 */
async function performConditionalClear(expectedSecret: string): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.clipboard) {
    lastCopiedSecret = null;
    return false;
  }

  try {
    // If readText is supported, check if clipboard still holds our secret
    if (typeof navigator.clipboard.readText === "function") {
      let currentText: string;
      try {
        currentText = await navigator.clipboard.readText();
      } catch {
        // Read permission denied or unavailable — do not blindly clear unrelated content
        lastCopiedSecret = null;
        return false;
      }

      if (currentText === expectedSecret) {
        await navigator.clipboard.writeText("");
        lastCopiedSecret = null;
        return true;
      } else {
        // User or another application has copied different content — do NOT overwrite
        lastCopiedSecret = null;
        return false;
      }
    } else {
      // readText is not available; do not blindly overwrite
      lastCopiedSecret = null;
      return false;
    }
  } catch {
    lastCopiedSecret = null;
    return false;
  }
}

/**
 * Attempts to clear the VaultGuard-owned clipboard secret immediately
 * (e.g. on vault lock, logout, or session expiry).
 */
export async function clearVaultClipboardImmediately(): Promise<boolean> {
  const secretToClear = lastCopiedSecret;
  cancelClipboardAutoClear();

  if (!secretToClear) {
    return false;
  }

  return await performConditionalClear(secretToClear);
}

/**
 * Cancels any pending auto-clear timer.
 */
export function cancelClipboardAutoClear(): void {
  if (activeClearTimer) {
    clearTimeout(activeClearTimer);
    activeClearTimer = null;
  }
}

/**
 * Returns whether an auto-clear timer is currently active.
 */
export function isClipboardAutoClearActive(): boolean {
  return activeClearTimer !== null;
}

/**
 * For testing: returns the internal state (without exposing secret).
 */
export function getClipboardStateForTesting(): { hasActiveTimer: boolean; hasTrackedSecret: boolean } {
  return {
    hasActiveTimer: activeClearTimer !== null,
    hasTrackedSecret: lastCopiedSecret !== null
  };
}

/**
 * For testing: resets internal state.
 */
export function resetClipboardStateForTesting(): void {
  cancelClipboardAutoClear();
  lastCopiedSecret = null;
}
